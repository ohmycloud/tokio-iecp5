use std::{collections::VecDeque, io, net::SocketAddr, ops::Deref, time::Duration};

use chrono::{DateTime, Utc};
use futures::{SinkExt, StreamExt};
use std::future::Future;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    select,
    sync::mpsc,
};
use tokio_util::codec::Framed;

use crate::{
    apci::{
        new_iframe, new_sframe, new_uframe, update_ack_no_out, ApciKind, SApci, UApci,
        U_STARTDT_ACTIVE, U_STARTDT_CONFIRM, U_STOPDT_ACTIVE, U_STOPDT_CONFIRM, U_TESTFR_ACTIVE,
        U_TESTFR_CONFIRM,
    },
    asdu::{Asdu, Cause, TypeID, INFO_OBJ_ADDR_IRRELEVANT, INVALID_COMMON_ADDR},
    csys::{ObjectQCC, ObjectQOI},
    Codec, Error, Request, SeqPending,
};

// TODO: add ServerSession to server
pub struct Server {
    listener: TcpListener,
}

pub trait ServerHandler {
    type Future: Future<Output = Result<Vec<Asdu>, Error>> + Send;

    fn call_interrogation(&self, _: Asdu, qoi: ObjectQOI) -> Self::Future;
    fn call_counter_interrogation(&self, _: Asdu, qcc: ObjectQCC) -> Self::Future;
    fn call(&self, asdu: Asdu) -> Self::Future;
}

impl<D> ServerHandler for D
where
    D: Deref + ?Sized,
    D::Target: ServerHandler,
{
    type Future = <D::Target as ServerHandler>::Future;

    /// A forwarding blanket impl to support smart pointers around [`Service`].
    fn call(&self, asdu: Asdu) -> Self::Future {
        self.deref().call(asdu)
    }
    fn call_interrogation(&self, _asdu: Asdu, qoi: ObjectQOI) -> Self::Future {
        self.deref().call_interrogation(_asdu, qoi)
    }
    fn call_counter_interrogation(&self, _asdu: Asdu, qcc: ObjectQCC) -> Self::Future {
        self.deref().call_counter_interrogation(_asdu, qcc)
    }
}

struct ServerSession {
    sender: Option<mpsc::UnboundedSender<Request>>,
}

impl Server {
    #[must_use]
    pub fn new(listener: TcpListener) -> Self {
        Self { listener }
    }

    pub async fn serve<S, T, F, OnConnected, OnprocessError>(
        &self,
        on_connected: &OnConnected,
        on_process_error: OnprocessError,
    ) -> io::Result<()>
    where
        S: ServerHandler + Send + Sync + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        OnConnected: Fn(TcpStream, SocketAddr) -> F,
        F: Future<Output = io::Result<Option<(S, T)>>>,
        OnprocessError: FnOnce(Error) + Clone + Send + 'static,
    {
        loop {
            let (stream, socket_addr) = self.listener.accept().await?;
            log::debug!("Accepted connection from {socket_addr}");

            let Some((handler, transport)) = on_connected(stream, socket_addr).await? else {
                log::debug!("No ServerHandler for connection from {socket_addr}");
                continue;
            };
            let on_process_error = on_process_error.clone();

            tokio::spawn(async move {
                log::debug!("Processing requests from {socket_addr}");
                let mut session = ServerSession::new();
                if let Err(err) = session.run(transport, handler).await {
                    session.sender = None;
                    on_process_error(err);
                }
            });
        }
    }
}

impl ServerSession {
    pub fn new() -> Self {
        ServerSession { sender: None }
    }

    pub async fn run<S, T>(&mut self, transport: T, handler: S) -> Result<(), Error>
    where
        S: ServerHandler + Send + Sync + 'static,
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.sender = Some(tx.clone());

        let mut framed = Framed::new(transport, Codec);

        let mut is_active = false;

        let mut send_sn = 0;
        let mut ack_sendsn = 0;
        let mut rcv_sn = 0;
        let mut ack_rcvsn = 0;

        let mut idle_timeout3_sine = Utc::now();
        let mut test4alive_send_since = DateTime::<Utc>::MAX_UTC;
        let mut un_ack_rcv_since = DateTime::<Utc>::MAX_UTC;

        // 对于server端，无需对应的U-Frame 无需判断
        // let mut start_dt_active_send_since = DateTime::<Utc>::MAX_UTC;
        // let mut stop_dt_active_send_since = DateTime::<Utc>::MAX_UTC;

        let mut pending: VecDeque<SeqPending> = VecDeque::new();

        let mut check_timer = tokio::time::interval(Duration::from_millis(100));

        'outer: loop {
            select! {

                _ = check_timer.tick() => {
                    if Utc::now() - Duration::from_secs(15) >= test4alive_send_since {
                       // Utc::now() - Duration::from_secs(15) >= start_dt_active_send_since ||
                       // Utc::now() - Duration::from_secs(15) >= stop_dt_active_send_since
                       log::error!("[CHECK TIMER] test frame alive confirm timeout t");
                       break 'outer
                    }

                    if  ack_sendsn != send_sn &&
                        Utc::now() - Duration::from_secs(15) >= pending[0].send_time {
                        log::warn!("[CHECK TIMER] send ack [sq:{ack_sendsn}] timeout");
                        ack_sendsn += 1;
                        pending.pop_front();
                    }

                    if ack_rcvsn != rcv_sn && (un_ack_rcv_since + Duration::from_secs(10) <= Utc::now() ||
                        idle_timeout3_sine + Duration::from_millis(100) <= Utc::now()) {
                            tx.send(Request::S(SApci { rcv_sn  }))?;
                            ack_rcvsn = rcv_sn;
                        }

                    if idle_timeout3_sine + Duration::from_secs(20) <= Utc::now() {
                        log::debug!("[CHECK TIMER] test for active");
                        tx.send(Request::U(UApci{ function: U_TESTFR_ACTIVE}))?;
                        idle_timeout3_sine = Utc::now();
                        test4alive_send_since = idle_timeout3_sine;
                    }
                }

                send_data = rx.recv() => {
                    if let Some(data) = send_data {
                        match data {
                            Request::I(asdu) => {
                                if !is_active {
                                    log::warn!("[TX] Server is not active, drop I-frame {asdu:?}");
                                    continue
                                }
                                let apdu = new_iframe(asdu, send_sn, rcv_sn);
                                if let ApciKind::I(iapci) = ApciKind::from(apdu.apci) {
                                    log::debug!("[TX] I-frame: {apdu}");
                                    log::trace!("[TX] I-frame: {:?} {:?}", iapci, apdu.asdu);
                                    framed.send(apdu).await?;
                                    pending.push_back(SeqPending {
                                        seq: iapci.send_sn,
                                        send_time: Utc::now()
                                    });
                                    ack_rcvsn = rcv_sn;
                                    send_sn  = (send_sn + 1) % 32767;
                                }
                            },
                            Request::U(uapci) => {
                                // match uapci.function {
                                //     U_STARTDT_ACTIVE => start_dt_active_send_since = Utc::now(),
                                //     U_STOPDT_ACTIVE => stop_dt_active_send_since = Utc::now(),
                                //     _ => ()
                                //
                                // }
                                let apdu = new_uframe(uapci.function);
                                log::debug!("[TX] U-frame: {apdu}");
                                log::trace!("[TX] U-frame: {:?}", uapci);
                                framed.send(apdu).await?;
                            }
                            Request::S(sapci) => {
                                let apdu = new_sframe(sapci.rcv_sn);
                                log::debug!("[TX] S-frame: {apdu}");
                                log::trace!("[TX] S-frame: {:?}", sapci);
                                framed.send(apdu).await?;
                            }
                        }
                    } else {
                        log::warn!("[TX] sink closed");
                        break 'outer
                    }
                }

                apdu = framed.next() => match apdu {
                    Some(apdu) => {
                        let apdu = apdu?;
                        idle_timeout3_sine = Utc::now(); // 每收到一个 I 帧,S 帧,U 帧, 重置空闲定时器 t3

                        let kind = apdu.apci.into();
                        match kind {
                            ApciKind::I(iapci) => {
                                log::debug!("[RX] I-frame: {apdu}");
                                log::trace!("[RX] I-frame: {iapci:#?} {:#?}", apdu.asdu);

                                if !update_ack_no_out(iapci.rcv_sn, &mut ack_sendsn, &mut send_sn, &mut pending) ||
                                    iapci.send_sn != rcv_sn {
                                    log::error!("fatal incoming acknowledge either earlier than previous or later than sendTime {:?} send_sn:{}",iapci, send_sn);
                                    break 'outer
                                }

                                if ack_rcvsn == rcv_sn {
                                    un_ack_rcv_since = Utc::now();
                                }


                                if let Some(asdu) = apdu.asdu {
                                    let mut asdu = asdu;
                                    let ca = asdu.identifier.common_addr;
                                    let cause = asdu.identifier.cot.cause().get();
                                    let type_id = asdu.identifier.type_id;
                                    match type_id {
                                        TypeID::C_IC_NA_1 => {
                                            if !(cause == Cause::Activation || cause == Cause::Deactivation) {
                                                tx.send(Request::I(asdu.mirror(Cause::UnknownCOT)))?;
                                                continue;
                                            }
                                            if ca == INVALID_COMMON_ADDR {
                                                tx.send(Request::I(asdu.mirror(Cause::UnknownCA)))?;
                                                continue;
                                            }
                                            let (mut ioa, qoi) = asdu.get_interrogation_cmd()?;
                                            let ioa = ioa.addr().get();
                                            if ioa != INFO_OBJ_ADDR_IRRELEVANT {
                                                tx.send(Request::I(asdu.mirror(Cause::UnknownIOA)))?;
                                                continue;
                                            }
                                            for asdu in handler.call_interrogation(asdu, qoi).await? {
                                                tx.send(Request::I(asdu))?;
                                            }
                                        }
                                        TypeID::C_CI_NA_1 => {
                                            if cause != Cause::Activation {
                                                tx.send(Request::I(asdu.mirror(Cause::UnknownCOT)))?;
                                                continue;
                                            }
                                            if ca == INVALID_COMMON_ADDR {
                                                tx.send(Request::I(asdu.mirror(Cause::UnknownCA)))?;
                                                continue;
                                            }
                                            let (mut ioa, qcc) = asdu.get_counter_interrogation_cmd()?;
                                            let ioa = ioa.addr().get();
                                            if ioa != INFO_OBJ_ADDR_IRRELEVANT {
                                                tx.send(Request::I(asdu.mirror(Cause::UnknownIOA)))?;
                                                continue;
                                            }
                                            for asdu in handler.call_counter_interrogation(asdu, qcc).await? {
                                                tx.send(Request::I(asdu))?;
                                                continue;
                                            }
                                        }
                                        // TypeID::C_RD_NA_1 => {
                                        //     if cause != Cause::Request {
                                        //         tx.send(Request::I(asdu.mirror(Cause::UnknownCOT)))?;
                                        //     }
                                        //     if ca == INVALID_COMMON_ADDR {
                                        //         tx.send(Request::I(asdu.mirror(Cause::UnknownCA)))?;
                                        //     }
                                        //     for asdu in handler.call_counter_interrogation(asdu, asdu.get_read_cmd()?).await? {
                                        //         tx.send(Request::I(asdu))?;
                                        //     }
                                        // }

                                        _ => {
                                            for asdu in handler.call(asdu).await? {
                                                tx.send(Request::I(asdu))?;
                                            }
                                        }
                                    }
                                }

                                rcv_sn = (iapci.send_sn + 1) % 32767;
                            }
                            ApciKind::U(uapci) => {
                                log::debug!("[RX] U-frame: {apdu}");
                                log::trace!("[RX] U-frame: {uapci:#?}");
                                match uapci.function {
                                    U_STARTDT_ACTIVE => {
                                        tx.send(Request::U(UApci { function: U_STARTDT_CONFIRM }))?;
                                        is_active = true;
                                    }
                                    U_STOPDT_ACTIVE => {
                                        tx.send(Request::U(UApci { function: U_STOPDT_CONFIRM }))?;
                                        is_active = false;
                                    }
                                    U_TESTFR_CONFIRM => {
                                        test4alive_send_since = DateTime::<Utc>::MAX_UTC;
                                    }
                                    U_TESTFR_ACTIVE => {
                                        tx.send(Request::U(UApci { function: U_TESTFR_CONFIRM }))?;
                                    }
                                    _ => {
                                        log::warn!("Unsupported U-frame: {uapci:#?}");
                                    }

                                }
                            }
                            ApciKind::S(sapci) => {
                                log::debug!("[RX] S-frame: {apdu}");
                                log::trace!("[RX] S-frame: {sapci:#?}");
                                if !update_ack_no_out(sapci.rcv_sn, &mut ack_sendsn, &mut send_sn, &mut pending) {
                                    log::error!("fatal incoming acknowledge either earlier than previous or later than sendTime {:?} rcv_sn:{}", sapci,rcv_sn);
                                    break 'outer
                                }
                                ack_sendsn = sapci.rcv_sn;
                            }
                        }

                    },
                    None =>  {
                        log::info!("[RX] Stream closed");
                        break 'outer
                    }
                }


            }
        }

        self.sender = None;

        Ok(())
    }

    pub async fn stop(&mut self) {
        if !self.is_connected().await {
            if let Some(sender) = self.sender.take() {
                sender.closed().await;
            }
        }
    }

    pub async fn is_connected(&self) -> bool {
        if let Some(sender) = &self.sender {
            return !sender.is_closed();
        }
        false
    }
}
