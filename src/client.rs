use std::{
    collections::VecDeque, fmt::Debug, net::SocketAddr, ops::Deref, sync::Arc, time::Duration,
};

use anyhow::Result;
use chrono::{DateTime, Utc};
use futures_util::{SinkExt as _, StreamExt as _};
use std::future::Future;
use tokio::{
    net::TcpStream,
    select,
    sync::{mpsc, Mutex},
    time::sleep,
};
use tokio_util::codec::Framed;

use crate::{
    apci::{
        new_iframe, new_sframe, new_uframe, update_ack_no_out, ApciKind, SApci, UApci,
        U_STARTDT_ACTIVE, U_STARTDT_CONFIRM, U_STOPDT_ACTIVE, U_STOPDT_CONFIRM, U_TESTFR_ACTIVE,
        U_TESTFR_CONFIRM,
    },
    asdu::{Asdu, CauseOfTransmission, CommonAddr, TypeID},
    cproc::{
        bits_string32_cmd, double_cmd, set_point_cmd_float, set_point_cmd_normal,
        set_point_cmd_scaled, single_cmd, BitsString32CommandInfo, DoubleCommandInfo,
        SetpointCommandFloatInfo, SetpointCommandNormalInfo, SetpointCommandScaledInfo,
        SingleCommandInfo,
    },
    csys::{counter_interrogation_cmd, interrogation_cmd, ObjectQCC, ObjectQOI},
    Codec, Error,
};

// TODO:
pub trait ClientHandler {
    type Future: Future<Output = Result<Vec<Asdu>, Error>> + Send;

    fn call(&self, asdu: Asdu) -> Self::Future;
}

impl<D> ClientHandler for D
where
    D: Deref + ?Sized,
    D::Target: ClientHandler,
{
    type Future = <D::Target as ClientHandler>::Future;
    /// A forwarding blanket impl to support smart pointers around [`Service`].
    fn call(&self, asdu: Asdu) -> Self::Future {
        self.deref().call(asdu)
    }
}

pub struct Client<S> {
    op: ClientOption,
    handler: S,
    is_active: Arc<Mutex<bool>>,
    sender: Arc<Mutex<Option<mpsc::UnboundedSender<Request>>>>,
}

#[derive(Debug, Clone, Copy)]
pub struct ClientOption {
    socket_addr: SocketAddr,
    auto_reconnect: bool,
}

#[derive(Debug)]
pub enum Request {
    I(Asdu),
    U(UApci),
    S(SApci),
}

pub struct SeqPending {
    pub seq: u16,
    pub send_time: DateTime<Utc>,
}

impl<S> Client<S>
where
    S: ClientHandler + Clone + Send + Sync + 'static,
{
    pub fn new(handler: S, option: ClientOption) -> Self {
        Client {
            op: option,
            handler,
            is_active: Arc::new(Mutex::new(false)),
            sender: Arc::new(Mutex::new(None)),
        }
    }

    // TODO: 防止上层连续调用，导致重复建立连接
    pub async fn start(&self) -> Result<(), Error> {
        if self.is_connected().await {
            return Ok(());
        }

        tokio::spawn(client_loop(
            self.is_active.clone(),
            self.sender.clone(),
            self.handler.clone(),
            self.op,
        ));

        Ok(())
    }

    pub async fn stop(&mut self) {
        if !self.is_connected().await {
            if let Some(sender) = self.sender.lock().await.take() {
                sender.closed().await;
            }
        }
    }

    pub async fn is_connected(&self) -> bool {
        if let Some(sender) = &*self.sender.lock().await {
            return !sender.is_closed();
        }
        false
    }

    pub async fn is_active(&self) -> bool {
        self.is_connected().await && *self.is_active.lock().await
    }
}

impl<S> Client<S>
where
    S: ClientHandler + Clone + Send + Sync + 'static,
{
    pub async fn send_asdu(&self, asdu: Asdu) -> Result<(), Error> {
        if !self.is_connected().await {
            return Err(Error::ErrUseClosedConnection);
        }

        if !self.is_active().await {
            return Err(Error::ErrNotActive);
        }

        self.send(Request::I(asdu)).await
    }

    pub async fn send_start_dt(&self) -> anyhow::Result<(), Error> {
        if !self.is_connected().await {
            return Err(Error::ErrUseClosedConnection);
        }

        self.send(Request::U(UApci {
            function: U_STARTDT_ACTIVE,
        }))
        .await
    }

    pub async fn send_stop_dt(&self) -> anyhow::Result<(), Error> {
        if !self.is_connected().await {
            return Err(Error::ErrUseClosedConnection);
        }

        self.send(Request::U(UApci {
            function: U_STOPDT_ACTIVE,
        }))
        .await
    }

    async fn send(&self, req: Request) -> Result<(), Error> {
        if let Some(sender) = &*self.sender.lock().await {
            if let Err(e) = sender.send(req) {
                return Err(Error::ErrAnyHow(anyhow::anyhow!(
                    "sender send error: {}",
                    e
                )));
            }
            Ok(())
        } else {
            Err(Error::ErrAnyHow(anyhow::anyhow!("sender not exist")))
        }
    }
}

impl<S> Client<S>
where
    S: ClientHandler + Clone + Send + Sync + 'static,
{
    pub async fn interrogation_cmd(
        &self,
        cot: CauseOfTransmission,
        ca: CommonAddr,
        qoi: ObjectQOI,
    ) -> Result<(), Error> {
        self.send_asdu(interrogation_cmd(cot, ca, qoi)?).await
    }

    pub async fn counter_interrogation_cmd(
        &self,
        cot: CauseOfTransmission,
        ca: CommonAddr,
        qcc: ObjectQCC,
    ) -> Result<(), Error> {
        self.send_asdu(counter_interrogation_cmd(cot, ca, qcc)?)
            .await
    }

    // siq
    pub async fn single_cmd(
        &self,
        type_id: TypeID,
        cot: CauseOfTransmission,
        ca: CommonAddr,
        cmd: SingleCommandInfo,
    ) -> Result<(), Error> {
        self.send_asdu(single_cmd(type_id, cot, ca, cmd)?).await
    }

    // double
    pub async fn double_cmd(
        &self,
        type_id: TypeID,
        cot: CauseOfTransmission,
        ca: CommonAddr,
        cmd: DoubleCommandInfo,
    ) -> Result<(), Error> {
        self.send_asdu(double_cmd(type_id, cot, ca, cmd)?).await
    }

    // nva
    pub async fn set_point_cmd_normal(
        &self,
        type_id: TypeID,
        cot: CauseOfTransmission,
        ca: CommonAddr,
        cmd: SetpointCommandNormalInfo,
    ) -> Result<(), Error> {
        self.send_asdu(set_point_cmd_normal(type_id, cot, ca, cmd)?)
            .await
    }

    // sva
    pub async fn set_point_cmd_scaled(
        &self,
        type_id: TypeID,
        cot: CauseOfTransmission,
        ca: CommonAddr,
        cmd: SetpointCommandScaledInfo,
    ) -> Result<(), Error> {
        self.send_asdu(set_point_cmd_scaled(type_id, cot, ca, cmd)?)
            .await
    }

    // r
    pub async fn set_point_cmd_float(
        &self,
        type_id: TypeID,
        cot: CauseOfTransmission,
        ca: CommonAddr,
        cmd: SetpointCommandFloatInfo,
    ) -> Result<(), Error> {
        self.send_asdu(set_point_cmd_float(type_id, cot, ca, cmd)?)
            .await
    }

    // bcr
    pub async fn bits_string32_cmd(
        &self,
        type_id: TypeID,
        cot: CauseOfTransmission,
        ca: CommonAddr,
        cmd: BitsString32CommandInfo,
    ) -> Result<(), Error> {
        self.send_asdu(bits_string32_cmd(type_id, cot, ca, cmd)?)
            .await
    }
}

async fn client_loop<S>(
    is_active: Arc<Mutex<bool>>,
    sender: Arc<Mutex<Option<mpsc::UnboundedSender<Request>>>>,
    handler: S,
    op: ClientOption,
) -> Result<(), Error>
where
    S: ClientHandler + Clone + Send + Sync + 'static,
{
    loop {
        {
            let mut send_sn = 0;
            let mut ack_sendsn = 0;
            let mut rcv_sn = 0;
            let mut ack_rcvsn = 0;

            let mut idle_timeout3_sine = Utc::now();
            let mut test4alive_send_since = DateTime::<Utc>::MAX_UTC;
            let mut un_ack_rcv_since = DateTime::<Utc>::MAX_UTC;

            let mut start_dt_active_send_since = DateTime::<Utc>::MAX_UTC;
            let mut stop_dt_active_send_since = DateTime::<Utc>::MAX_UTC;

            let mut pending: VecDeque<SeqPending> = VecDeque::new();

            let transport = TcpStream::connect(op.socket_addr).await;
            if transport.is_err() {
                if !op.auto_reconnect {
                    return Err(Error::ErrAnyHow(anyhow::anyhow!("connect error")));
                }
                sleep(Duration::from_secs(60)).await;
                continue;
            }
            let mut framed = Framed::new(transport.unwrap(), Codec);
            let (tx, mut rx) = mpsc::unbounded_channel();
            *sender.lock().await = Some(tx.clone());
            let mut check_timer = tokio::time::interval(Duration::from_millis(100));

            'outer: loop {
                select! {
                    _ = check_timer.tick() => {
                        if Utc::now() - Duration::from_secs(15) >= test4alive_send_since ||
                           Utc::now() - Duration::from_secs(15) >= start_dt_active_send_since ||
                           Utc::now() - Duration::from_secs(15) >= stop_dt_active_send_since  {
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
                                if let Err(e) = tx.send(Request::S(SApci { rcv_sn  })) {
                                    break 'outer
                                };
                                ack_rcvsn = rcv_sn;

                            }


                        if idle_timeout3_sine + Duration::from_secs(20) <= Utc::now() {
                            log::debug!("[CHECK TIMER] test for active");
                            if let Err(e) = tx.send(Request::U(UApci{ function: U_TESTFR_ACTIVE})) {
                                break 'outer
                            };
                            idle_timeout3_sine = Utc::now();
                            test4alive_send_since = idle_timeout3_sine;
                        }
                    }

                    send_data = rx.recv() => {
                        if let Some(data) = send_data {
                            match data {
                                Request::I(asdu) => {
                                    if !*is_active.lock().await {
                                        log::warn!("[TX] Server is not active, drop I-frame {asdu:?}");
                                        continue
                                    }
                                    let apdu = new_iframe(asdu, send_sn, rcv_sn);
                                    if let ApciKind::I(iapci) = ApciKind::from(apdu.apci) {
                                        log::debug!("[TX] I-frame {:?} {:?}", iapci, apdu.asdu);
                                        if let Err(e) = framed.send(apdu).await {
                                            break 'outer
                                        };
                                        pending.push_back(SeqPending {
                                            seq: iapci.send_sn,
                                            send_time: Utc::now()
                                        });
                                        ack_rcvsn = rcv_sn;
                                        send_sn  = (send_sn + 1) % 32767;
                                    }
                                },
                                Request::U(uapci) => {
                                    match uapci.function {
                                        U_STARTDT_ACTIVE => start_dt_active_send_since = Utc::now(),
                                        U_STOPDT_ACTIVE => stop_dt_active_send_since = Utc::now(),
                                        _ => ()

                                    }
                                    let apdu = new_uframe(uapci.function);
                                    log::debug!("[TX] U-frame {:?}", uapci);
                                    if let Err(e) = framed.send(apdu).await {
                                        break 'outer
                                    }
                                }
                                Request::S(sapci) => {
                                    let apdu = new_sframe(sapci.rcv_sn);
                                    log::debug!("[TX] S-frame {:?}", sapci);
                                    if let Err(e) = framed.send(apdu).await {
                                        break 'outer
                                    }
                                }
                            }
                        } else {
                            log::warn!("[TX] sink closed");
                            break 'outer
                        }
                    }

                    apdu = framed.next() => match apdu {
                        Some(Ok(apdu)) => {
                            idle_timeout3_sine = Utc::now(); // 每收到一个i帧,S帧,U帧, 重置空闲定时器 t3

                            let kind = apdu.apci.into();
                            match kind {
                                ApciKind::I(iapci) => {
                                    log::debug!("[RX] I-frame: {iapci:#?} {:#?}", apdu.asdu);

                                    if !update_ack_no_out(iapci.rcv_sn, &mut ack_sendsn, &mut send_sn, &mut pending) ||
                                        iapci.send_sn != rcv_sn {
                                        log::error!("fatal incoming acknowledge either earlier than previous or later than sendTime {:?} send_sn:{}",iapci, send_sn);
                                        break 'outer
                                    }

                                    if ack_rcvsn == rcv_sn {
                                        un_ack_rcv_since = Utc::now();
                                    }


                                    if let Some(asdu) = apdu.asdu {
                                        // for asdu in handler.call(asdu)? {
                                        //     tx.send(Request::I(asdu))?;
                                        // }
                                        match handler.call(asdu).await {
                                            Ok(asdus) => {
                                                for asdu in asdus {
                                                    if let Err(e) = tx.send(Request::I(asdu)) {
                                                        break 'outer
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                break 'outer
                                            }

                                        }
                                    }

                                    rcv_sn = (iapci.send_sn + 1) % 32767;
                                }
                                ApciKind::U(uapci) => {
                                    log::debug!("[RX] U-frame: {uapci:#?}");
                                    match uapci.function {
                                        U_STARTDT_CONFIRM => {
                                            start_dt_active_send_since = DateTime::<Utc>::MAX_UTC;
                                            *is_active.lock().await = true;
                                        }
                                        U_STOPDT_CONFIRM => {
                                            stop_dt_active_send_since = DateTime::<Utc>::MAX_UTC;
                                            *is_active.lock().await = false;
                                        }
                                        U_TESTFR_CONFIRM => {
                                            test4alive_send_since = DateTime::<Utc>::MAX_UTC;
                                        }
                                        U_TESTFR_ACTIVE => {
                                            if let Err(e) = tx.send(Request::U(UApci { function: U_TESTFR_CONFIRM })) {
                                                break 'outer
                                            }
                                        }
                                        _ => {
                                            log::warn!("Unsupported U-frame: {uapci:#?}");
                                        }

                                    }
                                }
                                ApciKind::S(sapci) => {
                                    log::debug!("[RX] S-frame: {sapci:#?}");
                                    if !update_ack_no_out(sapci.rcv_sn, &mut ack_sendsn, &mut send_sn, &mut pending) {
                                        log::error!("fatal incoming acknowledge either earlier than previous or later than sendTime {:?} rcv_sn:{}", sapci,rcv_sn);
                                        break 'outer
                                    }
                                    ack_sendsn = sapci.rcv_sn;
                                }
                            }

                        },
                        _ =>  {
                            log::info!("[RX] Stream closed");
                            break 'outer
                        }
                    }
                }
            }
            *is_active.lock().await = false;
        }
    }
}

impl ClientOption {
    pub fn new(socket_addr: SocketAddr, auto_reconnect: bool) -> Self {
        ClientOption {
            socket_addr,
            auto_reconnect,
        }
    }
}

impl Default for ClientOption {
    fn default() -> Self {
        Self {
            socket_addr: "127.0.0.1:2404".parse().unwrap(),
            auto_reconnect: true,
        }
    }
}
