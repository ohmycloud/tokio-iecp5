use std::{collections::VecDeque, fmt::Debug, net::SocketAddr, sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use futures::{SinkExt, StreamExt};
use tokio::{
    net::TcpStream,
    select,
    sync::{mpsc, Mutex},
};
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::{
    apci::{
        new_iframe, new_sframe, new_uframe, update_ack_no_out, ApciKind, SApci, UApci,
        U_STARTDT_ACTIVE, U_STARTDT_CONFIRM, U_STOPDT_ACTIVE, U_STOPDT_CONFIRM, U_TESTFR_ACTIVE,
        U_TESTFR_CONFIRM,
    },
    asdu::{Asdu, CauseOfTransmission, CommonAddr},
    csys::{interrogation_cmd, ObjectQOI},
    Codec, Error,
};

// TODO:
pub trait ClientHandler: Debug + Send + Sync {
    fn call(&self, asdu: Asdu) -> Option<Vec<Asdu>>;
}

#[derive(Debug)]
pub struct Client {
    option: ClientOption,
    handler: Arc<Box<dyn ClientHandler>>,
    is_active: Arc<Mutex<bool>>,
    sender: Option<mpsc::UnboundedSender<Request>>,
}

#[derive(Debug)]
pub struct ClientOption {
    socket_addr: SocketAddr,
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

impl Client {
    pub fn new(handler: Arc<Box<dyn ClientHandler>>, option: ClientOption) -> Client {
        Client {
            option,
            handler,
            is_active: Arc::new(Mutex::new(false)),
            sender: None,
        }
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        if self.is_connected().await {
            return Ok(());
        }

        let is_active = self.is_active.clone();
        let handler = self.handler.clone();

        let (tx, mut rx) = mpsc::unbounded_channel();
        self.sender = Some(tx.clone());

        let transport = TcpStream::connect(self.option.socket_addr).await?;
        let (r, w) = transport.into_split();
        let mut sink = FramedWrite::new(w, Codec);
        let mut stream = FramedRead::new(r, Codec);

        tokio::spawn(async move {
            struct CleanUp {
                is_con: Arc<Mutex<bool>>,
                is_act: Arc<Mutex<bool>>,
            }

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
                                    if !*is_active.lock().await {
                                        log::warn!("[TX] Server is not active, drop I-frame {asdu:?}");
                                        continue
                                    }
                                    let apdu = new_iframe(asdu, send_sn, rcv_sn);
                                    if let ApciKind::I(iapci) = ApciKind::from(apdu.apci) {
                                        log::debug!("[TX] I-frame {:?} {:?}", iapci, apdu.asdu);
                                        sink.send(apdu).await?;
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
                                    sink.send(apdu).await?;
                                }
                                Request::S(sapci) => {
                                    let apdu = new_sframe(sapci.rcv_sn);
                                    log::debug!("[TX] S-frame {:?}", sapci);
                                    sink.send(apdu).await?;
                                }
                            }
                        } else {
                            log::warn!("[TX] sink closed");
                            break 'outer
                        }
                    }

                    apdu = stream.next() => match apdu {
                        Some(apdu) => {
                            let apdu = apdu?;
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
                                        if let Some(asdus) = handler.call(asdu) {
                                            for asdu in asdus {
                                                tx.send(Request::I(asdu))?;
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
                                            tx.send(Request::U(UApci { function: U_TESTFR_CONFIRM }))?;
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
                        None =>  {
                            log::info!("[RX] Stream closed");
                            break 'outer
                        }
                    }
                }
            }
            *is_active.lock().await = false;
            Result::<(), Error>::Ok(())
        });
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

    pub async fn is_active(&self) -> bool {
        self.is_connected().await && *self.is_active.lock().await
    }
}

impl Client {
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
        if let Some(sender) = &self.sender {
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

impl Client {
    pub async fn interrogation_cmd(
        &self,
        cot: CauseOfTransmission,
        ca: CommonAddr,
        qoi: ObjectQOI,
    ) -> Result<(), Error> {
        self.send_asdu(interrogation_cmd(cot, ca, qoi)?).await
    }
}

impl Default for ClientOption {
    fn default() -> Self {
        Self {
            socket_addr: "127.0.0.1:2404".parse().unwrap(),
        }
    }
}
