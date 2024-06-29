use std::{fmt::Debug, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use chrono::{DateTime, Utc};
use futures::{lock::Mutex, SinkExt, StreamExt};
use tokio::{net::TcpStream, select, sync::mpsc};
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::{
    asdu::{CauseOfTransmission, CommonAddr},
    codec::Codec,
    csys::{interrogation_cmd, ObjectQOI},
    error::Error,
    frame::{
        apci::{
            new_iframe, new_sframe, new_uframe, ApciKind, SApci, UApci, U_STARTDT_ACTIVE,
            U_STARTDT_CONFIRM, U_STOPDT_ACTIVE, U_STOPDT_CONFIRM, U_TESTFR_ACTIVE,
            U_TESTFR_CONFIRM,
        },
        asdu::Asdu,
    },
};

#[derive(Debug)]
enum SendDataKind {
    I(Asdu),
    U(UApci),
    S(SApci),
}

// TODO:
pub trait ClientHandler: Debug + Send + Sync {
    fn call(&self, asdu: Asdu) -> Option<Vec<Asdu>>;
}

#[derive(Debug)]
pub struct Client {
    option: ClientOption,
    handler: Arc<Box<dyn ClientHandler>>,

    send_sn: Arc<Mutex<u16>>,
    ack_sendsn: Arc<Mutex<u16>>,
    rcv_sn: Arc<Mutex<u16>>,
    ack_rcvsn: Arc<Mutex<u16>>,

    is_connected: Arc<Mutex<bool>>,
    is_active: Arc<Mutex<bool>>,

    start_dt_active_send_since: Arc<Mutex<DateTime<Utc>>>,
    stop_dt_active_send_since: Arc<Mutex<DateTime<Utc>>>,

    sender: Option<mpsc::UnboundedSender<SendDataKind>>,
}

#[derive(Debug)]
pub struct ClientOption {
    socket_addr: SocketAddr,
}

impl Default for ClientOption {
    fn default() -> Self {
        Self {
            socket_addr: "127.0.0.1:2404".parse().unwrap(),
        }
    }
}

impl Client {
    pub fn new(handler: Arc<Box<dyn ClientHandler>>, option: ClientOption) -> Client {
        Client {
            option,
            handler,
            send_sn: Arc::new(Mutex::new(0)),
            ack_sendsn: Arc::new(Mutex::new(0)),
            rcv_sn: Arc::new(Mutex::new(0)),
            ack_rcvsn: Arc::new(Mutex::new(0)),
            is_connected: Arc::new(Mutex::new(false)),
            is_active: Arc::new(Mutex::new(false)),

            start_dt_active_send_since: Arc::new(Mutex::new(DateTime::<Utc>::MAX_UTC)),
            stop_dt_active_send_since: Arc::new(Mutex::new(DateTime::<Utc>::MAX_UTC)),

            sender: None,
        }
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        if *self.is_connected.lock().await {
            return Ok(());
        }

        let transport = TcpStream::connect(self.option.socket_addr).await?;
        *self.is_connected.lock().await = true;

        let (r, w) = transport.into_split();
        let mut sink = FramedWrite::new(w, Codec);
        let mut stream = FramedRead::new(r, Codec);

        let is_active = self.is_active.clone();
        let is_connected = self.is_connected.clone();
        let handler = self.handler.clone();

        let send_sn = Arc::new(Mutex::new(0));
        let ack_sendsn = Arc::new(Mutex::new(0));
        let rcv_sn = Arc::new(Mutex::new(0));
        let ack_rcvsn = Arc::new(Mutex::new(0));
        let start_dt_active_send_since = self.start_dt_active_send_since.clone();
        let stop_dt_active_send_since = self.stop_dt_active_send_since.clone();

        // let send_sn = self.send_sn.clone();
        // let ack_sendsn = self.ack_sendsn.clone();
        // let rcv_sn = self.rcv_sn.clone();
        // let ack_rcvsn = self.ack_rcvsn.clone();
        // let is_active = self.is_active.clone();
        // let is_connected = self.is_connected.clone();
        // let handler = self.handler.clone();
        //
        // let start_dt_active_send_since = self.start_dt_active_send_since.clone();
        // let stop_dt_active_send_since = self.stop_dt_active_send_since.clone();

        let (tx, mut rx) = mpsc::unbounded_channel();
        self.sender = Some(tx.clone());

        tokio::spawn(async move {
            let ack_sendsn = Arc::new(Mutex::new(0));
            let rcv_sn = Arc::new(Mutex::new(0));
            let ack_rcvsn = Arc::new(Mutex::new(0));

            let mut idle_timeout3_sine = Utc::now();
            let mut test4alive_send_since = DateTime::<Utc>::MAX_UTC;
            let mut un_ack_rcv_since = DateTime::<Utc>::MAX_UTC;

            let mut check_timer = tokio::time::interval(Duration::from_millis(100));
            loop {
                select! {

                    _ = check_timer.tick() => {
                        // if test4alive_send_since.add(Duration::from_secs(15)) <= Utc::now() ||
                        if Utc::now() - Duration::from_secs(15) >= test4alive_send_since ||
                           Utc::now() - Duration::from_secs(15) >= *start_dt_active_send_since.lock().await ||
                           Utc::now() - Duration::from_secs(15) >= *stop_dt_active_send_since.lock().await  {
                           log::error!("CHECK_TIMER test frame alive confirm timeout t");
                           break
                        }

                        // TODO: check send ack
                        // let send_sn = *send_sn.lock().await;
                        // let ack_sendsn = *ack_sendsn.lock().await;
                        // if  ack_sendsn != send_sn {
                        //
                        // }

                        let ack_rcvseqno = *ack_rcvsn.lock().await;
                        let rcv_sn = *rcv_sn.lock().await;
                        if ack_rcvseqno != rcv_sn && (un_ack_rcv_since + Duration::from_secs(10) <= Utc::now() ||
                            idle_timeout3_sine + Duration::from_millis(100) <= Utc::now()) {
                                if tx.send(SendDataKind::S(SApci { rcv_sn  })).is_err() {
                                    log::error!("CHECK_TIMER S-Frame failed {rcv_sn}");
                                    break
                                }
                                *ack_rcvsn.lock().await = rcv_sn;

                            }


                        if idle_timeout3_sine + Duration::from_secs(20) <= Utc::now() {
                            log::info!("CHECK_TIMER test for active");
                            if tx.send(SendDataKind::U(UApci{
                                function: U_TESTFR_ACTIVE})).is_err() {
                                log::error!("CHECK_TIMER test for active failed");
                                break
                            }
                            idle_timeout3_sine = Utc::now();
                            test4alive_send_since = idle_timeout3_sine;
                        }
                    }

                    send_data = rx.recv() => {
                        if let Some(data) = send_data {
                            match data {
                                SendDataKind::I(asdu) => {
                                    if *is_active.clone().lock().await {
                                        let send_seqno = *send_sn.lock().await;
                                        let rcv_seqno = *rcv_sn.lock().await;
                                        let apdu = new_iframe(asdu, send_seqno, rcv_seqno);
                                        log::info!("TX I-frame {apdu:?} {send_seqno}");
                                        if sink.send(apdu).await.is_err() {
                                            log::error!("TX I-frame failed");
                                            break
                                        }
                                        *ack_rcvsn.lock().await = rcv_seqno;
                                        *send_sn.lock().await  = (send_seqno + 1) % 32767;
                                    } else {
                                        log::info!("TX Client is not active, drop I-frame {asdu:?}");
                                    }
                                },
                                SendDataKind::U(uapci) => {
                                    let apdu = new_uframe(uapci.function);
                                    log::info!("TX U-frame {apdu:?}");
                                    if sink.send(apdu).await.is_err() {
                                        log::error!("Send U-frame failed");
                                        break
                                    }
                                }
                                SendDataKind::S(sapci) => {
                                    let apdu = new_sframe(sapci.rcv_sn);
                                        log::info!("TX S-frame {apdu:?}");
                                        if sink.send(apdu).await.is_err() {
                                            log::error!("TX S-frame failed");
                                            break
                                        }
                                }
                            }
                        } else {
                            log::warn!("TX sink closed");
                            break
                        }
                    }

                    apdu = stream.next() => match apdu {
                        Some(apdu) => {
                            if apdu.is_err() {
                                break
                            }

                            let apdu = apdu.unwrap();
                            let apci = apdu.apci;
                            let kind = apci.into();
                            idle_timeout3_sine = Utc::now(); // 每收到一个i帧,S帧,U帧, 重置空闲定时器, t3
                            match kind {
                                ApciKind::I(head) => {
                                    log::info!("RX I-frame: {head:#?} {:#?}", apdu.asdu);

                                    // TODO:
                                    if head.send_sn != *rcv_sn.lock().await {
                                        log::error!("fatal incoming acknowledge either earlier than previous or later than sendTime send_sn:{} rcv_sn:{}",head.send_sn,*rcv_sn.lock().await);
                                        break
                                    }

                                    if *ack_rcvsn.lock().await == *rcv_sn.lock().await {
                                        un_ack_rcv_since = Utc::now();
                                    }


                                    if let Some(asdus) = handler.call(apdu.asdu.unwrap()) {
                                        for asdu in asdus {
                                            if tx.send(SendDataKind::I(asdu)).is_err() {
                                                log::error!("Send I-frame failed");
                                                break
                                            }
                                        }
                                    }

                                    *rcv_sn.lock().await = (head.send_sn + 1) % 32767;
                                }
                                ApciKind::U(head) => {
                                    log::info!("RX U-frame: {head:#?}");
                                    match head.function {
                                        U_STARTDT_CONFIRM => {
                                            *start_dt_active_send_since.lock().await = DateTime::<Utc>::MAX_UTC;
                                            *is_active.lock().await = true;
                                        }
                                        U_STOPDT_CONFIRM => {
                                            *stop_dt_active_send_since.lock().await = DateTime::<Utc>::MAX_UTC;
                                            *is_active.lock().await = false;
                                        }
                                        U_TESTFR_CONFIRM => {
                                            test4alive_send_since = DateTime::<Utc>::MAX_UTC;
                                        }
                                        U_TESTFR_ACTIVE => {
                                            if tx.send(SendDataKind::U(UApci { function: U_TESTFR_CONFIRM })).is_err() {
                                                    log::error!("Send U-frame failed");
                                                    break
                                                }
                                        }
                                        _ => {
                                            log::error!("Unsupported U-frame: {head:#?}");
                                            break
                                        }

                                    }
                                }
                                ApciKind::S(head) => {
                                    log::info!("RX S-frame: {head:#?}");
                                }
                            }

                        },
                        None =>  {
                            log::warn!("RX Stream closed");
                            break
                        }
                    }
                }
            }
            *is_connected.lock().await = false;
            *is_active.lock().await = false;
        });
        Ok(())
    }

    pub async fn stop(&mut self) {
        if !*self.is_connected.lock().await {
            if let Some(sender) = self.sender.take() {
                sender.closed().await;
            }
        }
    }

    pub async fn is_connected(&self) -> bool {
        *self.is_connected.lock().await
    }

    pub async fn is_active(&self) -> bool {
        *self.is_active.lock().await
    }
}

impl Client {
    async fn send(&self, asdu: Asdu) -> anyhow::Result<(), Error> {
        if !self.is_connected().await {
            return Err(Error::ErrUseClosedConnection);
        }

        if !self.is_active().await {
            return Err(Error::ErrNotActive);
        }

        if let Some(sender) = &self.sender {
            if let Err(e) = sender.send(SendDataKind::I(asdu)) {
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

    pub async fn send_start_dt(&self) -> anyhow::Result<(), Error> {
        if !self.is_connected().await {
            return Err(Error::ErrUseClosedConnection);
        }

        if let Some(sender) = &self.sender {
            if let Err(e) = sender.send(SendDataKind::U(UApci {
                function: U_STARTDT_ACTIVE,
            })) {
                return Err(Error::ErrAnyHow(anyhow::anyhow!(
                    "sender send error: {}",
                    e
                )));
            }
            *self.start_dt_active_send_since.lock().await = Utc::now();
            Ok(())
        } else {
            Err(Error::ErrAnyHow(anyhow::anyhow!("sender not exist")))
        }
    }

    pub async fn send_stop_dt(&self) -> anyhow::Result<(), Error> {
        if !self.is_connected().await {
            return Err(Error::ErrUseClosedConnection);
        }

        if let Some(sender) = &self.sender {
            if let Err(e) = sender.send(SendDataKind::U(UApci {
                function: U_STOPDT_ACTIVE,
            })) {
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

    pub async fn interrogation_cmd(
        &self,
        cot: CauseOfTransmission,
        ca: CommonAddr,
        qoi: ObjectQOI,
    ) -> Result<(), Error> {
        self.send(interrogation_cmd(cot, ca, qoi)?).await
    }
}
