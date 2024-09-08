use std::{
    future,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use tokio::{sync::oneshot, time::sleep};
use tokio_iecp5::{
    asdu::{Asdu, Cause, CauseOfTransmission, CommonAddr, TypeID},
    cproc::{
        BitsString32CommandInfo, DoubleCommandInfo, SetpointCommandFloatInfo,
        SetpointCommandNormalInfo, SetpointCommandScaledInfo, SingleCommandInfo,
    },
    csys::{ObjectQCC, ObjectQOI},
    Client, ClientHandler, ClientOption, Error,
};

#[allow(dead_code)]
enum IEC104DateType {
    Siq,
    Diq,
    Nva,
    Sva,
    R,
    Bcr,
}

pub struct IEC104Client {
    remote_addr: CommonAddr,
    // TODO: change to mutex
    client: Arc<Client<Arc<IEC104ClientHandler>>>,
    inner: Arc<IEC104ClientHandler>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    terminated_rx: Option<oneshot::Receiver<()>>,
}

impl IEC104Client {
    pub fn new(socket_addr: SocketAddr, remote_addr: CommonAddr) -> Self {
        let op = ClientOption::new(socket_addr, true);
        let inner = Arc::new(IEC104ClientHandler::new());
        let client = Arc::new(Client::new(inner.clone(), op));

        IEC104Client {
            remote_addr,
            client,
            inner,
            shutdown_tx: None,
            terminated_rx: None,
        }
    }

    pub async fn start(&mut self) -> Result<(), Error> {
        self.client.start().await?;

        if self.shutdown_tx.is_some() {
            return Ok(());
        }

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let (terminated_tx, terminated_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);
        self.terminated_rx = Some(terminated_rx);

        let client = self.client.clone();
        let remote_addr = self.remote_addr;

        tokio::spawn(async move {
            loop {
                if shutdown_rx.try_recv().is_ok() {
                    terminated_tx.send(()).unwrap();
                    break;
                }
                if !client.is_connected().await {
                    // client 会自动连接
                    // client.start().await;
                    continue;
                }
                if !client.is_active().await {
                    if client.send_start_dt().await.is_err() {
                        continue;
                    }
                    log::info!("IEC104 TRIGGER: STARTDT");
                }

                sleep(Duration::from_secs(1)).await;

                if client
                    .counter_interrogation_cmd(
                        CauseOfTransmission::new(false, false, Cause::Activation),
                        remote_addr,
                        ObjectQCC::new(0x05),
                    )
                    .await
                    .is_err()
                {
                    continue;
                }
                log::info!("IEC104 TRIGGER: Interrogation CUM BEGIN");

                sleep(Duration::from_secs(10)).await;

                if client
                    .counter_interrogation_cmd(
                        CauseOfTransmission::new(false, false, Cause::ActivationTerm),
                        remote_addr,
                        ObjectQCC::new(0x05),
                    )
                    .await
                    .is_err()
                {
                    continue;
                }
                log::info!("IEC104 TRIGGER: Interrogation CUM END");

                if client
                    .interrogation_cmd(
                        CauseOfTransmission::new(false, false, Cause::Activation),
                        remote_addr,
                        ObjectQOI::new(20),
                    )
                    .await
                    .is_err()
                {
                    continue;
                }
                log::info!("IEC104 TRIGGER: Interrogation ALL BEGIN");

                sleep(Duration::from_secs(20)).await;

                if client
                    .interrogation_cmd(
                        CauseOfTransmission::new(false, false, Cause::ActivationTerm),
                        remote_addr,
                        ObjectQOI::new(20),
                    )
                    .await
                    .is_err()
                {
                    continue;
                }
                log::info!("IEC104 TRIGGER: Interrogation ALL END");

                if client.send_stop_dt().await.is_err() {
                    continue;
                }
                log::info!("IEC104 TRIGGER: STOPDT");
                sleep(Duration::from_secs(1)).await
            }
        });

        Ok(())
    }

    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            tx.send(()).unwrap();
        }
        if let Some(rx) = self.terminated_rx.take() {
            rx.await.unwrap();
            // TODO:
            // self.client.stop().await
        }
    }

    pub fn read_siq(&self, addr: u16) -> Option<bool> {
        self.inner.siq_space.lock().unwrap()[addr as usize]
    }

    pub async fn write_siq(&self, addr: u16, v: bool) -> Result<(), Error> {
        let cmd = SingleCommandInfo::new(addr, v, true);
        self.client
            .single_cmd(
                TypeID::C_SC_NA_1,
                CauseOfTransmission::new(false, false, Cause::Activation),
                self.remote_addr,
                cmd,
            )
            .await?;

        let cmd = SingleCommandInfo::new(addr, v, false);
        self.client
            .single_cmd(
                TypeID::C_SC_NA_1,
                CauseOfTransmission::new(false, false, Cause::Activation),
                self.remote_addr,
                cmd,
            )
            .await
    }

    pub fn read_diq(&self, addr: u16) -> Option<u8> {
        self.inner.diq_space.lock().unwrap()[addr as usize]
    }

    pub async fn write_diq(&self, addr: u16, v: u8) -> Result<(), Error> {
        let cmd = DoubleCommandInfo::new(addr, v, true);
        self.client
            .double_cmd(
                TypeID::C_DC_NA_1,
                CauseOfTransmission::new(false, false, Cause::Activation),
                self.remote_addr,
                cmd,
            )
            .await?;

        let cmd = DoubleCommandInfo::new(addr, v, false);
        self.client
            .double_cmd(
                TypeID::C_DC_NA_1,
                CauseOfTransmission::new(false, false, Cause::Activation),
                self.remote_addr,
                cmd,
            )
            .await
    }

    pub fn read_nva(&self, addr: u16) -> Option<i16> {
        self.inner.nva_space.lock().unwrap()[addr as usize]
    }

    pub async fn write_nva(&self, addr: u16, v: i16) -> Result<(), Error> {
        let cmd = SetpointCommandNormalInfo::new(addr, v);
        self.client
            .set_point_cmd_normal(
                TypeID::C_SE_NA_1,
                CauseOfTransmission::new(false, false, Cause::Activation),
                self.remote_addr,
                cmd,
            )
            .await
    }

    pub fn read_sva(&self, addr: u16) -> Option<i16> {
        self.inner.sva_space.lock().unwrap()[addr as usize]
    }

    pub async fn write_sva(&self, addr: u16, v: i16) -> Result<(), Error> {
        let cmd = SetpointCommandScaledInfo::new(addr, v);
        self.client
            .set_point_cmd_scaled(
                TypeID::C_SE_NB_1,
                CauseOfTransmission::new(false, false, Cause::Activation),
                self.remote_addr,
                cmd,
            )
            .await
    }

    pub fn read_r(&self, addr: u16) -> Option<f32> {
        self.inner.r_space.lock().unwrap()[addr as usize]
    }

    pub async fn write_r(&self, addr: u16, v: f32) -> Result<(), Error> {
        let cmd = SetpointCommandFloatInfo::new(addr, v);
        self.client
            .set_point_cmd_float(
                TypeID::C_SE_NC_1,
                CauseOfTransmission::new(false, false, Cause::Activation),
                self.remote_addr,
                cmd,
            )
            .await
    }

    pub fn read_bcr(&self, addr: u16) -> Option<i32> {
        self.inner.bcr_space.lock().unwrap()[addr as usize]
    }

    pub async fn write_bcr(&self, addr: u16, v: i32) -> Result<(), Error> {
        let cmd = BitsString32CommandInfo::new(addr, v);
        self.client
            .bits_string32_cmd(
                TypeID::C_BO_NA_1,
                CauseOfTransmission::new(false, false, Cause::Activation),
                self.remote_addr,
                cmd,
            )
            .await
    }
}

#[derive(Debug, Clone)]
struct IEC104ClientHandler {
    siq_space: Arc<Mutex<[Option<bool>; 65536]>>,
    diq_space: Arc<Mutex<[Option<u8>; 65536]>>,
    nva_space: Arc<Mutex<[Option<i16>; 65536]>>,
    sva_space: Arc<Mutex<[Option<i16>; 65536]>>,
    r_space: Arc<Mutex<[Option<f32>; 65536]>>,
    bcr_space: Arc<Mutex<[Option<i32>; 65536]>>,
}

impl IEC104ClientHandler {
    pub fn new() -> Self {
        IEC104ClientHandler {
            siq_space: Arc::new(Mutex::new([None; 65536])),
            diq_space: Arc::new(Mutex::new([None; 65536])),
            nva_space: Arc::new(Mutex::new([None; 65536])),
            sva_space: Arc::new(Mutex::new([None; 65536])),
            r_space: Arc::new(Mutex::new([None; 65536])),
            bcr_space: Arc::new(Mutex::new([None; 65536])),
        }
    }
}

impl ClientHandler for IEC104ClientHandler {
    type Future = future::Ready<Result<Vec<Asdu>, Error>>;

    fn call(&self, asdu: Asdu) -> Self::Future {
        let mut asdu = asdu;
        match asdu.identifier.type_id {
            TypeID::C_IC_NA_1 => future::ready(Ok(vec![])),
            TypeID::M_SP_NA_1 | TypeID::M_SP_TA_1 | TypeID::M_SP_TB_1 => {
                let sgs = asdu.get_single_point().unwrap();
                for mut sg in sgs {
                    self.siq_space.lock().unwrap()[sg.ioa.addr().get() as usize] =
                        Some(sg.siq.spi().get());
                }
                future::ready(Ok(vec![]))
            }
            TypeID::M_DP_NA_1 | TypeID::M_DP_TA_1 | TypeID::M_DP_TB_1 => {
                let dbs = asdu.get_double_point().unwrap();
                for mut db in dbs {
                    self.diq_space.lock().unwrap()[db.ioa.addr().get() as usize] =
                        Some(db.diq.spi().get().value());
                }
                future::ready(Ok(vec![]))
            }

            TypeID::M_ME_NA_1 | TypeID::M_ME_TA_1 | TypeID::M_ME_TD_1 | TypeID::M_ME_ND_1 => {
                let nvas = asdu.get_measured_value_normal().unwrap();
                for mut v in nvas {
                    self.nva_space.lock().unwrap()[v.ioa.addr().get() as usize] = Some(v.nva);
                }
                future::ready(Ok(vec![]))
            }
            TypeID::M_ME_NB_1 | TypeID::M_ME_TB_1 | TypeID::M_ME_TE_1 => {
                let svas = asdu.get_measured_value_scaled().unwrap();
                for mut v in svas {
                    self.sva_space.lock().unwrap()[v.ioa.addr().get() as usize] = Some(v.sva);
                }
                future::ready(Ok(vec![]))
            }
            TypeID::M_ME_NC_1 | TypeID::M_ME_TC_1 | TypeID::M_ME_TF_1 => {
                let rs = asdu.get_measured_value_float().unwrap();
                for mut v in rs {
                    self.r_space.lock().unwrap()[v.ioa.addr().get() as usize] = Some(v.r);
                }
                future::ready(Ok(vec![]))
            }
            TypeID::M_IT_NA_1 | TypeID::M_IT_TA_1 | TypeID::M_IT_TB_1 => {
                let bcrs = asdu.get_integrated_totals().unwrap();
                for mut v in bcrs {
                    self.bcr_space.lock().unwrap()[v.ioa.addr().get() as usize] = Some(v.bcr.value);
                }
                future::ready(Ok(vec![]))
            }

            _ => future::ready(Ok(vec![])),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let mut client = IEC104Client::new("127.0.0.1:2404".parse().unwrap(), 1);

    loop {
        println!("{:?}", client.read_siq(0));
        println!("{:?}", client.read_siq(1));
        println!("{:?}", client.read_siq(2));
        println!("{:?}", client.read_siq(3));
        println!("{:?}", client.read_diq(655));
        println!("{:?}", client.read_diq(658));
        client.start().await?;
        sleep(Duration::from_millis(500)).await;
        log::info!("main sleeping...");
    }
}
