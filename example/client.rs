use std::{sync::Arc, time::Duration};

use anyhow::Result;
use iecp5::{
    asdu::{Asdu, Cause, CauseOfTransmission, TypeID},
    csys::ObjectQOI,
    Client, ClientHandler, ClientOption, Error,
};
use tokio::time::sleep;

#[derive(Debug)]
struct ExampleHandler;

impl ClientHandler for ExampleHandler {
    fn call(&self, asdu: Asdu) -> Option<Vec<Asdu>> {
        let mut asdu = asdu;
        match asdu.identifier.type_id {
            TypeID::C_IC_NA_1 => None,
            TypeID::M_SP_NA_1 => {
                let sg = asdu.get_single_point();
                log::info!("ClientHandler {sg:?}");
                None
            }

            _ => None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let op = ClientOption::default();
    let mut client = Client::new(Arc::new(Box::new(ExampleHandler)), op);
    let _ = client.start().await;
    if let Err(e) = client.send_start_dt().await {
        println!("{e:?}")
    }

    sleep(Duration::from_secs(1)).await;

    let cot = CauseOfTransmission::new(false, false, Cause::Activation);
    let ca = 1;
    let qoi = ObjectQOI::new(20);
    if let Err(e) = client.interrogation_cmd(cot, ca, qoi).await {
        println!("{e:?}")
    }

    loop {
        sleep(Duration::from_millis(500)).await;
        log::info!("main sleeping...");
    }
}
