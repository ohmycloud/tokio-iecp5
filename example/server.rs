use anyhow::Result;
use std::{
    collections::HashMap,
    future, io,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use tokio::{
    net::{TcpListener, TcpStream},
    select,
};
use tokio_iecp5::{
    asdu::{Asdu, Cause, CauseOfTransmission, InfoObjAddr, TypeID},
    csys::{ObjectQCC, ObjectQOI},
    mproc::{double, single, DoublePointInfo, ObjectSIQ, SinglePointInfo},
    Error, Server, ServerHandler,
};

struct ExampleServer {
    siq: Arc<Mutex<HashMap<u16, bool>>>,
    diq: Arc<Mutex<HashMap<u16, u8>>>,
}

impl ExampleServer {
    pub fn new(siq: HashMap<u16, bool>, diq: HashMap<u16, u8>) -> Self {
        ExampleServer {
            siq: Arc::new(Mutex::new(siq)),
            diq: Arc::new(Mutex::new(diq)),
        }
    }
}

impl ServerHandler for ExampleServer {
    type Future = future::Ready<Result<Vec<Asdu>, Error>>;

    fn call(&self, asdu: Asdu) -> Self::Future {
        let mut asdu = asdu;
        let type_id = asdu.identifier.type_id;
        match type_id {
            TypeID::C_SC_NA_1 | TypeID::C_SC_TA_1 => {
                let mut single_cmd = asdu.get_single_cmd().unwrap();
                let ad = single_cmd.ioa.addr().get();
                let v = single_cmd.sco.scs().get();
                if let Some(value) = self.siq.lock().unwrap().get_mut(&ad) {
                    *value = v;
                }
            }
            TypeID::C_DC_NA_1 | TypeID::C_DC_TA_1 => {
                let mut double_cmd = asdu.get_double_cmd().unwrap();
                let ad = double_cmd.ioa.addr().get();
                let v = double_cmd.dco.dcs().get().value();
                if let Some(value) = self.diq.lock().unwrap().get_mut(&ad) {
                    *value = v;
                }
            }
            _ => (),
        };
        future::ready(Ok(Vec::new()))
    }

    fn call_interrogation(&self, _: Asdu, _qoi: ObjectQOI) -> Self::Future {
        let mut asdus = vec![];

        let mut siq_infos = vec![];
        for (addr, v) in self.siq.lock().unwrap().iter() {
            siq_infos.push(SinglePointInfo::new(
                InfoObjAddr::new(0, *addr),
                ObjectSIQ::new_with_value(*v),
                None,
            ));
        }
        let siq_asdu = single(
            false,
            CauseOfTransmission::new(false, false, Cause::InterrogatedByStation),
            0,
            siq_infos,
        )
        .unwrap();
        asdus.push(siq_asdu);

        let mut diq_infos = vec![];
        for (addr, v) in self.diq.lock().unwrap().iter() {
            diq_infos.push(DoublePointInfo::new_double(*addr, *v));
        }
        let diq_asdu = double(
            false,
            CauseOfTransmission::new(false, false, Cause::InterrogatedByStation),
            0,
            diq_infos,
        )
        .unwrap();
        asdus.push(diq_asdu);

        future::ready(Ok(asdus))
    }

    fn call_counter_interrogation(&self, _: Asdu, _qcc: ObjectQCC) -> Self::Future {
        future::ready(Ok(Vec::new()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let socket_addr = "127.0.0.1:2404".parse().unwrap();

    select! {
        _ = server(socket_addr) => {}

    }

    Ok(())
}

/// Accept unencrypted TCP connections.
pub fn accept_tcp_connection<S, NewService>(
    stream: TcpStream,
    socket_addr: SocketAddr,
    new_service: NewService,
) -> io::Result<Option<(S, TcpStream)>>
where
    S: ServerHandler + Send + Sync + 'static,
    NewService: Fn(SocketAddr) -> io::Result<Option<S>>,
{
    let service = new_service(socket_addr)?;
    Ok(service.map(|service| (service, stream)))
}

async fn server(socket_addr: SocketAddr) -> Result<()> {
    println!("Starting up server on {socket_addr}");
    let listener = TcpListener::bind(socket_addr).await?;
    let server = Server::new(listener);
    let mut siq = HashMap::new();
    let mut diq = HashMap::new();
    siq.insert(100, false);
    siq.insert(111, true);
    siq.insert(121, false);
    diq.insert(3000, 2);
    diq.insert(2345, 3);
    diq.insert(4523, 3);
    diq.insert(4524, 3);
    diq.insert(4525, 2);
    diq.insert(4526, 1);
    let handler = Arc::new(ExampleServer::new(siq, diq));
    let new_service = |_socket_addr| Ok(Some(handler.clone()));
    let on_connected = |stream, socket_addr| async move {
        accept_tcp_connection(stream, socket_addr, new_service)
    };
    let on_process_error = |err| {
        eprintln!("{err}");
    };
    server.serve(&on_connected, on_process_error).await?;

    Ok(())
}
