use anyhow::Result;
use std::{future, io, net::SocketAddr, sync::Arc};

use iecp5::{
    asdu::{Asdu, Cause, CauseOfTransmission, InfoObjAddr},
    csys::ObjectQOI,
    mproc::{single, ObjectSIQ, SinglePointInfo},
    Error, Server, ServerHandler,
};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
};

struct ExampleServer;

impl ServerHandler for ExampleServer {
    type Future = future::Ready<Result<Vec<Asdu>, Error>>;

    fn call(&self, _asdu: Asdu) -> Self::Future {
        future::ready(Ok(Vec::new()))
    }

    fn call_interrogation(&self, _req: Asdu, _qoi: ObjectQOI) -> Self::Future {
        let mut asdus = vec![];
        let infos = vec![
            SinglePointInfo::new(
                InfoObjAddr::new(0, 0),
                ObjectSIQ::new_with_value(false),
                None,
            ),
            SinglePointInfo::new(
                InfoObjAddr::new(0, 1),
                ObjectSIQ::new_with_value(true),
                None,
            ),
        ];
        let asdu = single(
            true,
            CauseOfTransmission::new(false, false, Cause::InterrogatedByStation),
            0,
            infos,
        )
        .unwrap();
        asdus.push(asdu);
        future::ready(Ok(asdus))
    }

    fn call_counter_interrogation(&self, _req: Asdu, _qcc: iecp5::csys::ObjectQCC) -> Self::Future {
        todo!()
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
    let handler = Arc::new(Box::new(ExampleServer));
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
