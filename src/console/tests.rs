use super::*;

async fn station(c: &Console) -> String {
    c.perform(Action::ServerStart {
        address: "127.0.0.1:0".into(),
        common_addr: 1,
    })
    .await
    .unwrap();
    c.snapshot().await.server_addr.unwrap()
}
async fn connect(c: &Console, address: String) {
    c.perform(Action::ClientConnect {
        address,
        common_addr: 1,
    })
    .await
    .unwrap();
    c.perform(Action::StartDt).await.unwrap();
}

#[tokio::test]
async fn full_station_master_workflow() {
    let c = Console::new("test-token".into());
    let addr = station(&c).await;
    connect(&c, addr.clone()).await;
    assert_eq!(c.snapshot().await.peers, 1);
    c.perform(Action::Interrogation).await.unwrap();
    let s = c.snapshot().await;
    assert_eq!(s.received.len(), 10);
    assert!(s
        .received
        .iter()
        .any(|p| p.ioa == 500 && (p.value - 10.52).abs() < 0.001));
    c.perform(Action::CounterInterrogation).await.unwrap();
    let s = c.snapshot().await;
    assert_eq!(s.received.len(), 12);
    assert_eq!(
        s.received.iter().find(|p| p.ioa == 600).unwrap().value,
        128640.0
    );
    // Select is acknowledged, but MUST NOT change the physical simulated value.
    c.perform(Action::Select {
        ioa: 100,
        kind: PointKind::Single,
        value: 0.0,
    })
    .await
    .unwrap();
    assert_eq!(lock(&c.data).station[&100].value, 1.0);
    c.perform(Action::Execute {
        ioa: 100,
        kind: PointKind::Single,
        value: 0.0,
    })
    .await
    .unwrap();
    let s = c.snapshot().await;
    assert_eq!(s.station.iter().find(|p| p.ioa == 100).unwrap().value, 0.0);
    assert_eq!(s.received.iter().find(|p| p.ioa == 100).unwrap().value, 0.0);
    c.perform(Action::Select {
        ioa: 200,
        kind: PointKind::Double,
        value: 2.0,
    })
    .await
    .unwrap();
    c.perform(Action::Execute {
        ioa: 200,
        kind: PointKind::Double,
        value: 2.0,
    })
    .await
    .unwrap();
    assert_eq!(lock(&c.data).received[&200].value, 2.0);
    c.perform(Action::UpdatePoint {
        ioa: 500,
        value: 11.2,
    })
    .await
    .unwrap();
    c.perform(Action::Interrogation).await.unwrap();
    assert!((lock(&c.data).received[&500].value - 11.2).abs() < 0.001);
    c.perform(Action::StopDt).await.unwrap();
    assert!(!c.snapshot().await.active);
    assert!(c.perform(Action::Interrogation).await.is_err());
    c.perform(Action::StartDt).await.unwrap();
    c.perform(Action::ServerStop).await.unwrap();
    assert_eq!(c.snapshot().await.peers, 0);
    tokio::time::timeout(Duration::from_secs(1), async {
        while c.snapshot().await.connected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // No orphan listener/session should prevent rebinding to the same port.
    c.perform(Action::ServerStart {
        address: addr.clone(),
        common_addr: 1,
    })
    .await
    .unwrap();
    connect(&c, addr).await;
    c.shutdown().await;
    assert_eq!(c.snapshot().await.peers, 0);
}

#[tokio::test]
async fn reject_invalid_or_expired_control_without_mutation() {
    let c = Console::new("test-token".into());
    let addr = station(&c).await;
    connect(&c, addr).await;
    assert!(c
        .perform(Action::Execute {
            ioa: 100,
            kind: PointKind::Single,
            value: 0.0
        })
        .await
        .is_err());
    assert!(c
        .perform(Action::Select {
            ioa: 999,
            kind: PointKind::Single,
            value: 0.0
        })
        .await
        .is_err());
    assert!(c
        .perform(Action::Select {
            ioa: 200,
            kind: PointKind::Double,
            value: 3.0
        })
        .await
        .is_err());
    c.perform(Action::Select {
        ioa: 100,
        kind: PointKind::Single,
        value: 0.0,
    })
    .await
    .unwrap();
    lock(&c.selection).as_mut().unwrap().at = Instant::now() - Duration::from_secs(11);
    assert!(c
        .perform(Action::Execute {
            ioa: 100,
            kind: PointKind::Single,
            value: 0.0
        })
        .await
        .is_err());
    assert_eq!(lock(&c.data).station[&100].value, 1.0);
    c.shutdown().await;
}

#[test]
fn station_enforces_select_per_connection() {
    let c = Console::new("test-token".into());
    let first = StationHandler::new(c.data.clone(), "127.0.0.1:1".parse().unwrap());
    let second = StationHandler::new(c.data.clone(), "127.0.0.1:2".parse().unwrap());
    let a = c.control(100, PointKind::Single, 0.0, true).unwrap();
    first.command(&a).unwrap();
    let a = c.control(100, PointKind::Single, 0.0, false).unwrap();
    let mut denied = second.command(&a).unwrap().remove(0);
    assert!(denied.identifier.cot.positive().get());
    assert_eq!(lock(&c.data).station[&100].value, 1.0);
    first.command(&a).unwrap();
    assert_eq!(lock(&c.data).station[&100].value, 0.0);
}

#[tokio::test]
async fn address_and_value_validation() {
    let c = Console::new("test-token".into());
    assert!(c
        .perform(Action::ServerStart {
            address: "0.0.0.0:2404".into(),
            common_addr: 1
        })
        .await
        .is_err());
    assert!(c
        .perform(Action::ServerStart {
            address: "127.0.0.1:0".into(),
            common_addr: 0
        })
        .await
        .is_err());
    for value in [f64::NAN, f64::INFINITY, 32768.0, 2.5] {
        assert!(valid_value(PointKind::Scaled, value).is_err());
    }
    assert!(c
        .perform(Action::UpdatePoint {
            ioa: 100,
            value: 2.0
        })
        .await
        .is_err());
    assert_eq!(lock(&c.data).station[&100].value, 1.0);
}

#[tokio::test]
async fn missing_confirmation_times_out_instead_of_reporting_success() {
    struct Silent;
    impl ServerHandler for Silent {
        type Future = Ready<Result<Vec<Asdu>, Error>>;
        fn call(&self, _: Asdu) -> Self::Future {
            ready(Ok(vec![]))
        }
        fn call_interrogation(&self, _: Asdu, _: ObjectQOI) -> Self::Future {
            ready(Ok(vec![]))
        }
        fn call_counter_interrogation(&self, _: Asdu, _: ObjectQCC) -> Self::Future {
            ready(Ok(vec![]))
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let on_connected = |stream, _| async move { Ok(Some((Silent, stream))) };
        Server::new(listener)
            .serve(&on_connected, |_| {})
            .await
            .unwrap();
    });
    let c = Console::new("test-token".into());
    connect(&c, addr.to_string()).await;
    let err = c
        .perform(Action::Select {
            ioa: 100,
            kind: PointKind::Single,
            value: 0.0,
        })
        .await
        .unwrap_err();
    assert!(err.to_string().contains("确认超时"));
    assert!(lock(&c.selection).is_none());
    c.shutdown().await;
    server.abort();
    let _ = server.await;
}

#[test]
fn token_is_required() {
    let c = Console::new("secret".into());
    let mut h = HeaderMap::new();
    assert!(!authorized(&c, &h));
    h.insert("x-iec104-token", "wrong".parse().unwrap());
    assert!(!authorized(&c, &h));
    h.insert("x-iec104-token", "secret".parse().unwrap());
    assert!(authorized(&c, &h));
}
