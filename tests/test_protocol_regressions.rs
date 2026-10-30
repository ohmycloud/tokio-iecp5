use bytes::BytesMut;
use futures::StreamExt;
use std::{
    collections::VecDeque,
    future::{ready, Ready},
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_iecp5::{
    apci::*, asdu::*, cproc::*, inspect::*, Client, ClientHandler, ClientOption, Codec, Error,
    SeqPending,
};
use tokio_util::codec::{Decoder, Encoder, Framed};

#[test]
fn command_wire_bits_match_iec104_and_upstream() {
    for (value, select, wire) in [
        (false, false, 0),
        (true, false, 1),
        (false, true, 0x80),
        (true, true, 0x81),
    ] {
        assert_eq!(SingleCommandInfo::new(100, value, select).sco.raw(), wire);
    }
    assert_eq!(DoubleCommandInfo::new(200, 1, true).dco.raw(), 0x81);
    assert_eq!(DoubleCommandInfo::new(200, 2, false).dco.raw(), 2);
    let mut qos = ObjectQOS::try_from(0x85).unwrap();
    assert_eq!(qos.se().get().value(), 1);
    assert_eq!(qos.ql().get().value(), 5);
    let mut qoc = ObjectQOC::try_from(0x8c).unwrap();
    assert_eq!(qoc.se().get().value(), 1);
    assert_eq!(qoc.qu().get().value(), 3);
    assert_eq!(Cause::ReturnInfoRemote as u8, 11);
    assert_eq!(Cause::ReturnInfoLocal as u8, 12);
    assert_eq!(Cause::FileTransfer as u8, 13);
}

#[test]
fn sequence_acknowledgement_wraps_at_32768() {
    let mut pending = VecDeque::from([SeqPending {
        seq: 32767,
        send_time: chrono::Utc::now(),
    }]);
    let (mut ack, mut send) = (32767, 0);
    assert!(update_ack_no_out(0, &mut ack, &mut send, &mut pending));
    assert_eq!(ack, 0);
    assert!(pending.is_empty());
    assert!(!update_ack_no_out(1, &mut ack, &mut send, &mut pending));
}

#[test]
fn decode_fragmented_and_coalesced_frames() {
    let frame = [0x68, 4, 7, 0, 0, 0];
    for split in 0..frame.len() {
        let mut buf = BytesMut::from(&frame[..split]);
        assert!(Codec.decode(&mut buf).unwrap().is_none());
        buf.extend_from_slice(&frame[split..]);
        assert!(Codec.decode(&mut buf).unwrap().is_some());
        assert!(buf.is_empty());
    }
    assert_eq!(
        inspect_frames("[68][04][07][00][00][00] 68 04 83 00 00 00")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn reject_malformed_frames_and_hex() {
    for hex in [
        "",
        "6",
        "0x680407000000",
        "garbage",
        "6804070000",
        "680402000300",
        "68080100000000000000",
        "680401010000",
        "680403000000",
        "680a00000000ff0106000100",
    ] {
        assert!(inspect_frames(hex).is_err(), "must reject {hex}");
    }
    let mut buf = BytesMut::new();
    let mut frame = new_uframe(U_STARTDT_ACTIVE);
    frame.apci.apdu_length = 8;
    assert!(Codec.encode(frame, &mut buf).is_err());
    assert!(
        buf.is_empty(),
        "failed encoding must not partly append a frame"
    );
}

#[test]
fn oversized_asdu_returns_error_without_panicking_or_partial_output() {
    let mut a = tokio_iecp5::csys::interrogation_cmd(
        CauseOfTransmission::new(false, false, Cause::Activation),
        1,
        tokio_iecp5::csys::ObjectQOI::new(20),
    )
    .unwrap();
    a.raw = bytes::Bytes::from(vec![0_u8; 300]);
    let frame = new_iframe(a, 0, 0);
    let mut buf = BytesMut::new();
    assert!(Codec.encode(frame, &mut buf).is_err());
    assert!(buf.is_empty());
}

#[derive(Clone)]
struct Noop;
impl ClientHandler for Noop {
    type Future = Ready<Result<Vec<Asdu>, Error>>;
    fn call(&self, _: Asdu) -> Self::Future {
        ready(Ok(vec![]))
    }
}

#[tokio::test]
async fn repeated_start_creates_one_connection_and_stop_closes_it() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = Arc::new(Client::new(
        Noop,
        ClientOption::new(listener.local_addr().unwrap(), false),
    ));
    let starts: Vec<_> = (0..20)
        .map(|_| {
            let c = client.clone();
            tokio::spawn(async move { c.start().await.unwrap() })
        })
        .collect();
    for start in starts {
        start.await.unwrap();
    }
    let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    client.stop().await;
    let mut framed = Framed::new(stream, Codec);
    assert!(tokio::time::timeout(Duration::from_secs(1), framed.next())
        .await
        .unwrap()
        .is_none());
    assert!(!client.is_connected().await);
    assert!(!client.is_active().await);
    client.start().await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .unwrap()
        .unwrap();
    client.stop().await;
}

#[tokio::test]
async fn stop_cancels_auto_reconnect_before_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let client = Client::new(Noop, ClientOption::new(addr, true));
    client.start().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), client.stop())
        .await
        .unwrap();
    assert!(!client.is_connected().await);
}
