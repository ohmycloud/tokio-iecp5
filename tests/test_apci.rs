use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use tokio_iecp5::apci::*;
use tokio_iecp5::{Apdu, Codec};
use tokio_iecp5::asdu::*;
use tokio_util::codec::{Decoder, Encoder};

#[test]
fn decode_iapci() -> Result<()> {
    let mut codec = Codec;
    let mut buf = BytesMut::from(&[START_FRAME, 0x04, 0x02, 0x00, 0x03, 0x00][..]);
    let apdu = codec.decode(&mut buf)?.ok_or(anyhow!("decode failed"))?;
    let apci_kind = apdu.apci.into();
    match apci_kind {
        ApciKind::I(apci) => {
            assert_eq!(apci.send_sn, 0x01);
            assert_eq!(apci.rcv_sn, 0x01);
        }
        _ => panic!(),
    }
    Ok(())
}

#[test]
fn decode_sapci() -> Result<()> {
    let mut codec = Codec;
    let mut buf = BytesMut::from(&[START_FRAME, 0x04, 0x01, 0x00, 0x02, 0x00][..]);
    let apdu = codec.decode(&mut buf)?.ok_or(anyhow!("decode failed"))?;
    let apci_kind = apdu.apci.into();
    match apci_kind {
        ApciKind::S(apci) => {
            assert_eq!(apci.rcv_sn, 0x01);
        }
        _ => panic!(),
    }
    Ok(())
}

#[test]
fn decode_uapci() -> Result<()> {
    let mut codec = Codec;
    let mut buf = BytesMut::from(&[START_FRAME, 0x04, 0x07, 0x00, 0x00, 0x00][..]);
    let apdu = codec.decode(&mut buf)?.ok_or(anyhow!("decode failed"))?;
    let apci_kind = apdu.apci.into();
    match apci_kind {
        ApciKind::U(apci) => {
            assert_eq!(apci.function, U_STARTDT_ACTIVE);
        }
        _ => panic!(),
    }
    Ok(())
}

#[test]
fn encode_iapci() -> Result<()> {
    let mut codec = Codec;
    let apdu = Apdu {
        apci: Apci {
            start: START_FRAME,
            apdu_length: 0x04 + IDENTIFIER_SIZE as u8 + 8,
            ctrl1: 0x02,
            ctrl2: 0x00,
            ctrl3: 0x03,
            ctrl4: 0x00,
        },
        asdu: Some(Asdu {
            identifier: Identifier {
                type_id: TypeID::M_SP_NA_1,
                variable_struct: VariableStruct::try_from(0x02)
                    .map_err(|_| anyhow!("failed convert into variable struct"))?,
                cot: CauseOfTransmission::try_from(0x06)
                    .map_err(|_| anyhow!("failed convert into cause of transmission"))?,
                orig_addr: 0,
                common_addr: 0,
            },
            raw: Bytes::from_static(&[0x01, 0x00, 0x00, 0x11, 0x02, 0x00, 0x00, 0x10]),
        }),
    };
    let expected = [
        START_FRAME,
        0x04 + IDENTIFIER_SIZE as u8 + 8,
        0x02,
        0x00,
        0x03,
        0x00,
        0x01,
        0x02,
        0x06,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x11,
        0x02,
        0x00,
        0x00,
        0x10,
    ];

    let mut buf = BytesMut::with_capacity(APDU_SIZE_MAX);
    codec.encode(apdu, &mut buf)?;
    assert_eq!(buf.as_ref(), &expected[..]);
    Ok(())
}