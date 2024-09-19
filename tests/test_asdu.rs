use anyhow::Result;
use bytes::Bytes;
use tokio_iecp5::asdu::{Asdu, Cause, TypeID};

#[test]
fn decode_and_encode_asdu() -> Result<()> {
    let bytes =
        Bytes::from_static(&[0x01, 0x01, 0x06, 0x00, 0x80, 0x00, 0x00, 0x01, 0x02, 0x03]);
    let mut asdu: Asdu = bytes.clone().try_into()?;
    assert_eq!(asdu.identifier.type_id, TypeID::M_SP_NA_1);
    assert_eq!(asdu.identifier.variable_struct.number().get().value(), 0x01);
    assert_eq!(asdu.identifier.cot.cause().get(), Cause::Activation);
    assert_eq!(asdu.identifier.orig_addr, 0x00);
    assert_eq!(asdu.identifier.common_addr, 0x80);
    assert_eq!(asdu.raw, Bytes::from_static(&[0x00, 0x01, 0x02, 0x03]));

    let raw: Bytes = asdu.try_into()?;
    assert_eq!(bytes, raw);
    Ok(())
}

#[test]
fn asdu_from_bytes() -> Result<()> {
    let bytes = Bytes::from_static(&[0x30, 0x01, 0x6C, 0x00, 0x01, 0x00, 0x05, 0x62, 0x00, 0x32, 0x00, 0x80]);
    let mut asdu: Asdu = bytes.clone().try_into()?;
    assert_eq!(asdu.identifier.type_id, TypeID::C_SE_NA_1);
    assert_eq!(asdu.identifier.variable_struct.number().get().value(), 0x01);
    assert_eq!(asdu.identifier.cot.cause().get(), Cause::UnknownTypeID);
    assert_eq!(asdu.identifier.orig_addr, 0x00);
    assert_eq!(asdu.identifier.common_addr, 0x01);
    assert_eq!(asdu.raw, Bytes::from_static(&[0x05, 0x62, 0x00, 0x32, 0x00, 0x80]));

    let raw: Bytes = asdu.try_into()?;
    assert_eq!(bytes, raw);
    Ok(())
}