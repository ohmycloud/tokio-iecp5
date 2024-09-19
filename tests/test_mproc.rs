use bytes::Bytes;
use chrono::{Datelike, TimeZone, Timelike, Utc};
use tokio_test::{assert_err, assert_ok};
use tokio_iecp5::asdu::*;
use tokio_iecp5::mproc::*;
use bit_struct::*;
use anyhow::Result;
use tokio_iecp5::Error;

#[test]
fn decode_singlepiont() -> Result<()> {
    struct Test {
        name: String,
        asdu: Asdu,
        want: Vec<SinglePointInfo>,
    }

    let mut tests = Vec::new();
    tests.push(Test {
        name: "M_SP_NA_1 seq = false Number = 2".into(),
        asdu: Asdu {
            identifier: Identifier {
                type_id: TypeID::M_SP_NA_1,
                variable_struct: VariableStruct::try_from(0x02).unwrap(),
                cot: CauseOfTransmission::try_from(0).unwrap(),
                orig_addr: 0,
                common_addr: 0,
            },
            raw: Bytes::from_static(&[0x01, 0x00, 0x00, 0x11, 0x02, 0x00, 0x00, 0x10]),
        },
        want: vec![
            SinglePointInfo::new(
                InfoObjAddr::try_from(u24!(0x01)).unwrap(),
                ObjectSIQ::try_from(0x11).unwrap(),
                None,
            ),
            SinglePointInfo::new(
                InfoObjAddr::try_from(u24!(0x02)).unwrap(),
                ObjectSIQ::try_from(0x10).unwrap(),
                None,
            ),
        ],
    });
    tests.push(Test {
        name: "M_SP_NA_1 seq = true Number = 2".into(),
        asdu: Asdu {
            identifier: Identifier {
                type_id: TypeID::M_SP_NA_1,
                variable_struct: VariableStruct::try_from(0x82).unwrap(),
                cot: CauseOfTransmission::try_from(0).unwrap(),
                orig_addr: 0,
                common_addr: 0,
            },
            raw: Bytes::from_static(&[0x01, 0x00, 0x00, 0x11, 0x10]),
        },
        want: vec![
            SinglePointInfo::new(
                InfoObjAddr::try_from(u24!(0x01)).unwrap(),
                ObjectSIQ::try_from(0x11).unwrap(),
                None,
            ),
            SinglePointInfo::new(
                InfoObjAddr::try_from(u24!(0x02)).unwrap(),
                ObjectSIQ::try_from(0x10).unwrap(),
                None,
            ),
        ],
    });

    let now_utc = Utc::now();
    let hour = now_utc.hour();
    let day = now_utc.day();
    let month = now_utc.month();
    let year = now_utc.year();

    tests.push(Test {
        name: "M_SP_NA_1 seq = true Number = 2".into(),
        asdu: Asdu {
            identifier: Identifier {
                type_id: TypeID::M_SP_TB_1,
                variable_struct: VariableStruct::try_from(0x02).unwrap(),
                cot: CauseOfTransmission::try_from(0).unwrap(),
                orig_addr: 0,
                common_addr: 0,
            },
            raw: Bytes::from_static(&[
                0x01, 0x00, 0x00, 0x11, 0x01, 0x02, 0x03, 0x04, 0x65, 0x06, 0x13, 0x02, 0x00,
                0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x65, 0x06, 0x13,
            ]),
        },
        want: vec![
            SinglePointInfo::new(
                InfoObjAddr::try_from(u24!(0x01)).unwrap(),
                ObjectSIQ::try_from(0x11).unwrap(),
                Some(Utc.with_ymd_and_hms(2019, 6, 5, 4, 3, 0).unwrap()),
            ),
            SinglePointInfo::new(
                InfoObjAddr::try_from(u24!(0x02)).unwrap(),
                ObjectSIQ::try_from(0x10).unwrap(),
                Some(Utc.with_ymd_and_hms(2019, 6, 5, 4, 3, 0).unwrap()),
            ),
        ],
    });

    tests.push(Test {
        name: "M_SP_TA_1 CP24Time2a  Number = 2".into(),
        asdu: Asdu {
            identifier: Identifier {
                type_id: TypeID::M_SP_TA_1,
                variable_struct: VariableStruct::try_from(0x02).unwrap(),
                cot: CauseOfTransmission::try_from(0).unwrap(),
                orig_addr: 0,
                common_addr: 0,
            },
            raw: Bytes::from_static(&[
                0x01, 0x00, 0x00, 0x11, 0x01, 0x02, 0x03, 0x02, 0x00, 0x00, 0x10, 0x01, 0x02,
                0x03,
            ]),
        },
        want: vec![
            SinglePointInfo::new(
                InfoObjAddr::try_from(u24!(0x01)).unwrap(),
                ObjectSIQ::try_from(0x11).unwrap(),
                Some(Utc.with_ymd_and_hms(year, month, day, hour, 3, 0).unwrap()),
            ),
            SinglePointInfo::new(
                InfoObjAddr::try_from(u24!(0x02)).unwrap(),
                ObjectSIQ::try_from(0x10).unwrap(),
                Some(Utc.with_ymd_and_hms(year, month, day, hour, 3, 0).unwrap()),
            ),
        ],
    });

    for mut t in tests {
        let result = t.asdu.get_single_point()?;
        assert_eq!(result, t.want);
    }
    Ok(())
}

#[test]
fn decode_measured_value_float() -> Result<()> {
    struct Test {
        name: String,
        asdu: Asdu,
        want: Vec<MeasuredValueFloatInfo>,
    }

    let r1 = 100_f32.to_le_bytes();
    let r2 = 101_f32.to_le_bytes();

    let mut tests = Vec::new();
    tests.push(Test {
        name: "M_ME_NC_1 seq = false Number = 2".into(),
        asdu: Asdu {
            identifier: Identifier {
                type_id: TypeID::M_ME_NC_1,
                variable_struct: VariableStruct::try_from(0x02).unwrap(),
                cot: CauseOfTransmission::try_from(0).unwrap(),
                orig_addr: 0,
                common_addr: 0,
            },
            raw: Bytes::from_iter([
                0x01, 0x00, 0x00, r1[0], r1[1], r1[2], r1[3], 0x10, 0x02, 0x00, 0x00, r2[0],
                r2[1], r2[2], r2[3], 0x10,
            ]),
        },
        want: vec![
            MeasuredValueFloatInfo {
                ioa: InfoObjAddr::try_from(u24!(0x01)).unwrap(),
                r: 100.0,
                qds: ObjectQDS::new(false, false, false, true, u3!(0), false),
                time: None,
            },
            MeasuredValueFloatInfo {
                ioa: InfoObjAddr::try_from(u24!(0x02)).unwrap(),
                r: 101.0,
                qds: ObjectQDS::new(false, false, false, true, u3!(0), false),
                time: None,
            },
        ],
    });
    tests.push(Test {
        name: "M_ME_NC_1 seq = true Number = 2".into(),
        asdu: Asdu {
            identifier: Identifier {
                type_id: TypeID::M_ME_NC_1,
                variable_struct: VariableStruct::try_from(0x82).unwrap(),
                cot: CauseOfTransmission::try_from(0).unwrap(),
                orig_addr: 0,
                common_addr: 0,
            },
            raw: Bytes::from_iter([
                0x01, 0x00, 0x00, r1[0], r1[1], r1[2], r1[3], 0x10, r2[0], r2[1], r2[2], r2[3],
                0x10,
            ]),
        },
        want: vec![
            MeasuredValueFloatInfo {
                ioa: InfoObjAddr::try_from(u24!(0x01)).unwrap(),
                r: 100.0,
                qds: ObjectQDS::new(false, false, false, true, u3!(0), false),
                time: None,
            },
            MeasuredValueFloatInfo {
                ioa: InfoObjAddr::try_from(u24!(0x02)).unwrap(),
                r: 101.0,
                qds: ObjectQDS::new(false, false, false, true, u3!(0), false),
                time: None,
            },
        ],
    });
    for mut t in tests {
        let result = t.asdu.get_measured_value_float()?;
        assert_eq!(result, t.want);
    }
    Ok(())
}

#[test]
fn test_single() -> Result<()> {
    struct Args {
        is_sequence: bool,
        cot: CauseOfTransmission,
        ca: CommonAddr,
        infos: Vec<SinglePointInfo>,
        want_bytes: Bytes,
    }

    struct Test {
        name: String,
        args: Args,
        want_err: bool,
    }

    let tests = vec![
        Test {
            name: "invalid cause".into(),
            args: Args {
                is_sequence: false,
                cot: CauseOfTransmission::new(false, false, Cause::Unused),
                ca: 0x1234,
                infos: vec![],
                want_bytes: Bytes::new(),
            },
            want_err: true,
        },
        Test {
            name: "M_SP_NA_1 seq = false Number = 2".into(),
            args: Args {
                is_sequence: false,
                cot: CauseOfTransmission::new(false, false, Cause::Background),
                ca: 0x1234,
                infos: vec![
                    SinglePointInfo::new(
                        InfoObjAddr::try_from(u24!(0x01)).unwrap(),
                        ObjectSIQ::new(false, false, false, true, u3!(0), true),
                        None,
                    ),
                    SinglePointInfo::new(
                        InfoObjAddr::try_from(u24!(0x02)).unwrap(),
                        ObjectSIQ::new(false, false, false, true, u3!(0), false),
                        None,
                    ),
                ],
                want_bytes: Bytes::from_static(&[
                    TypeID::M_SP_NA_1 as u8,
                    0x02,
                    0x02,
                    0x00,
                    0x34,
                    0x12,
                    0x01,
                    0x00,
                    0x00,
                    0x11,
                    0x02,
                    0x00,
                    0x00,
                    0x10,
                ]),
            },
            want_err: false,
        },
        Test {
            name: "M_SP_NA_1 seq = true Number = 2".into(),
            args: Args {
                is_sequence: true,
                cot: CauseOfTransmission::new(false, false, Cause::Background),
                ca: 0x1234,
                infos: vec![
                    SinglePointInfo::new(
                        InfoObjAddr::try_from(u24!(0x01)).unwrap(),
                        ObjectSIQ::new(false, false, false, true, u3!(0), true),
                        None,
                    ),
                    SinglePointInfo::new(
                        InfoObjAddr::try_from(u24!(0x02)).unwrap(),
                        ObjectSIQ::new(false, false, false, true, u3!(0), false),
                        None,
                    ),
                ],
                want_bytes: Bytes::from_static(&[
                    TypeID::M_SP_NA_1 as u8,
                    0x82,
                    0x02,
                    0x00,
                    0x34,
                    0x12,
                    0x01,
                    0x00,
                    0x00,
                    0x11,
                    0x10,
                ]),
            },
            want_err: false,
        },
    ];

    for t in tests {
        let r = single(t.args.is_sequence, t.args.cot, t.args.ca, t.args.infos)
            .map(|asdu| {
                let raw: Bytes = asdu.try_into().unwrap();
                raw
            })
            .and_then(|raw| {
                let want_bytes = t.args.want_bytes;
                if raw != want_bytes {
                    return Err(Error::ErrAnyHow(anyhow::anyhow!(
                            "expected: {want_bytes:?}, result: {raw:?}"
                        )));
                }
                Ok(())
            });

        if r.is_err() != t.want_err {
            if t.want_err {
                assert_err!(r);
            } else {
                assert_ok!(r);
            }
        }
    }

    Ok(())
}