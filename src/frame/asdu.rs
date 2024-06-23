use std::io::Cursor;

use anyhow::{anyhow, Result};
use bit_struct::*;
use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chrono::{DateTime, Datelike, TimeZone, Timelike, Utc};

// ASDUSizeMax asdu max size
pub(crate) const ASDU_SIZE_MAX: usize = 249;

// ASDU format
//       | data unit identification | information object <1..n> |
//
//       | <------------  data unit identification ------------>|
//       | typeID | variable struct | cause  |  common address  |
// bytes |    1   |      1          | [1,2]  |      [1,2]       |
//       | <------------  information object ------------------>|
//       | object address | element set  |  object time scale   |
// bytes |     [1,2,3]    |              |                      |

// InvalidCommonAddr is the invalid common address.
#[allow(dead_code)]
const INVALID_COMMON_ADDR: u16 = 0;

// GlobalCommonAddr is the broadcast address. Use is restricted
// to C_IC_NA_1, C_CI_NA_1, C_CS_NA_1 and C_RP_NA_1.
// When in 8-bit mode 255 is mapped to this value on the fly.
#[allow(dead_code)]
const GLOBAL_COMMON_ADDR: u16 = 65535;

pub const IDENTIFIER_SIZE: usize = 5;

#[derive(Debug)]
pub struct Asdu {
    pub identifier: Identifier,
    pub raw: Bytes,
}

#[derive(Debug)]
pub struct Identifier {
    pub type_id: TypeID,
    pub variable_struct: VariableStruct,
    pub cause: CauseOfTransmission,
    pub common_addr: u16,
}

// #[derive(Debug)]
// #[allow(dead_code)]
// pub enum Obj {
//     SinglePoint(Vec<SinglePointInfo>),
//     DoublePoint(Vec<DoublePointInfo>),
//     MeasuredValueNormal(Vec<MeasuredValueNormalInfo>),
// }

bit_struct! {
    pub struct VariableStruct(u8) {
        is_sequence: u1,
        number: u7,
    }
}

enums! {
    pub Cause {
        Unused,
        Periodic,
        Background,
        Spontaneous,
        Initialized,
        Request,
        Activation,
        ActivationCon,
        Deactivation,
        DeactivationCon,
        ActivationTerm,
        ReturnInfoRemote,
        ReturnInfoLocal,
        FileTransfer,
        Authentication,
        SessionKey,
        UserRoleAndUpdateKey,
        Reserved1,
        Reserved2,
        Reserved3,
        InterrogatedByStation,
        InterrogatedByGroup1,
        InterrogatedByGroup2,
        InterrogatedByGroup3,
        InterrogatedByGroup4,
        InterrogatedByGroup5,
        InterrogatedByGroup6,
        InterrogatedByGroup7,
        InterrogatedByGroup8,
        InterrogatedByGroup9,
        InterrogatedByGroup10,
        InterrogatedByGroup11,
        InterrogatedByGroup12,
        InterrogatedByGroup13,
        InterrogatedByGroup14,
        InterrogatedByGroup15,
        InterrogatedByGroup16,
        RequestByGeneralCounter,
        RequestByGroup1Counter,
        RequestByGroup2Counter,
        RequestByGroup3Counter,
        RequestByGroup4Counter,
        Reserved4,
        Reserved5,
        UnknownTypeID,
        UnknownCOT,
        UnknownCA,
        UnknownIOA,
    }
}

bit_struct! {
    pub struct CauseOfTransmission(u8) {
        test: bool,
        positive: bool,
        cause: Cause,
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub(crate) enum TypeID {
    M_SP_NA_1 = 1,
    M_SP_TA_1 = 2,
    M_DP_NA_1 = 3,
    M_DP_TA_1 = 4,
    M_ST_NA_1 = 5,
    M_ST_TA_1 = 6,
    M_BO_NA_1 = 7,
    M_BO_TA_1 = 8,
    M_ME_NA_1 = 9,
    M_ME_TA_1 = 10,
    M_ME_NB_1 = 11,
    M_ME_TB_1 = 12,
    M_ME_NC_1 = 13,
    M_ME_TC_1 = 14,
    M_IT_NA_1 = 15,
    M_IT_TA_1 = 16,
    M_EP_TA_1 = 17,
    M_EP_TB_1 = 18,
    M_EP_TC_1 = 19,
    M_PS_NA_1 = 20,
    M_ME_ND_1 = 21,
    M_SP_TB_1 = 30,
    M_DP_TB_1 = 31,
    M_ST_TB_1 = 32,
    M_BO_TB_1 = 33,
    M_ME_TD_1 = 34,
    M_ME_TE_1 = 35,
    M_ME_TF_1 = 36,
    M_IT_TB_1 = 37,
    M_EP_TD_1 = 38,
    M_EP_TE_1 = 39,
    M_EP_TF_1 = 40,
    S_IT_TC_1 = 41,
    C_SC_NA_1 = 45,
    C_DC_NA_1 = 46,
    C_RC_NA_1 = 47,
    C_SE_NA_1 = 48,
    C_SE_NB_1 = 49,
    C_SE_NC_1 = 50,
    C_BO_NA_1 = 51,
    C_SC_TA_1 = 58,
    C_DC_TA_1 = 59,
    C_RC_TA_1 = 60,
    C_SE_TA_1 = 61,
    C_SE_TB_1 = 62,
    C_SE_TC_1 = 63,
    C_BO_TA_1 = 64,
    M_EI_NA_1 = 70,
    S_CH_NA_1 = 81,
    S_RP_NA_1 = 82,
    S_AR_NA_1 = 83,
    S_KR_NA_1 = 84,
    S_KS_NA_1 = 85,
    S_KC_NA_1 = 86,
    S_ER_NA_1 = 87,
    S_US_NA_1 = 90,
    S_UQ_NA_1 = 91,
    S_UR_NA_1 = 92,
    S_UK_NA_1 = 93,
    S_UA_NA_1 = 94,
    S_UC_NA_1 = 95,
    C_IC_NA_1 = 100,
    C_CI_NA_1 = 101,
    C_RD_NA_1 = 102,
    C_CS_NA_1 = 103,
    C_TS_NA_1 = 104,
    C_RP_NA_1 = 105,
    C_CD_NA_1 = 106,
    C_TS_TA_1 = 107,
    P_ME_NA_1 = 110,
    P_ME_NB_1 = 111,
    P_ME_NC_1 = 112,
    P_AC_NA_1 = 113,
    F_FR_NA_1 = 120,
    F_SR_NA_1 = 121,
    F_SC_NA_1 = 122,
    F_LS_NA_1 = 123,
    F_AF_NA_1 = 124,
    F_SG_NA_1 = 125,
    F_DR_TA_1 = 126,
    F_SC_NB_1 = 127,
}

impl TryFrom<u8> for TypeID {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::M_SP_NA_1),
            2 => Ok(Self::M_SP_TA_1),
            3 => Ok(Self::M_DP_NA_1),
            4 => Ok(Self::M_DP_TA_1),
            5 => Ok(Self::M_ST_NA_1),
            6 => Ok(Self::M_ST_TA_1),
            7 => Ok(Self::M_BO_NA_1),
            8 => Ok(Self::M_BO_TA_1),
            9 => Ok(Self::M_ME_NA_1),
            10 => Ok(Self::M_ME_TA_1),
            11 => Ok(Self::M_ME_NB_1),
            12 => Ok(Self::M_ME_TB_1),
            13 => Ok(Self::M_ME_NC_1),
            14 => Ok(Self::M_ME_TC_1),
            15 => Ok(Self::M_IT_NA_1),
            16 => Ok(Self::M_IT_TA_1),
            17 => Ok(Self::M_EP_TA_1),
            18 => Ok(Self::M_EP_TB_1),
            19 => Ok(Self::M_EP_TC_1),
            20 => Ok(Self::M_PS_NA_1),
            21 => Ok(Self::M_ME_ND_1),
            30 => Ok(Self::M_SP_TB_1),
            31 => Ok(Self::M_DP_TB_1),
            32 => Ok(Self::M_ST_TB_1),
            33 => Ok(Self::M_BO_TB_1),
            34 => Ok(Self::M_ME_TD_1),
            35 => Ok(Self::M_ME_TE_1),
            36 => Ok(Self::M_ME_TF_1),
            37 => Ok(Self::M_IT_TB_1),
            38 => Ok(Self::M_EP_TD_1),
            39 => Ok(Self::M_EP_TE_1),
            40 => Ok(Self::M_EP_TF_1),
            41 => Ok(Self::S_IT_TC_1),
            45 => Ok(Self::C_SC_NA_1),
            46 => Ok(Self::C_DC_NA_1),
            47 => Ok(Self::C_RC_NA_1),
            48 => Ok(Self::C_SE_NA_1),
            49 => Ok(Self::C_SE_NB_1),
            50 => Ok(Self::C_SE_NC_1),
            51 => Ok(Self::C_BO_NA_1),
            52 => Ok(Self::M_IT_TA_1),
            53 => Ok(Self::M_IT_TA_1),
            54 => Ok(Self::M_IT_TA_1),
            55 => Ok(Self::M_IT_TA_1),
            56 => Ok(Self::M_IT_TA_1),
            57 => Ok(Self::M_IT_TA_1),
            58 => Ok(Self::C_SC_TA_1),
            59 => Ok(Self::C_DC_TA_1),
            60 => Ok(Self::C_RC_TA_1),
            61 => Ok(Self::C_SE_TA_1),
            62 => Ok(Self::C_SE_TB_1),
            63 => Ok(Self::C_SE_TC_1),
            64 => Ok(Self::C_BO_TA_1),
            70 => Ok(Self::M_EI_NA_1),
            81 => Ok(Self::S_CH_NA_1),
            82 => Ok(Self::S_RP_NA_1),
            83 => Ok(Self::S_AR_NA_1),
            84 => Ok(Self::S_KR_NA_1),
            85 => Ok(Self::S_KS_NA_1),
            86 => Ok(Self::S_KC_NA_1),
            87 => Ok(Self::S_ER_NA_1),
            90 => Ok(Self::S_US_NA_1),
            91 => Ok(Self::S_UQ_NA_1),
            92 => Ok(Self::S_UR_NA_1),
            93 => Ok(Self::S_UK_NA_1),
            94 => Ok(Self::S_UA_NA_1),
            95 => Ok(Self::S_UC_NA_1),
            100 => Ok(Self::C_IC_NA_1),
            101 => Ok(Self::C_CI_NA_1),
            102 => Ok(Self::C_RD_NA_1),
            103 => Ok(Self::C_CS_NA_1),
            104 => Ok(Self::C_TS_NA_1),
            105 => Ok(Self::C_RP_NA_1),
            106 => Ok(Self::C_CD_NA_1),
            107 => Ok(Self::C_TS_TA_1),
            110 => Ok(Self::P_ME_NA_1),
            111 => Ok(Self::P_ME_NB_1),
            112 => Ok(Self::P_ME_NC_1),
            113 => Ok(Self::P_AC_NA_1),
            120 => Ok(Self::F_FR_NA_1),
            121 => Ok(Self::F_SR_NA_1),
            122 => Ok(Self::F_SC_NA_1),
            123 => Ok(Self::F_LS_NA_1),
            124 => Ok(Self::F_AF_NA_1),
            125 => Ok(Self::F_SG_NA_1),
            126 => Ok(Self::F_DR_TA_1),
            127 => Ok(Self::F_SC_NB_1),
            _ => Err(anyhow!("Unknown TypeId: {}", value)),
        }
    }
}

// 信息对象地址 (IEC104)
bit_struct! {
    pub struct ObjectAddr(u24) {
        res: u8,       // 未使用, 置0
        addr: u16,     // 有效取值 [1, 65534]
    }
}

impl TryFrom<Bytes> for Asdu {
    type Error = anyhow::Error;

    fn try_from(bytes: Bytes) -> Result<Self> {
        let mut rdr = Cursor::new(&bytes);
        let type_id = TypeID::try_from(rdr.read_u8()?)?;
        let variable_struct = VariableStruct::try_from(rdr.read_u8()?).unwrap();
        let cause = CauseOfTransmission::try_from(rdr.read_u8()?).unwrap();
        let common_addr = rdr.read_u16::<byteorder::BigEndian>()?;
        let mut bytes = bytes;
        Ok(Asdu {
            identifier: Identifier {
                type_id,
                variable_struct,
                cause,
                common_addr,
            },
            raw: bytes.split_off(IDENTIFIER_SIZE),
        })
    }
}

impl TryInto<Bytes> for Asdu {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Bytes, Self::Error> {
        let mut buf = BytesMut::with_capacity(ASDU_SIZE_MAX);
        buf.put_u8(self.identifier.type_id as u8);
        buf.put_u8(self.identifier.variable_struct.raw());
        buf.put_u8(self.identifier.cause.raw());
        buf.put_u16(self.identifier.common_addr);
        buf.extend(self.raw);

        Ok(buf.freeze())
    }
}

/// 通过raw解析成Obj
impl Asdu {
    // CP56Time2a , CP24Time2a, CP16Time2a
    // |         Milliseconds(D7--D0)        | Milliseconds = 0-59999
    // |         Milliseconds(D15--D8)       |
    // | IV(D7)   RES1(D6)  Minutes(D5--D0)  | Minutes = 1-59, IV = invalid,0 = valid, 1 = invalid
    // | SU(D7)   RES2(D6-D5)  Hours(D4--D0) | Hours = 0-23, SU = summer Time,0 = standard time, 1 = summer time,
    // | DayOfWeek(D7--D5) DayOfMonth(D4--D0)| DayOfMonth = 1-31  DayOfWeek = 1-7
    // | RES3(D7--D4)        Months(D3--D0)  | Months = 1-12
    // | RES4(D7)            Year(D6--D0)    | Year = 0-99

    // decode info object byte to CP56Time2a
    pub fn decode_cp56time2a(rdr: &mut Cursor<&Bytes>) -> Result<Option<DateTime<Utc>>> {
        if rdr.remaining() < 7 {
            return Ok(None);
        }
        let millisecond = rdr.read_u16::<LittleEndian>()?;
        let msec = millisecond % 1000;
        let sec = (millisecond / 1000) as u32;
        let min = rdr.read_u8()?;
        let invalid = min & 0x80;
        let min = (min & 0x3f) as u32;
        let hour = (rdr.read_u8()? & 0x1f) as u32;
        let day = (rdr.read_u8()? & 0x1f) as u32;
        let month = (rdr.read_u8()? & 0x0f) as u32;
        let year = 2000 + (rdr.read_u8()? & 0x7f) as i32;

        if invalid != 0 {
            Ok(None)
        } else {
            Ok(Some(
                Utc.with_ymd_and_hms(year, month, day, hour, min, sec)
                    .unwrap(),
            ))
        }
    }

    // Decodecode info object byte to CP24Time2a
    pub fn decode_cp24time2a(rdr: &mut Cursor<&Bytes>) -> Result<Option<DateTime<Utc>>> {
        if rdr.remaining() < 3 {
            return Ok(None);
        }
        let millisecond = rdr.read_u16::<LittleEndian>()?;
        let msec = millisecond % 1000;
        let sec = (millisecond / 1000) as u32;
        let min = rdr.read_u8()?;
        let invalid = min & 0x80;
        let min = (min & 0x3f) as u32;

        let now_utc = Utc::now();
        let hour = now_utc.hour();
        let day = now_utc.day();
        let month = now_utc.month();
        let year = now_utc.year();
        if invalid != 0 {
            Ok(None)
        } else {
            Ok(Some(
                Utc.with_ymd_and_hms(year, month, day, hour, min, sec)
                    .unwrap(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_and_encode_asdu() -> Result<()> {
        let bytes =
            Bytes::from_static(&[0x01, 0x01, 0x06, 0x00, 0x80, 0x60, 0x00, 0x01, 0x02, 0x03]);
        let mut asdu: Asdu = bytes.clone().try_into()?;
        assert!(asdu.identifier.type_id == TypeID::M_SP_NA_1);
        assert_eq!(asdu.identifier.variable_struct.number().get().value(), 0x01);
        assert_eq!(asdu.identifier.cause.cause().get(), Cause::Activation);
        assert_eq!(asdu.identifier.common_addr, 0x0080);
        assert_eq!(
            asdu.raw,
            Bytes::from_static(&[0x60, 0x00, 0x01, 0x02, 0x03])
        );

        let raw: Bytes = asdu.try_into().unwrap();
        assert_eq!(bytes, raw);
        Ok(())
    }
}
