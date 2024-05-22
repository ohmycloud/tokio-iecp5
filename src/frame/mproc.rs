use std::io::Cursor;

use anyhow::Result;
use bit_struct::*;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, Utc};

use super::asdu::{Asdu, ObjectAddr, TypeID};

// 在监视方向过程信息的应用服务数据单元

#[derive(Debug, PartialEq)]
pub struct SinglePointInfo {
    pub ioa: ObjectAddr,
    pub siq: ObjectSIQ,
    pub time: Option<DateTime<Utc>>,
}

impl SinglePointInfo {
    pub fn new(ioa: ObjectAddr, siq: ObjectSIQ, time: Option<DateTime<Utc>>) -> SinglePointInfo {
        SinglePointInfo { ioa, siq, time }
    }
}

#[derive(Debug)]
pub struct DoublePointInfo {
    pub ioa: ObjectAddr,
    pub diq: ObjectDIQ,
    pub time: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct MeasuredValueNormalInfo {
    pub ioa: ObjectAddr,
    pub nva: i16,
    pub qds: Option<ObjectQDS>,
    pub time: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct MeasuredValueScaledInfo {
    pub ioa: ObjectAddr,
    pub sva: i16,
    pub qds: ObjectQDS,
    pub time: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct MeasuredValueFloatInfo {
    pub ioa: ObjectAddr,
    pub r: f32,
    pub qds: ObjectQDS,
    pub time: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct BinaryCounterReadingInfo {
    pub ioa: ObjectAddr,
    pub bcr: ObjectBCR,
    pub time: Option<DateTime<Utc>>,
}

// 单点遥信对象
bit_struct! {
    pub struct ObjectSIQ(u8) {
        invalid: u1,  // 数据无效标志
        nt: u1,       // 非最新状态
        sb: u1,       // 被取代/人工设置
        bl: u1,       // 封锁 blocking
        res: u3,      // 保留, 置0
        spi: u1,      // 遥信状态
    }

}

// 双点遥信对象
bit_struct! {
    pub struct ObjectDIQ(u8) {
        invalid: u1,    // 数据无效标志
        nt: u1,         // 非最新状态
        sb: u1,         // 被取代/人工设置
        bl: u1,         // 封锁 blocking
        res: u2,        // 保留, 置0
        spi: u2,        // 遥信状态
    }
}

// 信息对象品质描述词
bit_struct! {
    pub struct ObjectQDS(u8) {
        invalid: u1,     // 数据无效标志
        nt: u1,         // 非最新状态
        sb: u1,         // 被取代/人工设置
        bl: u1,         // 封锁 blocking
        res: u3,        // 保留，置0
        ov: u1,         // 溢出 overflow

    }

}

// 带变位检索的遥信对象
bit_struct! {
    pub struct ObjectSCD(u40) {
        res: u8,     // 保留, 置0
        vflag: u16,  // 连续16个遥信的变位标志
        spi: u16,    // 连续16个遥信状态
    }
}

// 二进制计数器遥测对象
#[derive(Debug)]
pub struct ObjectBCR {
    pub invalid: bool, // 数据无效标志
    pub ca: bool,      // 上次读数后计数量有调整
    pub cy: bool,      // 进位
    pub seq: u8,       // 顺序号 占五个bit
    pub value: i32,
}

impl Asdu {
    // [M_SP_NA_1], [M_SP_TA_1] or [M_SP_TB_1] 获取单点信息信息体集合
    pub fn get_single_point(&mut self) -> Result<Vec<SinglePointInfo>> {
        let mut rdr = Cursor::new(&self.raw);
        let info_num = self.identifier.variable_struct.number().get().value() as usize;
        let is_seq = self.identifier.variable_struct.is_sequence().get().value() != 0;
        let mut info = Vec::with_capacity(info_num);
        let mut once = false;
        let mut ioa = ObjectAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = ObjectAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
            } else {
                let addr = ioa.addr().get() + 1;
                ioa.addr().set(addr);
            }
            let siq = ObjectSIQ::try_from(rdr.read_u8()?).unwrap();
            let mut time = None;
            match self.identifier.type_id {
                TypeID::M_SP_NA_1 => (),
                TypeID::M_SP_TA_1 => time = Self::decode_cp24time2a(&mut rdr)?,
                TypeID::M_SP_TB_1 => time = Self::decode_cp56time2a(&mut rdr)?,
                _ => panic!("ErrTypeIDNotMatch"),
            }
            info.push(SinglePointInfo { ioa, siq, time });
        }
        Ok(info)
    }

    // [M_DP_NA_1], [M_DP_TA_1] or [M_DP_TB_1] 获得双点信息体集合
    fn get_double_point(&mut self) -> Result<Vec<DoublePointInfo>> {
        let mut rdr = Cursor::new(&self.raw);
        let info_num = self.identifier.variable_struct.number().get().value() as usize;
        let is_seq = self.identifier.variable_struct.is_sequence().get().value() != 0;
        let mut info = Vec::with_capacity(info_num);
        let mut once = false;
        let mut ioa = ObjectAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = ObjectAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
            } else {
                let addr = ioa.addr().get() + 1;
                ioa.addr().set(addr);
            }
            let diq = ObjectDIQ::try_from(rdr.read_u8()?).unwrap();
            let mut time = None;
            match self.identifier.type_id {
                TypeID::M_DP_NA_1 => (),
                TypeID::M_DP_TA_1 => time = Self::decode_cp24time2a(&mut rdr)?,
                TypeID::M_DP_TB_1 => time = Self::decode_cp56time2a(&mut rdr)?,
                _ => panic!("ErrTypeIDNotMatch"),
            }
            info.push(DoublePointInfo { ioa, diq, time });
        }
        Ok(info)
    }

    // [M_ME_NA_1], [M_ME_TA_1],[ M_ME_TD_1] or [M_ME_ND_1] 获得测量值,规一化值信息体集合
    fn get_measured_value_normal(&mut self) -> Result<Vec<MeasuredValueNormalInfo>> {
        let mut rdr = Cursor::new(&self.raw);
        let info_num = self.identifier.variable_struct.number().get().value() as usize;
        let is_seq = self.identifier.variable_struct.is_sequence().get().value() != 0;
        let mut info = Vec::with_capacity(info_num);
        let mut once = false;
        let mut ioa = ObjectAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = ObjectAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
            } else {
                let addr = ioa.addr().get() + 1;
                ioa.addr().set(addr);
            }
            let nva = rdr.read_i16::<LittleEndian>()?;
            let mut qds = None;
            let mut time = None;
            match self.identifier.type_id {
                TypeID::M_ME_NA_1 => {
                    qds = Some(ObjectQDS::try_from(rdr.read_u8()?).unwrap());
                }
                TypeID::M_ME_TA_1 => {
                    qds = Some(ObjectQDS::try_from(rdr.read_u8()?).unwrap());
                    time = Self::decode_cp24time2a(&mut rdr)?
                }
                TypeID::M_ME_TD_1 => {
                    qds = Some(ObjectQDS::try_from(rdr.read_u8()?).unwrap());
                    time = Self::decode_cp56time2a(&mut rdr)?
                }
                TypeID::M_ME_ND_1 => (), // 不带品质
                _ => panic!("ErrTypeIDNotMatch"),
            }
            info.push(MeasuredValueNormalInfo {
                ioa,
                nva,
                qds,
                time,
            });
        }
        Ok(info)
    }

    // [M_ME_NB_1], [M_ME_TB_1] or [M_ME_TE_1] 获得测量值，标度化值信息体集合
    fn get_measured_value_scaled(&mut self) -> Result<Vec<MeasuredValueScaledInfo>> {
        let mut rdr = Cursor::new(&self.raw);
        let info_num = self.identifier.variable_struct.number().get().value() as usize;
        let is_seq = self.identifier.variable_struct.is_sequence().get().value() != 0;
        let mut info = Vec::with_capacity(info_num);
        let mut once = false;
        let mut ioa = ObjectAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = ObjectAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
            } else {
                let addr = ioa.addr().get() + 1;
                ioa.addr().set(addr);
            }
            let sva = rdr.read_i16::<LittleEndian>()?;
            let qds = ObjectQDS::try_from(rdr.read_u8()?).unwrap();
            let mut time = None;
            match self.identifier.type_id {
                TypeID::M_ME_NB_1 => (),
                TypeID::M_ME_TB_1 => time = Self::decode_cp24time2a(&mut rdr)?,
                TypeID::M_ME_TE_1 => time = Self::decode_cp56time2a(&mut rdr)?,
                _ => panic!("ErrTypeIDNotMatch"),
            }
            info.push(MeasuredValueScaledInfo {
                ioa,
                sva,
                qds,
                time,
            });
        }
        Ok(info)
    }

    // [M_ME_NC_1], [M_ME_TC_1] or [M_ME_TF_1]. 获得测量值,短浮点数信息体集合
    fn get_measured_value_float(&mut self) -> Result<Vec<MeasuredValueFloatInfo>> {
        let mut rdr = Cursor::new(&self.raw);
        let info_num = self.identifier.variable_struct.number().get().value() as usize;
        let is_seq = self.identifier.variable_struct.is_sequence().get().value() != 0;
        let mut info = Vec::with_capacity(info_num);
        let mut once = false;
        let mut ioa = ObjectAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = ObjectAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
            } else {
                let addr = ioa.addr().get() + 1;
                ioa.addr().set(addr);
            }
            let r = rdr.read_f32::<LittleEndian>()?;
            let qds = ObjectQDS::try_from(rdr.read_u8()?).unwrap();
            let mut time = None;
            match self.identifier.type_id {
                TypeID::M_ME_NC_1 => (),
                TypeID::M_ME_TC_1 => time = Self::decode_cp24time2a(&mut rdr)?,
                TypeID::M_ME_TF_1 => time = Self::decode_cp56time2a(&mut rdr)?,
                _ => panic!("ErrTypeIDNotMatch"),
            }
            info.push(MeasuredValueFloatInfo { ioa, r, qds, time });
        }
        Ok(info)
    }

    // [M_IT_NA_1], [M_IT_TA_1] or [M_IT_TB_1]. 获得累计量信息体集合
    fn get_integrated_totals(&mut self) -> Result<Vec<BinaryCounterReadingInfo>> {
        let mut rdr = Cursor::new(&self.raw);
        let info_num = self.identifier.variable_struct.number().get().value() as usize;
        let is_seq = self.identifier.variable_struct.is_sequence().get().value() != 0;
        let mut info = Vec::with_capacity(info_num);
        let mut once = false;
        let mut ioa = ObjectAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = ObjectAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
            } else {
                let addr = ioa.addr().get() + 1;
                ioa.addr().set(addr);
            }
            let value = rdr.read_i32::<LittleEndian>()?;
            let b = rdr.read_u8()?;
            let bcr = ObjectBCR {
                invalid: b & 0x80 == 0x80,
                ca: b & 0x40 == 0x40,
                cy: b & 0x20 == 0x20,
                seq: b & 0x1f,
                value,
            };
            let mut time = None;
            match self.identifier.type_id {
                TypeID::M_IT_NA_1 => (),
                TypeID::M_IT_TA_1 => time = Self::decode_cp24time2a(&mut rdr)?,
                TypeID::M_IT_TB_1 => time = Self::decode_cp56time2a(&mut rdr)?,
                _ => panic!("ErrTypeIDNotMatch"),
            }
            info.push(BinaryCounterReadingInfo { ioa, bcr, time });
        }
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use chrono::{Datelike, TimeZone, Timelike};

    use crate::frame::asdu::{CauseOfTransmission, Identifier, VariableStruct};

    use super::*;

    // let tm0_cp56time2a = Utc.with_ymd_and_hms(2019, 6, 5, 4, 3, 0);
    // let tm0_cp24time2a = Utc.with_ymd_and_hms(2019, 6, 5, 0, 0, 0);
    // let tm0_cp56time2a_bytes = [0x01, 0x02, 0x03, 0x04, 0x65, 0x06, 0x13];
    // let tm0_cp24time2a_bytes = [0x01, 0x02, 0x03];

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
                    cause: CauseOfTransmission::try_from(0).unwrap(),
                    common_addr: 0,
                },
                raw: Bytes::from_static(&[0x01, 0x00, 0x00, 0x11, 0x02, 0x00, 0x00, 0x10]),
            },
            want: vec![
                SinglePointInfo::new(
                    ObjectAddr::try_from(u24!(0x01)).unwrap(),
                    ObjectSIQ::try_from(0x11).unwrap(),
                    None,
                ),
                SinglePointInfo::new(
                    ObjectAddr::try_from(u24!(0x02)).unwrap(),
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
                    cause: CauseOfTransmission::try_from(0).unwrap(),
                    common_addr: 0,
                },
                raw: Bytes::from_static(&[0x01, 0x00, 0x00, 0x11, 0x10]),
            },
            want: vec![
                SinglePointInfo::new(
                    ObjectAddr::try_from(u24!(0x01)).unwrap(),
                    ObjectSIQ::try_from(0x11).unwrap(),
                    None,
                ),
                SinglePointInfo::new(
                    ObjectAddr::try_from(u24!(0x02)).unwrap(),
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
                    cause: CauseOfTransmission::try_from(0).unwrap(),
                    common_addr: 0,
                },
                raw: Bytes::from_static(&[
                    0x01, 0x00, 0x00, 0x11, 0x01, 0x02, 0x03, 0x04, 0x65, 0x06, 0x13, 0x02, 0x00,
                    0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x65, 0x06, 0x13,
                ]),
            },
            want: vec![
                SinglePointInfo::new(
                    ObjectAddr::try_from(u24!(0x01)).unwrap(),
                    ObjectSIQ::try_from(0x11).unwrap(),
                    Some(Utc.with_ymd_and_hms(2019, 6, 5, 4, 3, 0).unwrap()),
                ),
                SinglePointInfo::new(
                    ObjectAddr::try_from(u24!(0x02)).unwrap(),
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
                    cause: CauseOfTransmission::try_from(0).unwrap(),
                    common_addr: 0,
                },
                raw: Bytes::from_static(&[
                    0x01, 0x00, 0x00, 0x11, 0x01, 0x02, 0x03, 0x02, 0x00, 0x00, 0x10, 0x01, 0x02,
                    0x03,
                ]),
            },
            want: vec![
                SinglePointInfo::new(
                    ObjectAddr::try_from(u24!(0x01)).unwrap(),
                    ObjectSIQ::try_from(0x11).unwrap(),
                    Some(Utc.with_ymd_and_hms(year, month, day, hour, 3, 0).unwrap()),
                ),
                SinglePointInfo::new(
                    ObjectAddr::try_from(u24!(0x02)).unwrap(),
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

    // #[test]
    // fn decode_measured_value_float() -> Result<()> {
    //     struct Test {
    //         name: String,
    //         asdu: Asdu,
    //         want: Vec<MeasuredValueFloatInfo>,
    //     }
    //     let mut tests = Vec::new();
    //     tests.push(Test {
    //         name: "华能虚拟电厂遥测".into(),
    //         asdu: Asdu {
    //             identifier: Identifier {
    //                 type_id: TypeID::
    //             }
    //         }
    //     })
    //     Ok(())
    // }
}
