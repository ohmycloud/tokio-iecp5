use core::panic;
use std::io::Cursor;

use anyhow::Result;
use bit_struct::*;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, Utc};

use crate::frame::asdu::TypeID;

use super::asdu::{Asdu, ObjectAddr};

// 在控制方向过程信息的应用服务数据单元

// 单命令 信息体
#[derive(Debug, PartialEq)]
pub struct SingleCommandInfo {
    pub ioa: ObjectAddr,
    pub sco: ObjectSCO,
    pub time: Option<DateTime<Utc>>,
}

// 双命令 信息体
#[derive(Debug, PartialEq)]
pub struct DoubleCommandInfo {
    pub ioa: ObjectAddr,
    pub dco: ObjectDCO,
    pub time: Option<DateTime<Utc>>,
}

// 设置命令，规一化值 信息体
#[derive(Debug, PartialEq)]
pub struct SetpointCommandNormalInfo {
    pub ioa: ObjectAddr,
    pub nva: i16,
    pub qos: ObjectQOS,
    pub time: Option<DateTime<Utc>>,
}

// 设定命令,标度化值 信息体
#[derive(Debug, PartialEq)]
pub struct SetpointCommandScaledInfo {
    pub ioa: ObjectAddr,
    pub sva: i16,
    pub qos: ObjectQOS,
    pub time: Option<DateTime<Utc>>,
}

// 设定命令, 短浮点数 信息体
pub struct SetpointCommandFloatInfo {
    pub ioa: ObjectAddr,
    pub r: f32,
    pub qos: ObjectQOS,
    pub time: Option<DateTime<Utc>>,
}

// 单命令 遥控信息
bit_struct! {
    pub struct ObjectSCO(u8) {
        scs: u1,    // 控制状态
        res: u1,    // 预留: 置0
        qu: u5,     // 输出方式: 0:被控确定, 1:短脉冲, 2:长脉冲, 3:持续脉冲
        se: u1,     // 选择标志: 0:执行, 1:选择
    }
}

// 双命令 遥控信息
bit_struct! {
    pub struct ObjectDCO(u8) {
        /// 控制状态
        dcs: u2,
        /// 输出方式: 0:被控确定, 1:短脉冲, 2:长脉冲, 3:持续脉冲
        qu: u5,
        /// 选择标志: 0:执行, 1:选择
        se: u1,
    }
}

// 命令限定词
bit_struct! {
    pub struct ObjectQOC(u8) {
        /// 预留：置0
        res: u2,
        /// 输出方式: 0:被控确定, 1:短脉冲, 2:长脉冲, 3:持续脉冲
        qu: u5,
        /// 选择标志: 0:执行, 1:选择
        se: u1,
    }
}

// 设定命令限定词
bit_struct! {
    pub struct ObjectQOS(u8) {
        /// 0: 默认 1-63: 预留为标准定义 64-127:特殊使用
        ql: u7,
        /// 选择标志: 0:执行, 1:选择
        se: u1,
    }
}

impl Asdu {
    // [C_SC_NA_1] or [C_SC_TA_1] 获取单命令信息体
    pub fn get_single_cmd(&mut self) -> Result<SingleCommandInfo> {
        let mut rdr = Cursor::new(&self.raw);
        let ioa = ObjectAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap();
        let sco = ObjectSCO::try_from(rdr.read_u8()?).unwrap();

        let mut time = None;
        match self.identifier.type_id {
            TypeID::C_SC_NA_1 => (),
            TypeID::C_SC_TA_1 => time = Self::decode_cp56time2a(&mut rdr)?,
            _ => panic!("ErrTypeIDNotMatch"),
        }
        Ok(SingleCommandInfo { ioa, sco, time })
    }

    // [C_DC_NA_1] or [C_DC_TA_1] 获取双命令信息体
    pub fn get_double_cmd(&mut self) -> Result<DoubleCommandInfo> {
        let mut rdr = Cursor::new(&self.raw);
        let ioa = ObjectAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap();
        let dco = ObjectDCO::try_from(rdr.read_u8()?).unwrap();
        let mut time = None;
        match self.identifier.type_id {
            TypeID::C_DC_NA_1 => (),
            TypeID::C_DC_TA_1 => time = Self::decode_cp56time2a(&mut rdr)?,
            _ => panic!("ErrTypeIDNotMatch"),
        }
        Ok(DoubleCommandInfo { ioa, dco, time })
    }

    // GetSetpointNormalCmd [C_SE_NA_1] or [C_SE_TA_1] 获取设定命令,规一化值信息体
    pub fn get_setpoint_normal_cmd(&mut self) -> Result<SetpointCommandNormalInfo> {
        let mut rdr = Cursor::new(&self.raw);
        let ioa = ObjectAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap();
        let nva = rdr.read_i16::<LittleEndian>()?;
        let qos = ObjectQOS::try_from(rdr.read_u8()?).unwrap();

        let mut time = None;
        match self.identifier.type_id {
            TypeID::C_SE_NA_1 => (),
            TypeID::C_SE_TA_1 => time = Self::decode_cp56time2a(&mut rdr)?,
            _ => panic!("ErrTypeIDNotMatch"),
        }

        Ok(SetpointCommandNormalInfo {
            ioa,
            nva,
            qos,
            time,
        })
    }

    // [C_SE_NB_1] or [C_SE_TB_1] 获取设定命令,标度化值信息体
    pub fn get_setpoint_scaled_cmd(&mut self) -> Result<SetpointCommandScaledInfo> {
        let mut rdr = Cursor::new(&self.raw);
        let ioa = ObjectAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap();
        let sva = rdr.read_i16::<LittleEndian>()?;
        let qos = ObjectQOS::try_from(rdr.read_u8()?).unwrap();

        let mut time = None;
        match self.identifier.type_id {
            TypeID::C_SE_NB_1 => (),
            TypeID::C_SE_TB_1 => time = Self::decode_cp56time2a(&mut rdr)?,
            _ => panic!("ErrTypeIDNotMatch"),
        }

        Ok(SetpointCommandScaledInfo {
            ioa,
            sva,
            qos,
            time,
        })
    }

    // [C_SE_NC_1] or [C_SE_TC_1] 获取设定命令，短浮点数信息体
    pub fn get_setpoint_float_cmd(&mut self) -> Result<SetpointCommandFloatInfo> {
        let mut rdr = Cursor::new(&self.raw);
        let ioa = ObjectAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap();
        let r = rdr.read_f32::<LittleEndian>()?;
        let qos = ObjectQOS::try_from(rdr.read_u8()?).unwrap();

        let mut time = None;
        match self.identifier.type_id {
            TypeID::C_SE_NC_1 => (),
            TypeID::C_SE_TC_1 => time = Self::decode_cp56time2a(&mut rdr)?,
            _ => panic!("ErrTypeIDNotMatch"),
        }

        Ok(SetpointCommandFloatInfo { ioa, r, qos, time })
    }
}
