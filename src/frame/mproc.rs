use std::io::Cursor;

use anyhow::Result;
use bit_struct::*;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bytes::Bytes;
use chrono::{DateTime, Utc};

use crate::{error::Error, interface::Connect};

use super::{
    asdu::{
        Asdu, Cause, CauseOfTransmission, CommonAddr, Identifier, InfoObjAddr, TypeID,
        VariableStruct,
    },
    time::{cp24time2a, cp56time2a, decode_cp24time2a, decode_cp56time2a},
};

// 在监视方向过程信息的应用服务数据单元

#[derive(Debug, PartialEq)]
pub struct SinglePointInfo {
    pub ioa: InfoObjAddr,
    pub siq: ObjectSIQ,
    pub time: Option<DateTime<Utc>>,
}

impl SinglePointInfo {
    pub fn new(ioa: InfoObjAddr, siq: ObjectSIQ, time: Option<DateTime<Utc>>) -> SinglePointInfo {
        SinglePointInfo { ioa, siq, time }
    }
}

#[derive(Debug)]
pub struct DoublePointInfo {
    pub ioa: InfoObjAddr,
    pub diq: ObjectDIQ,
    pub time: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct MeasuredValueNormalInfo {
    pub ioa: InfoObjAddr,
    pub nva: i16,
    pub qds: Option<ObjectQDS>,
    pub time: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct MeasuredValueScaledInfo {
    pub ioa: InfoObjAddr,
    pub sva: i16,
    pub qds: ObjectQDS,
    pub time: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct MeasuredValueFloatInfo {
    pub ioa: InfoObjAddr,
    pub r: f32,
    pub qds: ObjectQDS,
    pub time: Option<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct BinaryCounterReadingInfo {
    pub ioa: InfoObjAddr,
    pub bcr: ObjectBCR,
    pub time: Option<DateTime<Utc>>,
}

// 单点遥信对象
bit_struct! {
    pub struct ObjectSIQ(u8) {
        invalid: bool,  // 数据无效标志
        nt: bool,       // 非最新状态
        sb: bool,       // 被取代/人工设置
        bl: bool,       // 封锁 blocking
        res: u3,      // 保留, 置0
        spi: bool,      // 遥信状态
    }

}

// 双点遥信对象
bit_struct! {
    pub struct ObjectDIQ(u8) {
        invalid: bool,    // 数据无效标志
        nt: bool,         // 非最新状态
        sb: bool,         // 被取代/人工设置
        bl: bool,         // 封锁 blocking
        res: u2,        // 保留, 置0
        spi: u2,        // 遥信状态
    }
}

// 信息对象品质描述词
bit_struct! {
    pub struct ObjectQDS(u8) {
        invalid: bool,     // 数据无效标志
        nt: bool,         // 非最新状态
        sb: bool,         // 被取代/人工设置
        bl: bool,         // 封锁 blocking
        res: u3,        // 保留，置0
        ov: bool,         // 溢出 overflow

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

//  TODO: checkValid check common parameter of request is valid
fn check_vaild(
    _: &impl Connect,
    type_id: TypeID,
    is_sequence: bool,
    infos_len: usize,
) -> Result<(), Error> {
    Ok(())
}

// single sends a type identification [M_SP_NA_1], [M_SP_TA_1] or [M_SP_TB_1].单点信息
// [M_SP_NA_1] See companion standard 101,subclass 7.3.1.1
// [M_SP_TA_1] See companion standard 101,subclass 7.3.1.2
// [M_SP_TB_1] See companion standard 101,subclass 7.3.1.22
async fn single_inner(
    c: &impl Connect,
    type_id: TypeID,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<SinglePointInfo>,
) -> Result<(), Error> {
    check_vaild(c, type_id, is_sequence, infos.len())?;

    let variable_struct = VariableStruct::new(
        u1::new(is_sequence as u8).unwrap(),
        u7::new(infos.len() as u8).unwrap(),
    );

    let mut once = false;
    let mut buf = vec![];
    for info in infos {
        if !is_sequence || !once {
            once = true;
            buf.write_u24::<LittleEndian>(info.ioa.raw().value())?;
        }

        buf.write_u8(info.siq.raw())?;
        match type_id {
            TypeID::M_SP_NA_1 => (),
            TypeID::M_SP_TA_1 => {
                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp24time2a(time));
                } else {
                    buf.extend_from_slice(&cp24time2a(Utc::now()));
                }
            }
            TypeID::M_SP_TB_1 => {
                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp56time2a(time))
                } else {
                    buf.extend_from_slice(&cp56time2a(Utc::now()))
                }
            }
            _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
        }
    }

    let asdu = Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    };

    c.send(asdu).await
}

// Single sends a type identification [M_SP_NA_1].不带时标单点信息
// [M_SP_NA_1] See companion standard 101,subclass 7.3.1.1
// 传送原因(cot)用于
// 监视方向：
// <2> := 背景扫描
// <3> := 突发(自发)
// <5> := 被请求
// <11> := 远方命令引起的返送信息
// <12> := 当地命令引起的返送信息
// <20> := 响应站召唤
// <21> := 响应第1组召唤
// 至
// <36> := 响应第16组召唤
pub async fn single(
    c: &impl Connect,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<SinglePointInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Background
        || cause == Cause::Spontaneous
        || cause == Cause::Request
        || cause == Cause::ReturnInfoRemote
        || cause == Cause::ReturnInfoLocal
        || (cause >= Cause::InterrogatedByStation && cause <= Cause::InterrogatedByGroup16))
    {
        return Err(Error::ErrCmdCause(cot));
    }

    single_inner(c, TypeID::M_SP_NA_1, is_sequence, cot, ca, infos).await
}

// SingleCP24Time2a sends a type identification [M_SP_TA_1],带时标CP24Time2a的单点信息，只有(SQ = 0)单个信息元素集合
// [M_SP_TA_1] See companion standard 101,subclass 7.3.1.2
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <5> := 被请求
// <11> := 远方命令引起的返送信息
// <12> := 当地命令引起的返送信息
pub async fn single_cp24time2a(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<SinglePointInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous
        || cause == Cause::Request
        || cause == Cause::ReturnInfoRemote
        || cause == Cause::ReturnInfoLocal)
    {
        return Err(Error::ErrCmdCause(cot));
    }
    single_inner(c, TypeID::M_SP_TA_1, false, cot, ca, infos).await
}

// SingleCP56Time2a sends a type identification [M_SP_TB_1].带时标CP56Time2a的单点信息,只有(SQ = 0)单个信息元素集合
// [M_SP_TB_1] See companion standard 101,subclass 7.3.1.22
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <5> := 被请求
// <11> := 远方命令引起的返送信息
// <12> := 当地命令引起的返送信息
pub async fn single_cp56time2a(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<SinglePointInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous
        || cause == Cause::Request
        || cause == Cause::ReturnInfoRemote
        || cause == Cause::ReturnInfoLocal)
    {
        return Err(Error::ErrCmdCause(cot));
    }
    single_inner(c, TypeID::M_SP_TB_1, false, cot, ca, infos).await
}

// double sends a type identification [M_DP_NA_1], [M_DP_TA_1] or [M_DP_TB_1].双点信息
// [M_DP_NA_1] See companion standard 101,subclass 7.3.1.3
// [M_DP_TA_1] See companion standard 101,subclass 7.3.1.4
// [M_DP_TB_1] See companion standard 101,subclass 7.3.1.23
async fn double_inner(
    c: &impl Connect,
    type_id: TypeID,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<DoublePointInfo>,
) -> Result<(), Error> {
    check_vaild(c, type_id, is_sequence, infos.len())?;

    let variable_struct = VariableStruct::new(
        u1::new(is_sequence as u8).unwrap(),
        u7::new(infos.len() as u8).unwrap(),
    );

    let mut once = false;
    let mut buf = vec![];
    for info in infos {
        if !is_sequence || !once {
            once = true;
            buf.write_u24::<LittleEndian>(info.ioa.raw().value())?;
        }

        buf.write_u8(info.diq.raw())?;

        match type_id {
            TypeID::M_DP_NA_1 => (),
            TypeID::M_DP_TA_1 => {
                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp24time2a(time));
                } else {
                    buf.extend_from_slice(&cp24time2a(Utc::now()));
                }
            }
            TypeID::M_DP_TB_1 => {
                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp56time2a(time));
                } else {
                    buf.extend_from_slice(&cp56time2a(Utc::now()));
                }
            }
            _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
        }
    }

    let asdu = Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    };

    c.send(asdu).await
}

// Double sends a type identification [M_DP_NA_1].双点信息
// [M_DP_NA_1] See companion standard 101,subclass 7.3.1.3
// 传送原因(cot)用于
// 监视方向：
// <2> := 背景扫描
// <3> := 突发(自发)
// <5> := 被请求
// <11> := 远方命令引起的返送信息
// <12> := 当地命令引起的返送信息
// <20> := 响应站召唤
// <21> := 响应第1组召唤
// 至
// <36> := 响应第16组召唤
pub async fn double(
    c: &impl Connect,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<DoublePointInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Background
        || cause == Cause::Spontaneous
        || cause == Cause::Request
        || cause == Cause::ReturnInfoRemote
        || cause == Cause::ReturnInfoLocal
        || (cause >= Cause::InterrogatedByStation && cause <= Cause::InterrogatedByGroup16))
    {
        return Err(Error::ErrCmdCause(cot));
    }
    double_inner(c, TypeID::M_DP_NA_1, is_sequence, cot, ca, infos).await
}

// DoubleCP24Time2a sends a type identification [M_DP_TA_1] .带CP24Time2a双点信息,只有(SQ = 0)单个信息元素集合
// [M_DP_TA_1] See companion standard 101,subclass 7.3.1.4
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <5> := 被请求
// <11> := 远方命令引起的返送信息
// <12> := 当地命令引起的返送信息
pub async fn double_cp24time2a(
    c: &impl Connect,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<DoublePointInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous
        || cause == Cause::Request
        || cause == Cause::ReturnInfoRemote
        || cause == Cause::ReturnInfoLocal)
    {
        return Err(Error::ErrCmdCause(cot));
    }

    double_inner(c, TypeID::M_DP_TA_1, is_sequence, cot, ca, infos).await
}

// DoubleCP56Time2a sends a type identification [M_DP_TB_1].带CP56Time2a的双点信息,只有(SQ = 0)单个信息元素集合
// [M_DP_TB_1] See companion standard 101,subclass 7.3.1.23
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <5> := 被请求
// <11> := 远方命令引起的返送信息
// <12> := 当地命令引起的返送信息
pub async fn double_cp56time2a(
    c: &impl Connect,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<DoublePointInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous
        || cause == Cause::Request
        || cause == Cause::ReturnInfoRemote
        || cause == Cause::ReturnInfoLocal)
    {
        return Err(Error::ErrCmdCause(cot));
    }

    double_inner(c, TypeID::M_DP_TB_1, is_sequence, cot, ca, infos).await
}

// TODO:
// step sends a type identification [M_ST_NA_1], [M_ST_TA_1] or [M_ST_TB_1].步位置信息
// [M_ST_NA_1] See companion standard 101, subclass 7.3.1.5
// [M_ST_TA_1] See companion standard 101, subclass 7.3.1.6
// [M_ST_TB_1] See companion standard 101, subclass 7.3.1.24
// async fn setp_inner(c: &impl Connect, type_id: TypeID, is_sequence: bool, cot: CauseOfTransmission, ca: CommonAddr, infos: Vec<>);

// measuredValueNormal sends a type identification [M_ME_NA_1], [M_ME_TA_1],[ M_ME_TD_1] or [M_ME_ND_1].测量值,规一化值
// [M_ME_NA_1] See companion standard 101, subclass 7.3.1.9
// [M_ME_TA_1] See companion standard 101, subclass 7.3.1.10
// [M_ME_TD_1] See companion standard 101, subclass 7.3.1.26
// [M_ME_ND_1] See companion standard 101, subclass 7.3.1.21， The quality descriptor must default to asdu.GOOD
async fn measured_value_normal_inner(
    c: &impl Connect,
    type_id: TypeID,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueNormalInfo>,
) -> Result<(), Error> {
    check_vaild(c, type_id, is_sequence, infos.len())?;
    let variable_struct = VariableStruct::new(
        u1::new(is_sequence as u8).unwrap(),
        u7::new(infos.len() as u8).unwrap(),
    );
    let mut once = false;
    let mut buf = vec![];
    for info in infos {
        if !is_sequence || !once {
            once = true;
            buf.write_u24::<LittleEndian>(info.ioa.raw().value())?;
        }
        buf.write_i16::<LittleEndian>(info.nva)?;
        match type_id {
            TypeID::M_ME_NA_1 => {
                if let Some(qds) = info.qds {
                    buf.write_u8(qds.raw())?;
                } else {
                    buf.write_u8(ObjectQDS::of_defaults().raw())?;
                }
            }
            TypeID::M_ME_TA_1 => {
                if let Some(qds) = info.qds {
                    buf.write_u8(qds.raw())?;
                } else {
                    buf.write_u8(ObjectQDS::of_defaults().raw())?;
                }

                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp24time2a(time));
                } else {
                    buf.extend_from_slice(&cp24time2a(Utc::now()));
                }
            }
            TypeID::M_ME_TD_1 => {
                if let Some(qds) = info.qds {
                    buf.write_u8(qds.raw())?;
                } else {
                    buf.write_u8(ObjectQDS::of_defaults().raw())?;
                }

                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp56time2a(time));
                } else {
                    buf.extend_from_slice(&cp56time2a(Utc::now()));
                }
            }
            TypeID::M_ME_ND_1 => (),
            _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
        }
    }
    let asdu = Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    };
    c.send(asdu).await
}

// MeasuredValueNormal sends a type identification [M_ME_NA_1].测量值,规一化值
// [M_ME_NA_1] See companion standard 101, subclass 7.3.1.9
// 传送原因(cot)用于
// 监视方向：
// <1> := 周期/循环
// <2> := 背景扫描
// <3> := 突发(自发)
// <5> := 被请求
// <20> := 响应站召唤
// <21> := 响应第1组召唤
// 至
// <36> := 响应第16组召唤
pub async fn measured_value_normal(
    c: &impl Connect,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueNormalInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Periodic
        || cause == Cause::Background
        || cause == Cause::Spontaneous
        || cause == Cause::Request
        || (cause >= Cause::InterrogatedByStation && cause <= Cause::InterrogatedByGroup16))
    {
        return Err(Error::ErrCmdCause(cot));
    }

    measured_value_normal_inner(c, TypeID::M_ME_NA_1, is_sequence, cot, ca, infos).await
}

// MeasuredValueNormalCP24Time2a sends a type identification [M_ME_TA_1].带时标CP24Time2a的测量值,规一化值,只有(SQ = 0)单个信息元素集合
// [M_ME_TA_1] See companion standard 101, subclass 7.3.1.10
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <5> := 被请求
pub async fn measured_value_normal_cp24time2a(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueNormalInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous || cause == Cause::Request) {
        return Err(Error::ErrCmdCause(cot));
    }

    measured_value_normal_inner(c, TypeID::M_ME_TA_1, false, cot, ca, infos).await
}

// MeasuredValueNormalCP56Time2a sends a type identification [ M_ME_TD_1] 带时标CP57Time2a的测量值,规一化值,只有(SQ = 0)单个信息元素集合
// [M_ME_TD_1] See companion standard 101, subclass 7.3.1.26
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <5> := 被请求
pub async fn measured_value_normal_cp56time2a(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueNormalInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous || cause == Cause::Request) {
        return Err(Error::ErrCmdCause(cot));
    }

    measured_value_normal_inner(c, TypeID::M_ME_TD_1, false, cot, ca, infos).await
}

// MeasuredValueNormalNoQuality sends a type identification [M_ME_ND_1].不带品质的测量值,规一化值
// [M_ME_ND_1] See companion standard 101, subclass 7.3.1.21，
// The quality descriptor must default to asdu.GOOD
// 传送原因(cot)用于
// 监视方向：
// <1> := 周期/循环
// <2> := 背景扫描
// <3> := 突发(自发)
// <5> := 被请求
// <20> := 响应站召唤
// <21> := 响应第1组召唤
// 至
// <36> := 响应第16组召唤
pub async fn measured_value_normal_noquality(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueNormalInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Periodic
        || cause == Cause::Background
        || cause == Cause::Spontaneous
        || cause == Cause::Request
        || (cause >= Cause::InterrogatedByStation && cause <= Cause::InterrogatedByGroup16))
    {
        return Err(Error::ErrCmdCause(cot));
    }

    measured_value_normal_inner(c, TypeID::M_ME_ND_1, false, cot, ca, infos).await
}

// measuredValueScaled sends a type identification [M_ME_NB_1], [M_ME_TB_1] or [M_ME_TE_1].测量值,标度化值
// [M_ME_NB_1] See companion standard 101, subclass 7.3.1.11
// [M_ME_TB_1] See companion standard 101, subclass 7.3.1.12
// [M_ME_TE_1] See companion standard 101, subclass 7.3.1.27
async fn measured_value_scaled_inner(
    c: &impl Connect,
    type_id: TypeID,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueScaledInfo>,
) -> Result<(), Error> {
    check_vaild(c, type_id, is_sequence, infos.len())?;
    let variable_struct = VariableStruct::new(
        u1::new(is_sequence as u8).unwrap(),
        u7::new(infos.len() as u8).unwrap(),
    );
    let mut once = false;
    let mut buf = vec![];
    for info in infos {
        if !is_sequence || !once {
            once = true;
            buf.write_u24::<LittleEndian>(info.ioa.raw().value())?;
        }
        buf.write_i16::<LittleEndian>(info.sva)?;
        buf.write_u8(info.qds.raw())?;
        match type_id {
            TypeID::M_ME_NB_1 => (),
            TypeID::M_ME_TB_1 => {
                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp24time2a(time));
                } else {
                    buf.extend_from_slice(&cp24time2a(Utc::now()));
                }
            }
            TypeID::M_ME_TE_1 => {
                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp56time2a(time));
                } else {
                    buf.extend_from_slice(&cp56time2a(Utc::now()));
                }
            }
            _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
        }
    }
    let asdu = Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    };
    c.send(asdu).await
}

// MeasuredValueScaled sends a type identification [M_ME_NB_1].测量值,标度化值
// [M_ME_NB_1] See companion standard 101, subclass 7.3.1.11
// 传送原因(cot)用于
// 监视方向：
// <1> := 周期/循环
// <2> := 背景扫描
// <3> := 突发(自发)
// <5> := 被请求
// <20> := 响应站召唤
// <21> := 响应第1组召唤
// 至
// <36> := 响应第16组召唤
pub async fn measured_value_scaled(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueScaledInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Periodic
        || cause == Cause::Background
        || cause == Cause::Spontaneous
        || cause == Cause::Request
        || (cause >= Cause::InterrogatedByStation && cause <= Cause::InterrogatedByGroup16))
    {
        return Err(Error::ErrCmdCause(cot));
    }
    measured_value_scaled_inner(c, TypeID::M_ME_NB_1, false, cot, ca, infos).await
}

// MeasuredValueScaledCP24Time2a sends a type identification [M_ME_TB_1].带时标CP24Time2a的测量值,标度化值,只有(SQ = 0)单个信息元素集合
// [M_ME_TB_1] See companion standard 101, subclass 7.3.1.12
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <5> := 被请求
pub async fn measured_value_scaled_cp24time2a(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueScaledInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous || cause == Cause::Request) {
        return Err(Error::ErrCmdCause(cot));
    }
    measured_value_scaled_inner(c, TypeID::M_ME_TB_1, false, cot, ca, infos).await
}

// MeasuredValueScaledCP56Time2a sends a type identification [M_ME_TE_1].带时标CP56Time2a的测量值,标度化值,只有(SQ = 0)单个信息元素集合
// [M_ME_TE_1] See companion standard 101, subclass 7.3.1.27
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <5> := 被请求
pub async fn measured_value_scaled_cp56time2a(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueScaledInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous || cause == Cause::Request) {
        return Err(Error::ErrCmdCause(cot));
    }
    measured_value_scaled_inner(c, TypeID::M_ME_TE_1, false, cot, ca, infos).await
}

// measuredValueFloat sends a type identification [M_ME_NC_1], [M_ME_TC_1] or [M_ME_TF_1].测量值,短浮点数
// [M_ME_NC_1] See companion standard 101, subclass 7.3.1.13
// [M_ME_TC_1] See companion standard 101, subclass 7.3.1.14
// [M_ME_TF_1] See companion standard 101, subclass 7.3.1.28
async fn measured_value_float_inner(
    c: &impl Connect,
    type_id: TypeID,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueFloatInfo>,
) -> Result<(), Error> {
    check_vaild(c, type_id, is_sequence, infos.len())?;
    let variable_struct = VariableStruct::new(
        u1::new(is_sequence as u8).unwrap(),
        u7::new(infos.len() as u8).unwrap(),
    );
    let mut once = false;
    let mut buf = vec![];
    for info in infos {
        if !is_sequence || !once {
            once = true;
            buf.write_u24::<LittleEndian>(info.ioa.raw().value())?;
        }
        buf.write_f32::<LittleEndian>(info.r)?;
        buf.write_u8(info.qds.raw())?;
        match type_id {
            TypeID::M_ME_NC_1 => (),
            TypeID::M_ME_TC_1 => {
                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp24time2a(time));
                } else {
                    buf.extend_from_slice(&cp24time2a(Utc::now()));
                }
            }
            TypeID::M_ME_TF_1 => {
                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp56time2a(time));
                } else {
                    buf.extend_from_slice(&cp56time2a(Utc::now()));
                }
            }
            _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
        }
    }
    let asdu = Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    };
    c.send(asdu).await
}

// MeasuredValueFloat sends a type identification [M_ME_TF_1].测量值,短浮点数
// [M_ME_NC_1] See companion standard 101, subclass 7.3.1.13
// 传送原因(cot)用于
// 监视方向：
// <1> := 周期/循环
// <2> := 背景扫描
// <3> := 突发(自发)
// <5> := 被请求
// <20> := 响应站召唤
// <21> := 响应第1组召唤
// 至
// <36> := 响应第16组召唤
pub async fn measured_value_float(
    c: &impl Connect,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueFloatInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Periodic
        || cause == Cause::Background
        || cause == Cause::Spontaneous
        || cause == Cause::Request
        || (cause >= Cause::InterrogatedByStation && cause <= Cause::InterrogatedByGroup16))
    {
        return Err(Error::ErrCmdCause(cot));
    }

    measured_value_float_inner(c, TypeID::M_ME_NC_1, is_sequence, cot, ca, infos).await
}

// MeasuredValueFloatCP24Time2a sends a type identification [M_ME_TC_1].带时标CP24Time2a的测量值,短浮点数,只有(SQ = 0)单个信息元素集合
// [M_ME_TC_1] See companion standard 101, subclass 7.3.1.14
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <5> := 被请求
pub async fn measured_value_float_cp24time2a(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueFloatInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous || cause == Cause::Request) {
        return Err(Error::ErrCmdCause(cot));
    }

    measured_value_float_inner(c, TypeID::M_ME_TC_1, false, cot, ca, infos).await
}

// MeasuredValueFloatCP56Time2a sends a type identification [M_ME_TF_1].带时标CP56Time2a的测量值,短浮点数,只有(SQ = 0)单个信息元素集合
// [M_ME_TF_1] See companion standard 101, subclass 7.3.1.28
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <5> := 被请求
pub async fn measured_value_float_cp56time2a(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<MeasuredValueFloatInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous || cause == Cause::Request) {
        return Err(Error::ErrCmdCause(cot));
    }

    measured_value_float_inner(c, TypeID::M_ME_TF_1, false, cot, ca, infos).await
}
// integratedTotals sends a type identification [M_IT_NA_1], [M_IT_TA_1] or [M_IT_TB_1]. 累计量
// [M_IT_NA_1] See companion standard 101, subclass 7.3.1.15
// [M_IT_TA_1] See companion standard 101, subclass 7.3.1.16
// [M_IT_TB_1] See companion standard 101, subclass 7.3.1.29
async fn integrated_totals_inner(
    c: &impl Connect,
    type_id: TypeID,
    is_sequence: bool,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<BinaryCounterReadingInfo>,
) -> Result<(), Error> {
    check_vaild(c, type_id, is_sequence, infos.len())?;
    let variable_struct = VariableStruct::new(
        u1::new(is_sequence as u8).unwrap(),
        u7::new(infos.len() as u8).unwrap(),
    );
    let mut once = false;
    let mut buf = vec![];
    for info in infos {
        if !is_sequence || !once {
            once = true;
            buf.write_u24::<LittleEndian>(info.ioa.raw().value())?;
        }
        let mut v = info.bcr.seq & 0x1f;
        if info.bcr.cy {
            v |= 0x20;
        }
        if info.bcr.ca {
            v |= 0x40;
        }
        if info.bcr.invalid {
            v |= 0x80
        }
        buf.write_i32::<LittleEndian>(info.bcr.value)?;
        buf.write_u8(v)?;
        match type_id {
            TypeID::M_IT_NA_1 => (),
            TypeID::M_IT_TA_1 => {
                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp24time2a(time));
                } else {
                    buf.extend_from_slice(&cp24time2a(Utc::now()));
                }
            }
            TypeID::M_IT_TB_1 => {
                if let Some(time) = info.time {
                    buf.extend_from_slice(&cp56time2a(time));
                } else {
                    buf.extend_from_slice(&cp56time2a(Utc::now()));
                }
            }
            _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
        }
    }
    let asdu = Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    };
    c.send(asdu).await
}

// IntegratedTotals sends a type identification [M_IT_NA_1]. 累计量
// [M_IT_NA_1] See companion standard 101, subclass 7.3.1.15
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <37> := 响应总计数量召唤
// <38> := 响应第1组计数量召唤
// <39> := 响应第2组计数量召唤
// <40> := 响应第3组计数量召唤
// <41> := 响应第4组计数量召唤
pub async fn integrated_totals(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<BinaryCounterReadingInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous
        || (cause >= Cause::InterrogatedByStation && cause <= Cause::RequestByGroup4Counter))
    {
        return Err(Error::ErrCmdCause(cot));
    }

    integrated_totals_inner(c, TypeID::M_IT_NA_1, false, cot, ca, infos).await
}

// IntegratedTotalsCP24Time2a sends a type identification [M_IT_TA_1]. 带时标CP24Time2a的累计量,只有(SQ = 0)单个信息元素集合
// [M_IT_TA_1] See companion standard 101, subclass 7.3.1.16
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <37> := 响应总计数量召唤
// <38> := 响应第1组计数量召唤
// <39> := 响应第2组计数量召唤
// <40> := 响应第3组计数量召唤
// <41> := 响应第4组计数量召唤
pub async fn integrated_totals_cp24time2a(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<BinaryCounterReadingInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous
        || (cause >= Cause::InterrogatedByStation && cause <= Cause::RequestByGroup4Counter))
    {
        return Err(Error::ErrCmdCause(cot));
    }

    integrated_totals_inner(c, TypeID::M_IT_TA_1, false, cot, ca, infos).await
}

// IntegratedTotalsCP56Time2a sends a type identification [M_IT_TB_1]. 带时标CP56Time2a的累计量,只有(SQ = 0)单个信息元素集合
// [M_IT_TB_1] See companion standard 101, subclass 7.3.1.29
// 传送原因(cot)用于
// 监视方向：
// <3> := 突发(自发)
// <37> := 响应总计数量召唤
// <38> := 响应第1组计数量召唤
// <39> := 响应第2组计数量召唤
// <40> := 响应第3组计数量召唤
// <41> := 响应第4组计数量召唤
pub async fn integrated_totals_cp56time2a(
    c: &impl Connect,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    infos: Vec<BinaryCounterReadingInfo>,
) -> Result<(), Error> {
    let mut cot = cot;
    let cause = cot.cause().get();
    if !(cause == Cause::Spontaneous
        || (cause >= Cause::InterrogatedByStation && cause <= Cause::RequestByGroup4Counter))
    {
        return Err(Error::ErrCmdCause(cot));
    }

    integrated_totals_inner(c, TypeID::M_IT_TB_1, false, cot, ca, infos).await
}

impl Asdu {
    // [M_SP_NA_1], [M_SP_TA_1] or [M_SP_TB_1] 获取单点信息信息体集合
    pub fn get_single_point(&mut self) -> Result<Vec<SinglePointInfo>> {
        let mut rdr = Cursor::new(&self.raw);
        let info_num = self.identifier.variable_struct.number().get().value() as usize;
        let is_seq = self.identifier.variable_struct.is_sequence().get().value() != 0;
        let mut info = Vec::with_capacity(info_num);
        let mut once = false;
        let mut ioa = InfoObjAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = InfoObjAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
            } else {
                let addr = ioa.addr().get() + 1;
                ioa.addr().set(addr);
            }
            let siq = ObjectSIQ::try_from(rdr.read_u8()?).unwrap();
            let mut time = None;
            match self.identifier.type_id {
                TypeID::M_SP_NA_1 => (),
                TypeID::M_SP_TA_1 => time = decode_cp24time2a(&mut rdr)?,
                TypeID::M_SP_TB_1 => time = decode_cp56time2a(&mut rdr)?,
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
        let mut ioa = InfoObjAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = InfoObjAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
            } else {
                let addr = ioa.addr().get() + 1;
                ioa.addr().set(addr);
            }
            let diq = ObjectDIQ::try_from(rdr.read_u8()?).unwrap();
            let mut time = None;
            match self.identifier.type_id {
                TypeID::M_DP_NA_1 => (),
                TypeID::M_DP_TA_1 => time = decode_cp24time2a(&mut rdr)?,
                TypeID::M_DP_TB_1 => time = decode_cp56time2a(&mut rdr)?,
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
        let mut ioa = InfoObjAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = InfoObjAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
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
                    time = decode_cp24time2a(&mut rdr)?
                }
                TypeID::M_ME_TD_1 => {
                    qds = Some(ObjectQDS::try_from(rdr.read_u8()?).unwrap());
                    time = decode_cp56time2a(&mut rdr)?
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
        let mut ioa = InfoObjAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = InfoObjAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
            } else {
                let addr = ioa.addr().get() + 1;
                ioa.addr().set(addr);
            }
            let sva = rdr.read_i16::<LittleEndian>()?;
            let qds = ObjectQDS::try_from(rdr.read_u8()?).unwrap();
            let mut time = None;
            match self.identifier.type_id {
                TypeID::M_ME_NB_1 => (),
                TypeID::M_ME_TB_1 => time = decode_cp24time2a(&mut rdr)?,
                TypeID::M_ME_TE_1 => time = decode_cp56time2a(&mut rdr)?,
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
        let mut ioa = InfoObjAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = InfoObjAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
            } else {
                let addr = ioa.addr().get() + 1;
                ioa.addr().set(addr);
            }
            let r = rdr.read_f32::<LittleEndian>()?;
            let qds = ObjectQDS::try_from(rdr.read_u8()?).unwrap();
            let mut time = None;
            match self.identifier.type_id {
                TypeID::M_ME_NC_1 => (),
                TypeID::M_ME_TC_1 => time = decode_cp24time2a(&mut rdr)?,
                TypeID::M_ME_TF_1 => time = decode_cp56time2a(&mut rdr)?,
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
        let mut ioa = InfoObjAddr::try_from(u24!(0)).unwrap();
        let mut info_obj_addr_std;
        for i in 0..info_num {
            if !is_seq || !once {
                once = true;
                info_obj_addr_std = rdr.read_u24::<LittleEndian>()?;
                ioa = InfoObjAddr::try_from(u24::new(info_obj_addr_std).unwrap()).unwrap();
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
                TypeID::M_IT_TA_1 => time = decode_cp24time2a(&mut rdr)?,
                TypeID::M_IT_TB_1 => time = decode_cp56time2a(&mut rdr)?,
                _ => panic!("ErrTypeIDNotMatch"),
            }
            info.push(BinaryCounterReadingInfo { ioa, bcr, time });
        }
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use chrono::{Datelike, TimeZone, Timelike};
    use tokio_test::{assert_err, assert_ok};

    use crate::{
        frame::asdu::{CauseOfTransmission, Identifier, VariableStruct},
        interface::TestConn,
    };

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

    #[tokio::test]
    async fn test_single() -> Result<()> {
        struct Args {
            c: TestConn,
            is_sequence: bool,
            cot: CauseOfTransmission,
            ca: CommonAddr,
            infos: Vec<SinglePointInfo>,
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
                    c: TestConn::new(Bytes::new(), None),
                    is_sequence: false,
                    cot: CauseOfTransmission::new(false, false, Cause::Unused),
                    ca: 0x1234,
                    infos: vec![],
                },
                want_err: true,
            },
            Test {
                name: "M_SP_NA_1 seq = false Number = 2".into(),
                args: Args {
                    c: TestConn::new(
                        Bytes::from_static(&[
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
                        Some(Duration::from_millis(50)),
                    ),
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
                },
                want_err: false,
            },
            Test {
                name: "M_SP_NA_1 seq = true Number = 2".into(),
                args: Args {
                    c: TestConn::new(
                        Bytes::from_static(&[
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
                        None,
                    ),
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
                },
                want_err: false,
            },
        ];

        for t in tests {
            let r = single(
                &t.args.c,
                t.args.is_sequence,
                t.args.cot,
                t.args.ca,
                t.args.infos,
            )
            .await;
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
