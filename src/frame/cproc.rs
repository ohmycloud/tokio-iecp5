use core::panic;
use std::io::Cursor;

use anyhow::Result;
use bit_struct::*;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bytes::Bytes;
use chrono::{DateTime, Utc};

use crate::{error::Error, frame::asdu::TypeID};

use super::{
    asdu::{Asdu, Cause, CauseOfTransmission, CommonAddr, Identifier, InfoObjAddr, VariableStruct},
    time::{cp56time2a, decode_cp56time2a},
};

// 在控制方向过程信息的应用服务数据单元

// 单命令
#[derive(Debug, PartialEq)]
pub struct SingleCommandInfo {
    /// 信息对象地址
    pub ioa: InfoObjAddr,
    /// 信息对象元素
    pub sco: ObjectSCO,
    /// 时标
    pub time: Option<DateTime<Utc>>,
}

impl SingleCommandInfo {
    pub fn new(addr: u16, v: bool, se: bool) -> Self {
        let ioa = InfoObjAddr::new(0, addr);
        let sco = ObjectSCO::new(v, u1!(0), u5!(0), se);
        SingleCommandInfo {
            ioa,
            sco,
            time: None,
        }
    }
}

// 双命令
#[derive(Debug, PartialEq)]
pub struct DoubleCommandInfo {
    /// 信息对象地址
    pub ioa: InfoObjAddr,
    /// 信息对象元素
    pub dco: ObjectDCO,
    /// 时标
    pub time: Option<DateTime<Utc>>,
}

impl DoubleCommandInfo {
    pub fn new(addr: u16, v: u8, se: bool) -> Self {
        let v = v % 4;
        let ioa = InfoObjAddr::new(0, addr);
        let dco = ObjectDCO::new(u2::new(v).unwrap(), u5!(0), se);
        DoubleCommandInfo {
            ioa,
            dco,
            time: None,
        }
    }
}

// 设定命令, 规一化值
#[derive(Debug, PartialEq)]
pub struct SetpointCommandNormalInfo {
    /// 信息对象地址
    pub ioa: InfoObjAddr,
    /// 信息对象值(归一化值)
    pub nva: i16,
    /// 设定点命令限定词
    pub qos: ObjectQOS,
    /// 时标
    pub time: Option<DateTime<Utc>>,
}

impl SetpointCommandNormalInfo {
    pub fn new(addr: u16, v: i16) -> Self {
        let ioa = InfoObjAddr::new(0, addr);
        let qos = ObjectQOS::new(u7!(0), u1!(0));
        SetpointCommandNormalInfo {
            ioa,
            nva: v,
            qos,
            time: None,
        }
    }
}

// 设定命令, 标度化值
// C_SE_NB_1 := CP{数据单元标识符, 信息对象地址, SVA, QOS}
// 设定命令, 标度化值
// 单个信息对象 (SQ = 0)
// | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 类型标识 (TYP)                                      |
// | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 可变结构限定词 (VSQ)                                 |
// | 在 DL/T 634.5101 7.2.3 中定义  | 传送原因 (COT)                                      |
// | 在 DL/T 634.5101 7.2.4 中定义  | 应用服务数据单元公共地址                               |
// | 在 DL/T 634.5101 7.2.5 中定义  | 信息对象地址                                         |
// |           Value               | SVA=标度化值 (在 DL/T 634.5101 7.2.6.7 中定义)       |
// | S |       Value               |                                                   |
// |S/E|       QL                  | QOS=设定命令限定词 (在 DL/T 634.5101 7.2.6.39 中定义) |

// C_SE_TB_1 := CP{数据单元标识符, 信息对象地址, SVA, QOS, CP56Time2a}
// 带时标 CP56Time2a 的设定值命令, 标度化值
// 单个信息对象 (SQ = 0)
// | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 0 | 类型标识 (TYP)                                         |
// | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 可变结构限定词 (VSQ)                                    |
// | 在 DL/T 634.5101 7.2.3 中定义  | 传送原因 (COT)                                         |
// | 在 DL/T 634.5101 7.2.4 中定义  | 应用服务数据单元公共地址                                  |
// | 在 DL/T 634.5101 7.2.5 中定义  | 信息对象地址                                            |
// |   |          Value            | SVA=标度化值 (在 DL/T 634.5101 7.2.6.7 中定义)          |
// | S |          Value            |                                                      |
// |S/E|          QL               | QOS=设定命令品质限定词 (在 DL/T 634.5101 7.2.6.39 中定义) |
// |    CP56Time2a (在 DL/T 634.5101 7.2.6.18 中定义) | 7 个八位位组的二进制时间               |
#[derive(Debug, PartialEq)]
pub struct SetpointCommandScaledInfo {
    /// 信息对象地址
    pub ioa: InfoObjAddr,
    /// 标度化值
    pub sva: i16,
    // 设定命令限定词
    pub qos: ObjectQOS,
    /// 时标
    pub time: Option<DateTime<Utc>>,
}

impl SetpointCommandScaledInfo {
    pub fn new(addr: u16, v: i16) -> Self {
        let ioa = InfoObjAddr::new(0, addr);
        let qos = ObjectQOS::new(u7!(0), u1!(0));
        SetpointCommandScaledInfo {
            ioa,
            sva: v,
            qos,
            time: None,
        }
    }
}

// 设定命令, 短浮点数
pub struct SetpointCommandFloatInfo {
    pub ioa: InfoObjAddr,
    pub r: f32,
    pub qos: ObjectQOS,
    pub time: Option<DateTime<Utc>>,
}

impl SetpointCommandFloatInfo {
    pub fn new(addr: u16, v: f32) -> Self {
        let ioa = InfoObjAddr::new(0, addr);
        let qos = ObjectQOS::new(u7!(0), u1!(0));
        SetpointCommandFloatInfo {
            ioa,
            r: v,
            qos,
            time: None,
        }
    }
}

// 比特串命令
pub struct BitsString32CommandInfo {
    pub ioa: InfoObjAddr,
    pub bcr: i32,
    pub time: Option<DateTime<Utc>>,
}

impl BitsString32CommandInfo {
    pub fn new(addr: u16, v: i32) -> Self {
        let ioa = InfoObjAddr::new(0, addr);
        BitsString32CommandInfo {
            ioa,
            bcr: v,
            time: None,
        }
    }
}

// SCO - Single Command Output(单点命令输出) 遥控信息
// 用于发送单点控制命令，通常用于控制只有两个状态的设备
// 单个信息对象 (SQ = 0)
// | 0 | 0 | 1 | 0 | 1 | 1 | 0 | 1  | 类型标识(TYP)                |
// | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1  | 可变结构限定词(VSQ)          |
// | 在 7.2.3 中定义                 | 传送原因(COT)               |
// | 在 7.2.4 中定义                 | 应用服务数据单元公共地址      |
// | 在 7.2.5 中定义                 | 信息对象地址                 |
// |S/E| QU                | 0 |SCS| SCO=单命令(在 7.2.6.15中定义) |

// SCO=单命令 := CP8 [SCS, BS1, QOC]
// SCS=单命令状态 := BS1 [1] <0, 1>
//     <0> := 开
//     <1> := 合
// RES=备用 := BS1 [2] <0>
// QOC=CP6 [3...8] {QU, S/E}
// QU := UI5 [3...7] <0...31>
//   <0> := 无另外的定义
//   <1> := 短脉冲持续时间
//   <2> := 长脉冲持续时间
//   <3> := 持续输出
// S/E := BSI [8] <0, 1>
//   <0> := 执行
//   <1> := 选择
bit_struct! {
    pub struct ObjectSCO(u8) {
        scs: bool,  // 单命令状态
        res: u1,    // 预留: 置 0
        qu: u5,     // 输出方式: 0: 被控确定, 1: 短脉冲, 2: 长脉冲, 3: 持续脉冲
        se: bool,   // 选择标志: 0: 执行, 1: 选择
    }
}

// DCO - Double Command Output(双点命令输出) 遥控信息
// 单个信息对象 (SQ = 0)
// | 0 | 0 | 1 | 0 | 1 | 1 | 1 | 0 | 类型标识(TYP)                |
// | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 可变结构限定词(VSQ)          |
// | 在 7.2.3 中定义                | 传送原因(COT)               |
// | 在 7.2.4 中定义                | 应用服务数据单元公共地址      |
// | 在 7.2.5 中定义                | 信息对象地址                  |
// |S/E| QU                | DCS  | DCO=双命令(在 7.2.6.16 中定义) |

// DCO=双命令 := CP8 {DCS, QOC}
// DCS=双命令状态 := UI2 [1, 2] <0...3>
//     <0> := 不允许
//     <1> := 开
//     <2> := 合
//     <3> := 不允许
// QOC := CP6 [3...8] {QU, S/E}
// QU := UI5 [3...7] <0...31>
//   <0> := 无另外的定义
//   <1> := 短脉冲持续时间
//   <2> := 长脉冲持续时间
//   <3> := 持续输出
// S/E := BSI [8] <0, 1>
//   <0> := 执行
//   <1> := 选择
bit_struct! {
    pub struct ObjectDCO(u8) {
        /// 双命令状态
        dcs: u2,
        /// 输出方式: 0: 被控确定, 1: 短脉冲, 2: 长脉冲, 3: 持续脉冲
        qu: u5,
        /// 选择标志: 0:执行, 1:选择
        se: bool,
    }
}

// QOC - Qualifier of Command(命令限定词)
// QOC := CP6 {QU, S/E}
// QU := UI5 [3...7] <0...31>
//   <0> := 无另外的定义
//   <1> := 短脉冲持续时间
//   <2> := 长脉冲持续时间
//   <3> := 持续输出
// S/E := BSI [8] <0, 1>
//   <0> := 执行
//   <1> := 选择
bit_struct! {
    pub struct ObjectQOC(u8) {
        /// 预留: 置 0
        res: u2,
        /// 输出方式: 0: 被控确定, 1: 短脉冲, 2: 长脉冲, 3: 持续脉冲
        qu: u5,
        /// 选择标志: 0: 执行, 1: 选择
        se: u1,
    }
}

// QOS - Qualifier of Set-point Command(设定命令限定词)
// | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 类型标识(TYP)                      |
// | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 可变结构限定词(VSQ)                 |
// | 在 7.2.3 中定义                | 传送原因(COT)                      |
// | 在 7.2.4 中定义                | 应用服务数据单元公共地址              |
// | 在 7.2.5 中定义                | 信息对象地址                        |
// |S/E| QL                       | QOS=设定命令限定词(在 7.2.6.39 中定义) |
// QOS := CP8 {QL, S/E}
// Q1 := UI7 [1...7] <0...127>
//   <0> := 缺省
//   <1...63> := 为本配套标准的标准定义保留（兼容范围）
//   <64...127> := 为特定使用保留（专用范围）
// S/E := BS1 [8] <0, 1>
//   <0> := 执行
//   <1> := 选择
bit_struct! {
    pub struct ObjectQOS(u8) {
        /// 0: 默认 1-63: 预留为标准定义 64-127:特殊使用
        ql: u7,
        /// 选择标志: 0: 执行, 1: 选择
        se: u1,
    }
}

// SingleCmd sends a type identification [C_SC_NA_1] or [C_SC_TA_1]. 单命令, 只有单个信息对象(SQ = 0)
// [C_SC_NA_1] See companion standard 101, subclass 7.3.2.1
// [C_SC_TA_1] See companion standard 101,
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// <8> := 停止激活
// 监视方向：
// <7> := 激活确认
// <9> := 停止激活确认
// <10> := 激活终止
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn single_cmd(
    type_id: TypeID,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    cmd: SingleCommandInfo,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    let cause = cot.cause().get();

    if !(cause == Cause::Activation || cause == Cause::Deactivation) {
        return Err(Error::ErrCmdCause(cot));
    }

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(cmd.ioa.raw().value())?;
    buf.write_u8(cmd.sco.raw())?;

    match type_id {
        TypeID::C_SC_NA_1 => (),
        TypeID::C_SC_TA_1 => {
            if let Some(time) = cmd.time {
                buf.extend_from_slice(&cp56time2a(time));
            } else {
                buf.extend_from_slice(&cp56time2a(Utc::now()));
            }
        }
        _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
    }

    Ok(Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// DoubleCmd sends a type identification [C_DC_NA_1] or [C_DC_TA_1]. 双命令, 只有单个信息对象(SQ = 0)
// [C_DC_NA_1] See companion standard 101, subclass 7.3.2.2
// [C_DC_TA_1] See companion standard 101,
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// <8> := 停止激活
// 监视方向：
// <7> := 激活确认
// <9> := 停止激活确认
// <10> := 激活终止
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn double_cmd(
    type_id: TypeID,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    cmd: DoubleCommandInfo,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    let cause = cot.cause().get();

    if !(cause == Cause::Activation || cause == Cause::Deactivation) {
        return Err(Error::ErrCmdCause(cot));
    }

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(cmd.ioa.raw().value())?;
    buf.write_u8(cmd.dco.raw())?;

    match type_id {
        TypeID::C_DC_NA_1 => (),
        TypeID::C_DC_TA_1 => {
            if let Some(time) = cmd.time {
                buf.extend_from_slice(&cp56time2a(time));
            } else {
                buf.extend_from_slice(&cp56time2a(Utc::now()));
            }
        }
        _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
    }

    Ok(Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// StepCmd sends a type [C_RC_NA_1] or [C_RC_TA_1]. 步调节命令, 只有单个信息对象(SQ = 0)
// [C_RC_NA_1] See companion standard 101, subclass 7.3.2.3
// [C_RC_TA_1] See companion standard 101,
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// <8> := 停止激活
// 监视方向：
// <7> := 激活确认
// <9> := 停止激活确认
// <10> := 激活终止
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
// pub fn step_cmd(
//     c: &impl Connect,
//     type_id: TypeID,
//     cot: CauseOfTransmission,
//     ca: CommonAddr,
//     cmd: StepCommandInfo,
// ) -> Result<(), Error> {
//     let mut cot = cot;
//     let cause = cot.cause().get();
//
//     if !(cause == Cause::Activation || cause == Cause::Deactivation) {
//         return Err(Error::ErrCmdCause(cot));
//     }
//
//     let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());
//
//     let mut buf = vec![];
//     buf.write_u24::<LittleEndian>(cmd.ioa.raw().value())?;
//     buf.write_u8(cmd.dco.raw())?;
//
//     match type_id {
//         TypeID::C_DC_NA_1 => (),
//         TypeID::C_DC_TA_1 => {
//             if let Some(time) = cmd.time {
//                 buf.extend_from_slice(&cp56time2a(time));
//             } else {
//                 buf.extend_from_slice(&cp56time2a(Utc::now()));
//             }
//         }
//         _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
//     }
//
//     let asdu = Asdu {
//         identifier: Identifier {
//             type_id,
//             variable_struct,
//             cot,
//             orig_addr: 0,
//             common_addr: ca,
//         },
//         raw: Bytes::from(buf),
//     };
//
//     c.send(asdu).await
// }

// SetpointCmdNormal sends a type [C_SE_NA_1] or [C_SE_TA_1]. 设定命令,规一化值, 只有单个信息对象(SQ = 0)
// [C_SE_NA_1] See companion standard 101, subclass 7.3.2.4
// [C_SE_TA_1] See companion standard 101,
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// <8> := 停止激活
// 监视方向：
// <7> := 激活确认
// <9> := 停止激活确认
// <10> := 激活终止
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn set_point_cmd_normal(
    type_id: TypeID,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    cmd: SetpointCommandNormalInfo,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    let cause = cot.cause().get();

    if !(cause == Cause::Activation || cause == Cause::Deactivation) {
        return Err(Error::ErrCmdCause(cot));
    }

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(cmd.ioa.raw().value())?;
    buf.write_i16::<LittleEndian>(cmd.nva)?;
    buf.write_u8(cmd.qos.raw())?;

    match type_id {
        TypeID::C_SE_NA_1 => (),
        TypeID::C_SE_TA_1 => {
            if let Some(time) = cmd.time {
                buf.extend_from_slice(&cp56time2a(time));
            } else {
                buf.extend_from_slice(&cp56time2a(Utc::now()));
            }
        }
        _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
    }

    Ok(Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// SetpointCmdScaled sends a type [C_SE_NB_1] or [C_SE_TB_1]. 设定命令,标度化值,只有单个信息对象(SQ = 0)
// [C_SE_NB_1] See companion standard 101, subclass 7.3.2.5
// [C_SE_TB_1] See companion standard 101,
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// <8> := 停止激活
// 监视方向：
// <7> := 激活确认
// <9> := 停止激活确认
// <10> := 激活终止
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn set_point_cmd_scaled(
    type_id: TypeID,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    cmd: SetpointCommandScaledInfo,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    let cause = cot.cause().get();

    if !(cause == Cause::Activation || cause == Cause::Deactivation) {
        return Err(Error::ErrCmdCause(cot));
    }

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(cmd.ioa.raw().value())?;
    buf.write_i16::<LittleEndian>(cmd.sva)?;
    buf.write_u8(cmd.qos.raw())?;

    match type_id {
        TypeID::C_SE_NB_1 => (),
        TypeID::C_SE_TB_1 => {
            if let Some(time) = cmd.time {
                buf.extend_from_slice(&cp56time2a(time));
            } else {
                buf.extend_from_slice(&cp56time2a(Utc::now()));
            }
        }
        _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
    }

    Ok(Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// SetpointCmdFloat sends a type [C_SE_NC_1] or [C_SE_TC_1].设定命令,短浮点数,只有单个信息对象(SQ = 0)
// [C_SE_NC_1] See companion standard 101, subclass 7.3.2.6
// [C_SE_TC_1] See companion standard 101,
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// <8> := 停止激活
// 监视方向：
// <7> := 激活确认
// <9> := 停止激活确认
// <10> := 激活终止
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn set_point_cmd_float(
    type_id: TypeID,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    cmd: SetpointCommandFloatInfo,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    let cause = cot.cause().get();

    if !(cause == Cause::Activation || cause == Cause::Deactivation) {
        return Err(Error::ErrCmdCause(cot));
    }

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(cmd.ioa.raw().value())?;
    buf.write_f32::<LittleEndian>(cmd.r)?;
    buf.write_u8(cmd.qos.raw())?;

    match type_id {
        TypeID::C_SE_NC_1 => (),
        TypeID::C_SE_TC_1 => {
            if let Some(time) = cmd.time {
                buf.extend_from_slice(&cp56time2a(time));
            } else {
                buf.extend_from_slice(&cp56time2a(Utc::now()));
            }
        }
        _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
    }

    Ok(Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// BitsString32Cmd sends a type [C_BO_NA_1] or [C_BO_TA_1]. 比特串命令,只有单个信息对象(SQ = 0)
// [C_BO_NA_1] See companion standard 101, subclass 7.3.2.7
// [C_BO_TA_1] See companion standard 101,
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// <8> := 停止激活
// 监视方向：
// <7> := 激活确认
// <9> := 停止激活确认
// <10> := 激活终止
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn bits_string32_cmd(
    type_id: TypeID,
    cot: CauseOfTransmission,
    ca: CommonAddr,
    cmd: BitsString32CommandInfo,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    let cause = cot.cause().get();

    if !(cause == Cause::Activation || cause == Cause::Deactivation) {
        return Err(Error::ErrCmdCause(cot));
    }

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(cmd.ioa.raw().value())?;
    buf.write_i32::<LittleEndian>(cmd.bcr)?;

    match type_id {
        TypeID::C_BO_NA_1 => (),
        TypeID::C_BO_TA_1 => {
            if let Some(time) = cmd.time {
                buf.extend_from_slice(&cp56time2a(time));
            } else {
                buf.extend_from_slice(&cp56time2a(Utc::now()));
            }
        }
        _ => return Err(Error::ErrTypeIDNotMatch(type_id)),
    }

    Ok(Asdu {
        identifier: Identifier {
            type_id,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

impl Asdu {
    // [C_SC_NA_1] or [C_SC_TA_1] 获取单命令信息体
    pub fn get_single_cmd(&mut self) -> Result<SingleCommandInfo> {
        let mut rdr = Cursor::new(&self.raw);
        let ioa =
            InfoObjAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap();
        let sco = ObjectSCO::try_from(rdr.read_u8()?).unwrap();

        let mut time = None;
        match self.identifier.type_id {
            TypeID::C_SC_NA_1 => (),
            TypeID::C_SC_TA_1 => time = decode_cp56time2a(&mut rdr)?,
            _ => panic!("ErrTypeIDNotMatch"),
        }
        Ok(SingleCommandInfo { ioa, sco, time })
    }

    // [C_DC_NA_1] or [C_DC_TA_1] 获取双命令信息体
    pub fn get_double_cmd(&mut self) -> Result<DoubleCommandInfo> {
        let mut rdr = Cursor::new(&self.raw);
        let ioa =
            InfoObjAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap();
        let dco = ObjectDCO::try_from(rdr.read_u8()?).unwrap();
        let mut time = None;
        match self.identifier.type_id {
            TypeID::C_DC_NA_1 => (),
            TypeID::C_DC_TA_1 => time = decode_cp56time2a(&mut rdr)?,
            _ => panic!("ErrTypeIDNotMatch"),
        }
        Ok(DoubleCommandInfo { ioa, dco, time })
    }

    // GetSetpointNormalCmd [C_SE_NA_1] or [C_SE_TA_1] 获取设定命令,规一化值信息体
    pub fn get_setpoint_normal_cmd(&mut self) -> Result<SetpointCommandNormalInfo> {
        let mut rdr = Cursor::new(&self.raw);
        let ioa =
            InfoObjAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap();
        let nva = rdr.read_i16::<LittleEndian>()?;
        let qos = ObjectQOS::try_from(rdr.read_u8()?).unwrap();

        let mut time = None;
        match self.identifier.type_id {
            TypeID::C_SE_NA_1 => (),
            TypeID::C_SE_TA_1 => time = decode_cp56time2a(&mut rdr)?,
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
        let ioa =
            InfoObjAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap();
        let sva = rdr.read_i16::<LittleEndian>()?;
        let qos = ObjectQOS::try_from(rdr.read_u8()?).unwrap();

        let mut time = None;
        match self.identifier.type_id {
            TypeID::C_SE_NB_1 => (),
            TypeID::C_SE_TB_1 => time = decode_cp56time2a(&mut rdr)?,
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
        let ioa =
            InfoObjAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap();
        let r = rdr.read_f32::<LittleEndian>()?;
        let qos = ObjectQOS::try_from(rdr.read_u8()?).unwrap();

        let mut time = None;
        match self.identifier.type_id {
            TypeID::C_SE_NC_1 => (),
            TypeID::C_SE_TC_1 => time = decode_cp56time2a(&mut rdr)?,
            _ => panic!("ErrTypeIDNotMatch"),
        }

        Ok(SetpointCommandFloatInfo { ioa, r, qos, time })
    }

    // [C_BO_NA_1] or [C_BO_TA_1] 获取比特串命令信息体
    pub fn get_bits_string32_cmd(&mut self) -> Result<BitsString32CommandInfo> {
        let mut rdr = Cursor::new(&self.raw);
        let ioa =
            InfoObjAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap();
        let bcr = rdr.read_i32::<LittleEndian>()?;

        let mut time = None;
        match self.identifier.type_id {
            TypeID::C_BO_NA_1 => (),
            TypeID::C_BO_TA_1 => time = decode_cp56time2a(&mut rdr)?,
            _ => panic!("ErrTypeIDNotMatch"),
        }

        Ok(BitsString32CommandInfo { ioa, bcr, time })
    }
}
