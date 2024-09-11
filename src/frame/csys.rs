use std::io::Cursor;

use anyhow::Result;
use bit_struct::*;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use bytes::Bytes;
use chrono::{DateTime, Utc};

use crate::error::Error;

use super::{
    asdu::{
        Asdu, Cause, CauseOfTransmission, CommonAddr, Identifier, InfoObjAddr, TypeID,
        VariableStruct, INFO_OBJ_ADDR_IRRELEVANT,
    },
    time::{cp16time2a_from_msec, cp56time2a},
};

// 在控制方向系统信息的应用服务数据单元

// FBPTestWord test special value
const FBPTEST_WORD: u16 = 0x55aa;

pub type QualifierOfResetProcessCmd = u8;

// QOI - Qualifier of Interrogation(召唤限定词)
bit_struct! {
    pub struct ObjectQOI(u8) {
        range: u8,   // 范围: 0~19:保留, 20:全站, 21~36:第1~16组, 37~255:保留
    }
}

// QCC - Qualifier of Counter Interrogation Command(计数器召唤命令限定词)
bit_struct! {
    pub struct ObjectQCC(u8) {
        qcc: u8,
    }
}

// QRP - Qualifier of Reset Process Command(复位进程命令限定词)
bit_struct! {
    pub struct ObjectQRP(u8) {
        qrp: u8,     // 0:保留, 1:进程复位, 2:复位事件缓冲
    }
}

// InterrogationCmd send a new interrogation command [C_IC_NA_1]. 总召唤命令, 只有单个信息对象(SQ = 0)
// [C_IC_NA_1] See companion standard 101, subclass 7.3.4.1
// 传送原因(cot)用于
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
pub fn interrogation_cmd(
    cot: CauseOfTransmission,
    ca: CommonAddr,
    qoi: ObjectQOI,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    let cause = cot.cause().get();

    if !(cause == Cause::Activation || cause == Cause::Deactivation) {
        return Err(Error::ErrCmdCause(cot));
    }

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(InfoObjAddr::new(0, INFO_OBJ_ADDR_IRRELEVANT).raw().value())?;
    buf.write_u8(qoi.raw())?;

    Ok(Asdu {
        identifier: Identifier {
            type_id: TypeID::C_IC_NA_1,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// CounterInterrogationCmd send Counter Interrogation command [C_CI_NA_1]，计数量召唤命令，只有单个信息对象(SQ = 0)
// [C_CI_NA_1] See companion standard 101, subclass 7.3.4.2
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// 监视方向：
// <7> := 激活确认
// <10> := 激活终止
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn counter_interrogation_cmd(
    cot: CauseOfTransmission,
    ca: CommonAddr,
    qcc: ObjectQCC,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    cot.cause().set(Cause::Activation);

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(InfoObjAddr::new(0, INFO_OBJ_ADDR_IRRELEVANT).raw().value())?;
    buf.write_u8(qcc.raw())?;

    Ok(Asdu {
        identifier: Identifier {
            type_id: TypeID::C_CI_NA_1,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// ReadCmd send read command [C_RD_NA_1], 读命令, 只有单个信息对象(SQ = 0)
// [C_RD_NA_1] See companion standard 101, subclass 7.3.4.3
// 传送原因(coa)用于
// 控制方向：
// <5> := 请求
// 监视方向：
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn read_cmd(cot: CauseOfTransmission, ca: CommonAddr, ioa: InfoObjAddr) -> Result<Asdu, Error> {
    let mut cot = cot;
    cot.cause().set(Cause::Request);

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(ioa.raw().value())?;

    Ok(Asdu {
        identifier: Identifier {
            type_id: TypeID::C_RD_NA_1,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// ClockSynchronizationCmd send clock sync command [C_CS_NA_1],时钟同步命令, 只有单个信息对象(SQ = 0)
// [C_CS_NA_1] See companion standard 101, subclass 7.3.4.4
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// 监视方向：
// <7> := 激活确认
// <10> := 激活终止
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn clock_synchronization_cmd(
    cot: CauseOfTransmission,
    ca: CommonAddr,
    time: DateTime<Utc>,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    cot.cause().set(Cause::Activation);

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(InfoObjAddr::new(0, INFO_OBJ_ADDR_IRRELEVANT).raw().value())?;
    buf.extend_from_slice(&cp56time2a(time));

    Ok(Asdu {
        identifier: Identifier {
            type_id: TypeID::C_CS_NA_1,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// TestCommand send test command [C_TS_NA_1]，测试命令, 只有单个信息对象(SQ = 0)
// [C_TS_NA_1] See companion standard 101, subclass 7.3.4.5
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// 监视方向：
// <7> := 激活确认
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn test_command(cot: CauseOfTransmission, ca: CommonAddr) -> Result<Asdu, Error> {
    let mut cot = cot;
    cot.cause().set(Cause::Activation);

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(InfoObjAddr::new(0, INFO_OBJ_ADDR_IRRELEVANT).raw().value())?;
    buf.write_u16::<LittleEndian>(FBPTEST_WORD)?;

    Ok(Asdu {
        identifier: Identifier {
            type_id: TypeID::C_TS_NA_1,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// ResetProcessCmd send reset process command [C_RP_NA_1],复位进程命令, 只有单个信息对象(SQ = 0)
// [C_RP_NA_1] See companion standard 101, subclass 7.3.4.6
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// 监视方向：
// <7> := 激活确认
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn reset_process_cmd(
    cot: CauseOfTransmission,
    ca: CommonAddr,
    qrp: QualifierOfResetProcessCmd,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    cot.cause().set(Cause::Activation);

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(InfoObjAddr::new(0, INFO_OBJ_ADDR_IRRELEVANT).raw().value())?;
    buf.write_u8(qrp)?;

    Ok(Asdu {
        identifier: Identifier {
            type_id: TypeID::C_RP_NA_1,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// DelayAcquireCommand send delay acquire command [C_CD_NA_1],延时获得命令, 只有单个信息对象(SQ = 0)
// [C_CD_NA_1] See companion standard 101, subclass 7.3.4.7
// 传送原因(coa)用于
// 控制方向：
// <3> := 突发
// <6> := 激活
// 监视方向：
// <7> := 激活确认
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn delay_acquire_command(
    cot: CauseOfTransmission,
    ca: CommonAddr,
    msec: u16,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    let cause = cot.cause().get();

    if !(cause == Cause::Spontaneous || cause == Cause::Activation) {
        return Err(Error::ErrCmdCause(cot));
    }

    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(InfoObjAddr::new(0, INFO_OBJ_ADDR_IRRELEVANT).raw().value())?;
    buf.extend_from_slice(&cp16time2a_from_msec(msec));

    Ok(Asdu {
        identifier: Identifier {
            type_id: TypeID::C_CD_NA_1,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

// TestCommandCP56Time2a send test command [C_TS_TA_1]，测试命令, 只有单个信息对象(SQ = 0)
// 传送原因(coa)用于
// 控制方向：
// <6> := 激活
// 监视方向：
// <7> := 激活确认
// <44> := 未知的类型标识
// <45> := 未知的传送原因
// <46> := 未知的应用服务数据单元公共地址
// <47> := 未知的信息对象地址
pub fn test_command_cp56time2a(
    cot: CauseOfTransmission,
    ca: CommonAddr,
    time: DateTime<Utc>,
) -> Result<Asdu, Error> {
    let mut cot = cot;
    cot.cause().set(Cause::Activation);
    let variable_struct = VariableStruct::new(u1::new(0).unwrap(), u7::new(1).unwrap());

    let mut buf = vec![];
    buf.write_u24::<LittleEndian>(InfoObjAddr::new(0, INFO_OBJ_ADDR_IRRELEVANT).raw().value())?;
    buf.write_u16::<LittleEndian>(FBPTEST_WORD)?;
    buf.extend_from_slice(&cp56time2a(time));

    Ok(Asdu {
        identifier: Identifier {
            type_id: TypeID::C_CD_NA_1,
            variable_struct,
            cot,
            orig_addr: 0,
            common_addr: ca,
        },
        raw: Bytes::from(buf),
    })
}

impl Asdu {
    // GetInterrogationCmd [C_IC_NA_1] 获取总召唤信息体(信息对象地址，召唤限定词)
    pub fn get_interrogation_cmd(&mut self) -> Result<(InfoObjAddr, ObjectQOI)> {
        let mut rdr = Cursor::new(&self.raw);
        Ok((
            InfoObjAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap(),
            ObjectQOI::try_from(rdr.read_u8()?).unwrap(),
        ))
    }

    // [C_CI_NA_1] 获得计量召唤信息体(信息对象地址，计量召唤限定词)
    pub fn get_counter_interrogation_cmd(&mut self) -> Result<(InfoObjAddr, ObjectQCC)> {
        let mut rdr = Cursor::new(&self.raw);
        Ok((
            InfoObjAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap(),
            ObjectQCC::try_from(rdr.read_u8()?).unwrap(),
        ))
    }

    // GetResetProcessCmd [C_RP_NA_1] 获得复位进程命令信息体(信息对象地址,复位进程命令限定词)
    pub fn get_reset_process_cmd(&mut self) -> Result<(InfoObjAddr, ObjectQRP)> {
        let mut rdr = Cursor::new(&self.raw);
        Ok((
            InfoObjAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap(),
            ObjectQRP::try_from(rdr.read_u8()?).unwrap(),
        ))
    }
}
