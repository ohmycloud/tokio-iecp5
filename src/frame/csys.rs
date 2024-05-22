use std::io::Cursor;

use anyhow::Result;
use bit_struct::*;
use byteorder::{LittleEndian, ReadBytesExt};

use super::asdu::{Asdu, ObjectAddr};

// 在控制方向系统信息的应用服务数据单元

// 数据召唤限定词
bit_struct! {
    pub struct ObjectQOI(u8) {
        range: u8,   // 范围: 0~19:保留, 20:全站, 21~36:第1~16组, 37~255:保留
    }
}

// QCC: 累计召回限定词
bit_struct! {
    pub struct ObjectQCC(u8) {
        qcc: u8,
    }
}

// 复位进程命令限定词
bit_struct! {
    pub struct ObjectQRP(u8) {
        qrp: u8,     // 0:保留, 1:进程复位, 2:复位事件缓冲
    }
}

impl Asdu {
    // GetInterrogationCmd [C_IC_NA_1] 获取总召唤信息体(信息对象地址，召唤限定词)
    pub fn get_interrogation_cmd(&mut self) -> Result<(ObjectAddr, ObjectQOI)> {
        let mut rdr = Cursor::new(&self.raw);
        Ok((
            ObjectAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap(),
            ObjectQOI::try_from(rdr.read_u8()?).unwrap(),
        ))
    }

    // [C_CI_NA_1] 获得计量召唤信息体(信息对象地址，计量召唤限定词)
    pub fn get_counter_interrogation_cmd(&mut self) -> Result<(ObjectAddr, ObjectQCC)> {
        let mut rdr = Cursor::new(&self.raw);
        Ok((
            ObjectAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap(),
            ObjectQCC::try_from(rdr.read_u8()?).unwrap(),
        ))
    }

    // GetResetProcessCmd [C_RP_NA_1] 获得复位进程命令信息体(信息对象地址,复位进程命令限定词)
    pub fn get_reset_process_cmd(&mut self) -> Result<(ObjectAddr, ObjectQRP)> {
        let mut rdr = Cursor::new(&self.raw);
        Ok((
            ObjectAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap(),
            ObjectQRP::try_from(rdr.read_u8()?).unwrap(),
        ))
    }
}
