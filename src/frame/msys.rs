use std::io::Cursor;

use anyhow::Result;
use bit_struct::*;
use byteorder::{LittleEndian, ReadBytesExt};

use super::asdu::{Asdu, ObjectAddr};

// 在监视方向系统信息的应用服务数据单元

// 初始化原因
bit_struct! {
    pub struct ObjectCOI(u8) {
        cause: u7, // 0: 电源上电, 1:手动复位, 2:远方复位
        flag: u1,  // 是否改变了当地参数
    }
}

impl Asdu {
    // GetEndOfInitialization get GetEndOfInitialization for asdu when the identification [M_EI_NA_1]
    fn get_end_of_initialization(&mut self) -> Result<(ObjectAddr, ObjectCOI)> {
        let mut rdr = Cursor::new(&self.raw);
        Ok((
            ObjectAddr::try_from(u24::new(rdr.read_u24::<LittleEndian>()?).unwrap()).unwrap(),
            ObjectCOI::try_from(rdr.read_u8()?).unwrap(),
        ))
    }
}
