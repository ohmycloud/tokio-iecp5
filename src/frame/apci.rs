use super::asdu::ASDU_SIZE_MAX;

pub const START_FRAME: u8 = 0x68; // 启动字符

// APDU form Max size 255
//      |              APCI                   |       ASDU         |
//      | start | APDU length | control field |       ASDU         |
//                       |          APDU field size(253)           |
// bytes|    1  |    1   |        4           |                    |
pub const APCI_FIELD_SIZE: usize = 6;
pub const APCICTL_FIELD_SIZE: usize = 6;
pub const APDU_SIZE_MAX: usize = 255;
pub const APDU_FIELD_SIZE_MAX: usize = APCICTL_FIELD_SIZE + ASDU_SIZE_MAX;

// U帧 控制域功能
pub const U_STARTDT_ACTIVE: u8 = 0x04; // 启动激活
pub const U_STARTDT_CONFIRM: u8 = 0x08; // 启动确认
pub const U_STOPDT_ACTIVE: u8 = 0x10; // 停止激活
pub const U_STOPDT_CONFIRM: u8 = 0x20; // 停止确认
pub const U_TESTFR_ACTIVE: u8 = 0x40; // 测试激活
pub const U_TESTFR_CONFIRM: u8 = 0x80; // 测试确认

#[derive(Debug)]
pub struct Apci {
    pub start: u8,
    pub apdu_length: u8,
    pub ctrl1: u8,
    pub ctrl2: u8,
    pub ctrl3: u8,
    pub ctrl4: u8,
}

#[derive(Debug)]
pub struct IApci {
    pub send_sn: u16,
    pub rcv_sn: u16,
}

#[derive(Debug)]
pub struct UApci {
    pub function: u8,
}

#[derive(Debug)]
pub struct SApci {
    pub rcv_sn: u16,
}
