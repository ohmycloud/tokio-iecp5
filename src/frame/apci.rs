use std::collections::VecDeque;

use crate::{asdu::IDENTIFIER_SIZE, client::SeqPending};

use super::{
    asdu::{Asdu, ASDU_SIZE_MAX},
    Apdu,
};

pub const START_FRAME: u8 = 0x68; // 启动字符

// APDU form Max size 255
//      |              APCI                   |       ASDU         |
//      | start | APDU length | control field |       ASDU         |
//                       |          APDU field size(253)           |
// bytes|    1  |    1   |        4           |                    |
pub const APCI_FIELD_SIZE: usize = 6;
pub const APCICTL_FIELD_SIZE: usize = 4;
pub const APDU_SIZE_MAX: usize = 255;
pub const APDU_FIELD_SIZE_MAX: usize = APCICTL_FIELD_SIZE + ASDU_SIZE_MAX;

// U帧 控制域功能
pub const U_STARTDT_ACTIVE: u8 = 0x04; // 启动激活
pub const U_STARTDT_CONFIRM: u8 = 0x08; // 启动确认
pub const U_STOPDT_ACTIVE: u8 = 0x10; // 停止激活
pub const U_STOPDT_CONFIRM: u8 = 0x20; // 停止确认
pub const U_TESTFR_ACTIVE: u8 = 0x40; // 测试激活
pub const U_TESTFR_CONFIRM: u8 = 0x80; // 测试确认

#[derive(Debug, Clone, Copy)]
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

pub enum ApciKind {
    I(IApci),
    U(UApci),
    S(SApci),
}

impl From<Apci> for ApciKind {
    fn from(apci: Apci) -> Self {
        if apci.ctrl1 & 0x01 == 0 {
            return ApciKind::I(IApci {
                send_sn: ((apci.ctrl1 as u16) >> 1) + ((apci.ctrl2 as u16) << 7),
                rcv_sn: ((apci.ctrl3 as u16) >> 1) + ((apci.ctrl4 as u16) << 7),
            });
        }

        if apci.ctrl1 & 0x03 == 0x01 {
            return ApciKind::S(SApci {
                rcv_sn: ((apci.ctrl3 as u16) >> 1) + ((apci.ctrl4 as u16) << 7),
            });
        }

        ApciKind::U(UApci {
            function: apci.ctrl1 & 0xfc,
        })
    }
}

pub fn new_iframe(asdu: Asdu, send_sn: u16, rcv_sn: u16) -> Apdu {
    let apci = Apci {
        start: START_FRAME,
        apdu_length: APCICTL_FIELD_SIZE as u8 + IDENTIFIER_SIZE as u8 + asdu.raw.len() as u8,
        ctrl1: (send_sn << 1) as u8,
        ctrl2: (send_sn >> 7) as u8,
        ctrl3: (rcv_sn << 1) as u8,
        ctrl4: (rcv_sn >> 7) as u8,
    };
    Apdu {
        apci,
        asdu: Some(asdu),
    }
}

pub fn new_sframe(rcv_sn: u16) -> Apdu {
    Apdu {
        apci: Apci {
            start: START_FRAME,
            apdu_length: APCICTL_FIELD_SIZE as u8,
            ctrl1: 0x01,
            ctrl2: 0x00,
            ctrl3: (rcv_sn << 1) as u8,
            ctrl4: (rcv_sn >> 7) as u8,
        },
        asdu: None,
    }
}

pub fn new_uframe(function: u8) -> Apdu {
    Apdu {
        apci: Apci {
            start: START_FRAME,
            apdu_length: APCICTL_FIELD_SIZE as u8,
            ctrl1: function | 0x03,
            ctrl2: 0x00,
            ctrl3: 0x00,
            ctrl4: 0x00,
        },
        asdu: None,
    }
}

fn seq_no_count(next_ack_no: u16, mut next_send_no: u16) -> u16 {
    if next_ack_no > next_send_no {
        next_send_no += 32768;
    }
    next_send_no - next_ack_no
}

pub fn update_ack_no_out(
    ack_no: u16,
    ack_sendsn: &mut u16,
    send_sn: &mut u16,
    pending: &mut VecDeque<SeqPending>,
) -> bool {
    if ack_no == *ack_sendsn {
        return true;
    }

    if seq_no_count(*ack_sendsn, *send_sn) < seq_no_count(ack_no, *send_sn) {
        return false;
    }

    for i in 0..pending.len() {
        if let Some(p) = pending.pop_front() {
            if p.seq == ack_no - 1 {
                break;
            }
        }
    }
    *ack_sendsn = ack_no;
    true
}
