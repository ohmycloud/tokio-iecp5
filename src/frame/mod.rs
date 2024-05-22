pub mod apci;
pub mod asdu;
pub mod cproc;
pub mod csys;
pub mod mproc;
pub mod msys;

use self::{apci::Apci, asdu::Asdu};

#[derive(Debug)]
pub struct Apdu {
    pub apci: Apci,
    pub apdu: Asdu,
}
