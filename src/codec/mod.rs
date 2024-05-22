use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::frame::{
    apci::{Apci, IApci, SApci, UApci, APCI_FIELD_SIZE, APDU_SIZE_MAX, START_FRAME},
    asdu::Asdu,
    Apdu,
};

#[derive(Debug, PartialEq, Default)]
pub(crate) struct ApciDecoder;

#[derive(Debug, PartialEq, Default)]
pub struct Codec {
    pub decoder: ApciDecoder,
}

pub enum ApciKind {
    I(IApci),
    U(UApci),
    S(SApci),
}

impl Encoder<Apdu> for Codec {
    type Error = anyhow::Error;

    fn encode(&mut self, item: Apdu, dst: &mut BytesMut) -> Result<()> {
        todo!()
    }
}

impl Decoder for Codec {
    type Item = (ApciKind, Option<Asdu>);

    type Error = anyhow::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>> {
        if let Some((apci, asdu_data)) = self.decoder.decode(buf)? {
            match apci {
                ApciKind::I(_) => Ok(Some((apci, Some(asdu_data.try_into()?)))),
                ApciKind::S(_) => Ok(Some((apci, None))),
                ApciKind::U(_) => Ok(Some((apci, None))),
            }
        } else {
            Ok(None)
        }
    }
}

impl Decoder for ApciDecoder {
    type Item = (ApciKind, Bytes);

    type Error = anyhow::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<(ApciKind, Bytes)>> {
        if buf.len() < APCI_FIELD_SIZE {
            return Ok(None);
        }
        let len = buf[1] as usize + 2;
        if !(APCI_FIELD_SIZE..=APDU_SIZE_MAX).contains(&len) {
            return Err(anyhow!("Invalid APDU length:{}", len));
        }

        if buf.len() < len {
            return Ok(None);
        }
        let apci_data = buf.split_to(APCI_FIELD_SIZE);
        if apci_data[0] != START_FRAME {
            return Err(anyhow!("Invalid start frame:{}", apci_data[0]));
        }
        let apci = Apci {
            start: apci_data[0],
            apdu_length: apci_data[1],
            ctrl1: apci_data[2],
            ctrl2: apci_data[3],
            ctrl3: apci_data[4],
            ctrl4: apci_data[5],
        };

        let asdu_data = buf.split_to(len - APCI_FIELD_SIZE).freeze();

        if apci.ctrl1 & 0x01 == 0 {
            return Ok(Some((
                ApciKind::I(IApci {
                    send_sn: ((apci.ctrl1 as u16) >> 1) + ((apci.ctrl2 as u16) << 7),
                    rcv_sn: ((apci.ctrl3 as u16) >> 1) + ((apci.ctrl4 as u16) << 7),
                }),
                asdu_data,
            )));
        }

        if apci.ctrl1 & 0x03 == 0x01 {
            return Ok(Some((
                ApciKind::S(SApci {
                    rcv_sn: ((apci.ctrl3 as u16) >> 1) + ((apci.ctrl4 as u16) << 7),
                }),
                asdu_data,
            )));
        }

        Ok(Some((
            (ApciKind::U(UApci {
                function: apci.ctrl1 & 0xfc,
            })),
            asdu_data,
        )))
    }
}

#[cfg(test)]
mod tests {
    use crate::frame::apci::U_STARTDT_ACTIVE;

    use super::*;

    pub struct Args {
        apdu: Bytes,
    }

    #[test]
    fn decode_iapci() {
        let mut codec = ApciDecoder;
        let mut buf = BytesMut::from(&[START_FRAME, 0x04, 0x02, 0x00, 0x03, 0x00][..]);
        let (apci, asdu_data) = codec.decode(&mut buf).unwrap().unwrap();
        match apci {
            ApciKind::I(apci) => {
                assert_eq!(apci.send_sn, 0x01);
                assert_eq!(apci.rcv_sn, 0x01);
                assert!(asdu_data.is_empty())
            }
            _ => panic!(),
        }
    }

    #[test]
    fn decode_sapci() {
        let mut codec = ApciDecoder;
        let mut buf = BytesMut::from(&[START_FRAME, 0x04, 0x01, 0x00, 0x02, 0x00][..]);
        let (apci, asdu_data) = codec.decode(&mut buf).unwrap().unwrap();
        match apci {
            ApciKind::S(apci) => {
                assert_eq!(apci.rcv_sn, 0x01);
                assert!(asdu_data.is_empty())
            }
            _ => panic!(),
        }
    }

    #[test]
    fn decode_uapci() {
        let mut codec = ApciDecoder;
        let mut buf = BytesMut::from(&[START_FRAME, 0x04, 0x07, 0x00, 0x00, 0x00][..]);
        let (apci, asdu_data) = codec.decode(&mut buf).unwrap().unwrap();
        match apci {
            ApciKind::U(apci) => {
                assert_eq!(apci.function, U_STARTDT_ACTIVE);
                assert!(asdu_data.is_empty())
            }
            _ => panic!(),
        }
    }
}
