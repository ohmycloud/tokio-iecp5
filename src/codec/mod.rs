use anyhow::{anyhow, Result};
use bytes::{BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::frame::{
    apci::{Apci, ApciKind, APCI_FIELD_SIZE, APDU_SIZE_MAX, START_FRAME},
    Apdu,
};

#[derive(Debug, PartialEq, Default)]
pub struct Codec;

impl Encoder<Apdu> for Codec {
    type Error = anyhow::Error;

    fn encode(&mut self, apdu: Apdu, buf: &mut BytesMut) -> Result<()> {
        let apci = apdu.apci;

        buf.put_u8(apci.start);
        buf.put_u8(apci.apdu_length);
        buf.put_u8(apci.ctrl1);
        buf.put_u8(apci.ctrl2);
        buf.put_u8(apci.ctrl3);
        buf.put_u8(apci.ctrl4);

        if let Some(asdu) = apdu.asdu {
            let asdu_raw: Bytes = asdu.try_into()?;
            buf.extend(asdu_raw);
        }

        Ok(())
    }
}

impl Decoder for Codec {
    type Item = Apdu;

    type Error = anyhow::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>> {
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

        let apci_kind = apci.into();

        match apci_kind {
            ApciKind::I(_) => {
                let asdu_data = buf.split_to(len - APCI_FIELD_SIZE).freeze();
                let asdu = asdu_data.try_into();

                if asdu.is_err() {
                    return Ok(Some(Apdu { apci, asdu: None }));
                }

                Ok(Some(Apdu {
                    apci,
                    asdu: Some(asdu?),
                }))
            }
            _ => Ok(Some(Apdu { apci, asdu: None })),
        }
    }
}
