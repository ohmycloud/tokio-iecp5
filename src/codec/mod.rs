use anyhow::{anyhow, bail, Result};
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
        let raw: Bytes = match apdu.asdu {
            Some(asdu) => asdu.try_into()?,
            None => Bytes::new(),
        };
        let length = 4 + raw.len();
        if length + 2 > APDU_SIZE_MAX || apci.apdu_length as usize != length {
            bail!(
                "APDU length does not match payload: {} / {length}",
                apci.apdu_length
            );
        }
        validate_control(apci, !raw.is_empty())?;
        buf.reserve(length + 2);
        buf.extend_from_slice(&[
            apci.start,
            apci.apdu_length,
            apci.ctrl1,
            apci.ctrl2,
            apci.ctrl3,
            apci.ctrl4,
        ]);
        buf.put_slice(&raw);
        Ok(())
    }
}

fn validate_control(apci: Apci, has_asdu: bool) -> Result<()> {
    if apci.start != START_FRAME {
        bail!("Invalid start frame: {}", apci.start);
    }
    match ApciKind::from(apci) {
        ApciKind::I(_) => {
            if !has_asdu || apci.ctrl3 & 1 != 0 {
                bail!("Invalid I-frame: missing ASDU or reserved receive bit set");
            }
        }
        ApciKind::S(_) => {
            if has_asdu
                || apci.apdu_length != 4
                || apci.ctrl1 != 1
                || apci.ctrl2 != 0
                || apci.ctrl3 & 1 != 0
            {
                bail!("Invalid S-frame control field or length");
            }
        }
        ApciKind::U(u) => {
            if has_asdu
                || apci.apdu_length != 4
                || apci.ctrl2 != 0
                || apci.ctrl3 != 0
                || apci.ctrl4 != 0
                || !matches!(u.function, 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80)
            {
                bail!("Invalid U-frame control field or length");
            }
        }
    }
    Ok(())
}

impl Decoder for Codec {
    type Item = Apdu;
    type Error = anyhow::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>> {
        if buf.len() < 2 {
            return Ok(None);
        }
        if buf[0] != START_FRAME {
            bail!("Invalid start frame: {}", buf[0]);
        }
        let len = buf[1] as usize + 2;
        if !(APCI_FIELD_SIZE..=APDU_SIZE_MAX).contains(&len) {
            return Err(anyhow!("Invalid APDU length: {len}"));
        }
        if buf.len() < len {
            return Ok(None);
        }
        let apci = Apci {
            start: buf[0],
            apdu_length: buf[1],
            ctrl1: buf[2],
            ctrl2: buf[3],
            ctrl3: buf[4],
            ctrl4: buf[5],
        };
        validate_control(apci, len > APCI_FIELD_SIZE)?;
        let frame = buf.split_to(len).freeze();
        let asdu = if matches!(ApciKind::from(apci), ApciKind::I(_)) {
            // A malformed ASDU must not silently become an empty I-frame.
            Some(frame.slice(APCI_FIELD_SIZE..).try_into()?)
        } else {
            None
        };
        Ok(Some(Apdu { apci, asdu }))
    }
}
