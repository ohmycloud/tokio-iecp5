//! Strict hexadecimal parsing and streaming-frame inspection, shared by tools.
use crate::{Apdu, Codec};
use anyhow::{bail, Result};
use bytes::BytesMut;
use tokio_util::codec::Decoder;

pub fn parse_hex(input: &str) -> Result<Vec<u8>> {
    let mut hex = String::new();
    for c in input.chars() {
        if c.is_ascii_hexdigit() {
            hex.push(c);
        } else if !c.is_whitespace() && !matches!(c, '[' | ']' | ':' | '-' | '_') {
            bail!("非法十六进制字符: {c}");
        }
    }
    if hex.is_empty() || hex.len() & 1 != 0 {
        bail!("请输入非空、偶数位的十六进制字节");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| Ok(u8::from_str_radix(&hex[i..i + 2], 16)?))
        .collect()
}

pub fn inspect_frames(input: &str) -> Result<Vec<Apdu>> {
    let bytes = parse_hex(input)?;
    let mut buf = BytesMut::from(bytes.as_slice());
    let mut frames = vec![];
    while let Some(frame) = Codec.decode(&mut buf)? {
        frames.push(frame);
    }
    if !buf.is_empty() {
        bail!("报文不完整，剩余 {} 字节", buf.len());
    }
    Ok(frames)
}
