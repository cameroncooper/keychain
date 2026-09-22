use std::collections::BTreeMap;

use crate::{Error, Result};

pub const MAX_PROTO_SIZE: usize = 64 * 1024 * 1024;
pub const MAX_FIELD_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_FIELDS: usize = 200_000;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Varint(u64),
    Bytes(Vec<u8>),
    Fixed64(u64),
    Fixed32(u32),
}

pub type Fields = BTreeMap<u32, Vec<Value>>;

pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        out.push(byte | if value == 0 { 0 } else { 0x80 });
        if value == 0 {
            return out;
        }
    }
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut shift = 0_u32;
    let mut value = 0_u64;
    loop {
        let byte = *data
            .get(*pos)
            .ok_or_else(|| Error::InvalidData("truncated protobuf varint".into()))?;
        *pos += 1;
        if shift >= 64 && byte & 0x7f != 0 {
            return Err(Error::InvalidData("protobuf varint overflow".into()));
        }
        value |= u64::from(byte & 0x7f) << shift.min(63);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 70 {
            return Err(Error::InvalidData("protobuf varint is too long".into()));
        }
    }
}

pub fn decode_fields(data: &[u8]) -> Result<Fields> {
    if data.len() > MAX_PROTO_SIZE {
        return Err(Error::InvalidData(
            "protobuf message exceeds size limit".into(),
        ));
    }
    let mut pos = 0;
    let mut count = 0;
    let mut fields = Fields::new();
    while pos < data.len() {
        count += 1;
        if count > MAX_FIELDS {
            return Err(Error::InvalidData("protobuf has too many fields".into()));
        }
        let tag = read_varint(data, &mut pos)?;
        let field = u32::try_from(tag >> 3)
            .map_err(|_| Error::InvalidData("protobuf field number overflow".into()))?;
        if field == 0 {
            return Err(Error::InvalidData("protobuf field zero is invalid".into()));
        }
        let value = match tag & 7 {
            0 => Value::Varint(read_varint(data, &mut pos)?),
            1 => {
                let end = pos
                    .checked_add(8)
                    .ok_or_else(|| Error::InvalidData("protobuf offset overflow".into()))?;
                let bytes = data
                    .get(pos..end)
                    .ok_or_else(|| Error::InvalidData("truncated protobuf fixed64".into()))?;
                pos = end;
                Value::Fixed64(u64::from_le_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| Error::InvalidData("fixed64 size".into()))?,
                ))
            }
            2 => {
                let len = usize::try_from(read_varint(data, &mut pos)?)
                    .map_err(|_| Error::InvalidData("protobuf length overflow".into()))?;
                if len > MAX_FIELD_SIZE {
                    return Err(Error::InvalidData(
                        "protobuf field exceeds size limit".into(),
                    ));
                }
                let end = pos
                    .checked_add(len)
                    .ok_or_else(|| Error::InvalidData("protobuf offset overflow".into()))?;
                let bytes = data
                    .get(pos..end)
                    .ok_or_else(|| Error::InvalidData("truncated protobuf bytes".into()))?;
                pos = end;
                Value::Bytes(bytes.to_vec())
            }
            5 => {
                let end = pos
                    .checked_add(4)
                    .ok_or_else(|| Error::InvalidData("protobuf offset overflow".into()))?;
                let bytes = data
                    .get(pos..end)
                    .ok_or_else(|| Error::InvalidData("truncated protobuf fixed32".into()))?;
                pos = end;
                Value::Fixed32(u32::from_le_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| Error::InvalidData("fixed32 size".into()))?,
                ))
            }
            wire => {
                return Err(Error::InvalidData(format!(
                    "unsupported protobuf wire type {wire}"
                )));
            }
        };
        fields.entry(field).or_default().push(value);
    }
    Ok(fields)
}

pub fn first_bytes(fields: &Fields, field: u32) -> Option<&[u8]> {
    match fields.get(&field)?.first()? {
        Value::Bytes(value) => Some(value),
        _ => None,
    }
}

pub fn first_string(fields: &Fields, field: u32) -> Result<Option<String>> {
    first_bytes(fields, field)
        .map(|value| {
            std::str::from_utf8(value)
                .map(str::to_owned)
                .map_err(|_| Error::InvalidData(format!("protobuf field {field} is not UTF-8")))
        })
        .transpose()
}

pub fn first_u64(fields: &Fields, field: u32) -> Option<u64> {
    match fields.get(&field)?.first()? {
        Value::Varint(value) | Value::Fixed64(value) => Some(*value),
        Value::Fixed32(value) => Some(u64::from(*value)),
        Value::Bytes(_) => None,
    }
}

#[derive(Clone, Debug, Default)]
pub struct Writer {
    data: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    fn tag(mut self, field: u32, wire: u8) -> Self {
        self.data
            .extend_from_slice(&encode_varint((u64::from(field) << 3) | u64::from(wire)));
        self
    }
    pub fn uint64(mut self, field: u32, value: u64) -> Self {
        self = self.tag(field, 0);
        self.data.extend_from_slice(&encode_varint(value));
        self
    }
    pub fn bool(self, field: u32, value: bool) -> Self {
        self.uint64(field, u64::from(value))
    }
    pub fn bytes(mut self, field: u32, value: &[u8]) -> Self {
        self = self.tag(field, 2);
        self.data
            .extend_from_slice(&encode_varint(value.len() as u64));
        self.data.extend_from_slice(value);
        self
    }
    pub fn string(self, field: u32, value: &str) -> Self {
        self.bytes(field, value.as_bytes())
    }
    pub fn message(self, field: u32, value: &[u8]) -> Self {
        self.bytes(field, value)
    }
    pub fn finish(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_varints() {
        assert_eq!(encode_varint(0), [0]);
        assert_eq!(encode_varint(300), [0xac, 0x02]);
    }

    #[test]
    fn writer_round_trip() {
        let data = Writer::new().uint64(1, 150).string(2, "hello").finish();
        let fields = decode_fields(&data).unwrap_or_else(|e| panic!("decode: {e}"));
        assert_eq!(first_u64(&fields, 1), Some(150));
        assert_eq!(
            first_string(&fields, 2).unwrap_or_else(|e| panic!("string: {e}")),
            Some("hello".into())
        );
    }

    #[test]
    fn rejects_truncation() {
        assert!(decode_fields(&[0x0a, 0x05, 1]).is_err());
    }
}
