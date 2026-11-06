//! Private-key bytes never enter plist's owned event table. Serialize a zero
//! placeholder first, locate its bounded binary-plist data object, then replace
//! it only in protected memory. This accepts flat creation items, not arbitrary
//! archived Apple plists. Format reference: Apple's CFBinaryPList.c.
use crate::{Error, Result};
use keychain_sep_driver::memory::LockedBuffer;
use std::io::{self, Write};
use std::ops::Range;

pub(super) const CAPACITY: usize = 64 * 1024;
pub(super) struct Plaintext {
    memory: LockedBuffer<CAPACITY>,
    length: usize,
}
impl Plaintext {
    pub fn new() -> Result<Self> {
        Ok(Self {
            memory: LockedBuffer::new().map_err(|e| Error::io("CKKS plaintext memory", e))?,
            length: 0,
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.memory.as_array()[..self.length]
    }
    pub fn buffer(&mut self) -> &mut [u8] {
        self.memory.as_mut_array()
    }
    pub fn len(&self) -> usize {
        self.length
    }
}
impl Write for Plaintext {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > (CAPACITY - 40).saturating_sub(self.length) {
            return Err(io::Error::other("CKKS protected plaintext exceeds limit"));
        }
        self.memory.as_mut_array()[self.length..self.length + data.len()].copy_from_slice(data);
        self.length += data.len();
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn invalid() -> Error {
    Error::InvalidData("unsupported or malformed flat CKKS binary plist".into())
}
fn number(bytes: &[u8]) -> Result<usize> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(invalid());
    }
    let mut value = 0usize;
    for byte in bytes {
        value = value
            .checked_mul(256)
            .and_then(|v| v.checked_add(usize::from(*byte)))
            .ok_or_else(invalid)?;
    }
    Ok(value)
}
fn length(data: &[u8], offset: usize, limit: usize) -> Result<(usize, usize)> {
    let marker = *data.get(offset).ok_or_else(invalid)?;
    let mut cursor = offset + 1;
    let length = if marker & 15 != 15 {
        usize::from(marker & 15)
    } else {
        let integer = *data.get(cursor).ok_or_else(invalid)?;
        if integer >> 4 != 1 || integer & 15 > 3 {
            return Err(invalid());
        }
        cursor += 1;
        let width = 1usize << (integer & 15);
        let end = cursor
            .checked_add(width)
            .filter(|end| *end <= limit)
            .ok_or_else(invalid)?;
        let value = number(data.get(cursor..end).ok_or_else(invalid)?)?;
        cursor = end;
        value
    };
    Ok((length, cursor))
}

pub(super) fn secret_range(data: &[u8]) -> Result<Range<usize>> {
    if data.len() < 40 || data.len() > CAPACITY || &data[..8] != b"bplist00" {
        return Err(invalid());
    }
    let trailer = &data[data.len() - 32..];
    let offset_width = usize::from(trailer[6]);
    let reference_width = usize::from(trailer[7]);
    let count = number(&trailer[8..16])?;
    let root = number(&trailer[16..24])?;
    let table = number(&trailer[24..32])?;
    if !(1..=8).contains(&offset_width)
        || !(1..=8).contains(&reference_width)
        || !(1..=4096).contains(&count)
        || root >= count
        || table < 8
        || count
            .checked_mul(offset_width)
            .and_then(|len| table.checked_add(len))
            != Some(data.len() - 32)
    {
        return Err(invalid());
    }
    let mut offsets = Vec::with_capacity(count);
    for index in 0..count {
        let start = table + index * offset_width;
        let offset = number(data.get(start..start + offset_width).ok_or_else(invalid)?)?;
        if !(8..table).contains(&offset) {
            return Err(invalid());
        }
        offsets.push(offset);
    }
    let mut order = offsets.clone();
    order.sort_unstable();
    if order.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid());
    }
    // Validate object extents before borrowing any data. Overlapping objects,
    // nested collections and cyclic references are not creation-item formats.
    for (index, offset) in order.iter().enumerate() {
        let limit = order.get(index + 1).copied().unwrap_or(table);
        let marker = data[*offset];
        let end = match marker {
            0x08 | 0x09 => offset + 1,
            0x10..=0x13 | 0x22 | 0x23 | 0x33 => offset + 1 + (1usize << (marker & 15)),
            _ if matches!(marker >> 4, 4 | 5 | 6 | 13) => {
                let (count, start) = length(data, *offset, limit)?;
                let width = match marker >> 4 {
                    6 => 2,
                    13 => {
                        if *offset != offsets[root] || count > 128 {
                            return Err(invalid());
                        }
                        2 * reference_width
                    }
                    _ => 1,
                };
                count
                    .checked_mul(width)
                    .and_then(|len| start.checked_add(len))
                    .ok_or_else(invalid)?
            }
            _ => return Err(invalid()),
        };
        if end > limit {
            return Err(invalid());
        }
    }
    let root_offset = offsets[root];
    if data[root_offset] >> 4 != 13 {
        return Err(invalid());
    }
    let (fields, start) = length(data, root_offset, table)?;
    let reference = |index: usize| -> Result<usize> {
        let offset = start + index * reference_width;
        let id = number(
            data.get(offset..offset + reference_width)
                .ok_or_else(invalid)?,
        )?;
        offsets.get(id).copied().ok_or_else(invalid)
    };
    let mut names = std::collections::BTreeSet::new();
    let mut secret = None;
    for index in 0..fields {
        let key = reference(index)?;
        if data[key] >> 4 != 5 {
            return Err(invalid());
        }
        let (size, position) = length(data, key, table)?;
        let name = data.get(position..position + size).ok_or_else(invalid)?;
        if !names.insert(name) {
            return Err(invalid());
        }
        let value = reference(index + fields)?;
        if data[value] >> 4 == 13 {
            return Err(invalid());
        }
        if name == b"v_Data" {
            if data[value] >> 4 != 4 {
                return Err(invalid());
            }
            let (size, position) = length(data, value, table)?;
            if size != 97 {
                return Err(invalid());
            }
            secret = Some(position..position + size);
        }
    }
    secret.ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> plist::Dictionary {
        let mut fields = plist::Dictionary::new();
        fields.insert("v_Data".into(), plist::Value::Data(vec![0; 97]));
        fields.insert("label".into(), plist::Value::String("鍵 🔑".repeat(200)));
        fields.insert("sync".into(), plist::Value::Boolean(true));
        fields.insert("version".into(), plist::Value::Integer(2.into()));
        fields
    }

    #[test]
    fn inserts_and_redacts_only_the_borrowed_private_data() -> Result<()> {
        let fields = fixture();
        let mut output = Plaintext::new()?;
        plist::to_writer_binary(&mut output, &fields)?;
        let range = secret_range(output.bytes())?;
        assert_eq!(range.len(), 97);
        assert!(output.bytes()[range.clone()].iter().all(|byte| *byte == 0));
        output.buffer()[range.clone()].fill(0x42);
        let with_secret = plist::Value::from_reader(io::Cursor::new(output.bytes()))?;
        assert_eq!(
            with_secret
                .as_dictionary()
                .and_then(|d| d.get("v_Data"))
                .and_then(plist::Value::as_data),
            Some(&[0x42; 97][..])
        );
        output.buffer()[range].fill(0);
        assert_eq!(
            plist::Value::from_reader(io::Cursor::new(output.bytes()))?,
            plist::Value::Dictionary(fields)
        );
        Ok(())
    }

    #[test]
    fn rejects_missing_wrong_type_nested_and_malformed_data() -> Result<()> {
        for value in [
            None,
            Some(plist::Value::Data(vec![0; 96])),
            Some(plist::Value::String("wrong".into())),
            Some(plist::Value::Array(vec![])),
        ] {
            let mut fields = fixture();
            fields.remove("v_Data");
            if let Some(value) = value {
                fields.insert("v_Data".into(), value);
            }
            let mut bytes = Vec::new();
            plist::to_writer_binary(&mut bytes, &fields)?;
            assert!(secret_range(&bytes).is_err());
        }
        let mut bytes = Vec::new();
        plist::to_writer_binary(&mut bytes, &fixture())?;
        for length in 0..bytes.len() {
            assert!(secret_range(&bytes[..length]).is_err());
        }
        let trailer = bytes.len() - 32;
        for index in [
            trailer + 6,
            trailer + 7,
            trailer + 8,
            trailer + 16,
            trailer + 24,
        ] {
            let mut broken = bytes.clone();
            broken[index] = 255;
            assert!(secret_range(&broken).is_err());
        }
        let width = usize::from(bytes[trailer + 6]);
        let table = number(&bytes[trailer + 24..trailer + 32])?;
        let mut alias = bytes.clone();
        alias.copy_within(table..table + width, table + width);
        assert!(secret_range(&alias).is_err());
        // Deterministic adversarial mutations exercise every object/table byte.
        // Some remain valid; none may panic or return an out-of-bounds range.
        for index in 0..bytes.len() {
            for mask in [1, 0x80, 0xff] {
                let mut mutated = bytes.clone();
                mutated[index] ^= mask;
                if let Ok(range) = secret_range(&mutated) {
                    assert_eq!(range.len(), 97);
                    assert!(range.end <= mutated.len());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn writer_reserves_padding_without_partial_overflow() -> Result<()> {
        let mut output = Plaintext::new()?;
        output
            .write_all(&vec![0x21; CAPACITY - 40])
            .map_err(|e| Error::io("test writer", e))?;
        assert!(output.write_all(&[1]).is_err());
        assert_eq!(output.len(), CAPACITY - 40);
        assert!(output.bytes().iter().all(|byte| *byte == 0x21));
        Ok(())
    }
}
