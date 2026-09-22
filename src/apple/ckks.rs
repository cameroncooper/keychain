use std::collections::BTreeMap;

use crate::Result;
use crate::proto::{Fields, Value, Writer, decode_fields, first_bytes, first_string, first_u64};

pub const KEYCHAIN_ZONES: &[&str] = &[
    "Passwords",
    "Manatee",
    "Engram",
    "SecureObjectSync",
    "ProtectedCloudStorage",
    "CreditCards",
    "ApplePay",
    "WiFi",
    "Home",
    "Groups",
    "Contacts",
    "Mail",
    "LimitedPeersAllowed",
    "SE-PTC",
    "Photos",
];

pub const OP_RETRIEVE_CHANGES: u64 = 213;
pub const FIELD_RETRIEVE_CHANGES: u32 = 213;
const ID_RECORD_ZONE: u64 = 6;
const ID_USER: u64 = 7;

#[derive(Clone, Debug, PartialEq)]
pub enum FieldValue {
    Bytes(Vec<u8>),
    String(String),
    Integer(i64),
    Double(f64),
    Date(f64),
    Reference(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub name: String,
    pub record_type: String,
    pub fields: BTreeMap<String, FieldValue>,
}

impl Record {
    pub fn string(&self, name: &str) -> Option<&str> {
        match self.fields.get(name)? {
            FieldValue::String(value) | FieldValue::Reference(value) => Some(value),
            _ => None,
        }
    }

    pub fn bytes(&self, name: &str) -> Option<&[u8]> {
        match self.fields.get(name)? {
            FieldValue::Bytes(value) => Some(value),
            _ => None,
        }
    }

    pub fn integer(&self, name: &str) -> Option<i64> {
        match self.fields.get(name)? {
            FieldValue::Integer(value) => Some(*value),
            _ => None,
        }
    }
}

fn identifier(name: &str, kind: u64) -> Vec<u8> {
    Writer::new().string(1, name).uint64(2, kind).finish()
}

pub fn record_zone_identifier(zone: &str, user_id: &str) -> Vec<u8> {
    Writer::new()
        .message(1, &identifier(zone, ID_RECORD_ZONE))
        .message(2, &identifier(user_id, ID_USER))
        .finish()
}

pub fn build_retrieve_changes_request(
    zone_identifier: &[u8],
    continuation: Option<&[u8]>,
    max_changes: u64,
) -> Vec<u8> {
    let mut writer = Writer::new();
    if let Some(token) = continuation {
        writer = writer.bytes(1, token);
    }
    writer
        .message(2, zone_identifier)
        .uint64(4, max_changes)
        .finish()
}

fn parse_value(raw: &[u8]) -> Result<Option<FieldValue>> {
    let fields = decode_fields(raw)?;
    if let Some(value) = first_bytes(&fields, 2) {
        return Ok(Some(FieldValue::Bytes(value.to_vec())));
    }
    if let Some(value) = first_string(&fields, 7)? {
        return Ok(Some(FieldValue::String(value)));
    }
    if let Some(value) = first_u64(&fields, 4) {
        return Ok(Some(FieldValue::Integer(value as i64)));
    }
    if let Some(value) = fixed64(&fields, 5) {
        return Ok(Some(FieldValue::Double(f64::from_bits(value))));
    }
    if let Some(date) = first_bytes(&fields, 6) {
        let date = decode_fields(date)?;
        if let Some(value) = fixed64(&date, 1) {
            return Ok(Some(FieldValue::Date(f64::from_bits(value))));
        }
    }
    if let Some(reference) = first_bytes(&fields, 9) {
        let reference = decode_fields(reference)?;
        if let Some(record_id) = first_bytes(&reference, 2) {
            let record_id = decode_fields(record_id)?;
            if let Some(identifier) = first_bytes(&record_id, 1) {
                let identifier = decode_fields(identifier)?;
                if let Some(name) = first_string(&identifier, 1)? {
                    return Ok(Some(FieldValue::Reference(name)));
                }
            }
        }
    }
    Ok(None)
}

pub fn parse_record(raw: &[u8]) -> Result<Record> {
    let fields = decode_fields(raw)?;
    let name = if let Some(record_id) = first_bytes(&fields, 2) {
        let record_id = decode_fields(record_id)?;
        if let Some(identifier) = first_bytes(&record_id, 1) {
            first_string(&decode_fields(identifier)?, 1)?.unwrap_or_default()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    let record_type = if let Some(kind) = first_bytes(&fields, 3) {
        first_string(&decode_fields(kind)?, 1)?.unwrap_or_default()
    } else {
        String::new()
    };
    let mut parsed = BTreeMap::new();
    for field in repeated_bytes(&fields, 7) {
        let field = decode_fields(field)?;
        let Some(identifier) = first_bytes(&field, 1) else {
            continue;
        };
        let Some(name) = first_string(&decode_fields(identifier)?, 1)? else {
            continue;
        };
        let Some(value) = first_bytes(&field, 2) else {
            continue;
        };
        if let Some(value) = parse_value(value)? {
            parsed.insert(name, value);
        }
    }
    Ok(Record {
        name,
        record_type,
        fields: parsed,
    })
}

#[derive(Clone, Debug)]
pub struct ChangesPage {
    pub records: Vec<Record>,
    pub continuation: Option<Vec<u8>>,
    pub status: u64,
}

pub fn parse_retrieve_changes_response(raw: &[u8]) -> Result<ChangesPage> {
    let fields = decode_fields(raw)?;
    let mut records = Vec::new();
    for change in repeated_bytes(&fields, 1) {
        let change = decode_fields(change)?;
        if let Some(record) = first_bytes(&change, 5) {
            records.push(parse_record(record)?);
        }
    }
    Ok(ChangesPage {
        records,
        continuation: first_bytes(&fields, 2).map(ToOwned::to_owned),
        status: first_u64(&fields, 4).unwrap_or_default(),
    })
}

fn fixed64(fields: &Fields, field: u32) -> Option<u64> {
    match fields.get(&field)?.first()? {
        Value::Fixed64(value) => Some(*value),
        _ => None,
    }
}

fn repeated_bytes(fields: &Fields, field: u32) -> impl Iterator<Item = &[u8]> {
    fields
        .get(&field)
        .into_iter()
        .flatten()
        .filter_map(|value| match value {
            Value::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_string(value: &str) -> Vec<u8> {
        Writer::new().uint64(1, 3).string(7, value).finish()
    }

    fn value_bytes(value: &[u8]) -> Vec<u8> {
        Writer::new().uint64(1, 1).bytes(2, value).finish()
    }

    fn value_integer(value: u64) -> Vec<u8> {
        Writer::new().uint64(1, 7).uint64(4, value).finish()
    }

    fn value_reference(name: &str) -> Vec<u8> {
        let identifier = Writer::new().string(1, name).finish();
        let record_identifier = Writer::new().message(1, &identifier).finish();
        let reference = Writer::new().message(2, &record_identifier).finish();
        Writer::new().uint64(1, 5).message(9, &reference).finish()
    }

    fn field(name: &str, value: &[u8]) -> Vec<u8> {
        Writer::new()
            .message(1, &identifier(name, 0))
            .message(2, value)
            .finish()
    }

    fn record(name: &str, kind: &str, fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let record_id = Writer::new().message(1, &identifier(name, 1)).finish();
        let kind = Writer::new().string(1, kind).finish();
        let mut writer = Writer::new().message(2, &record_id).message(3, &kind);
        for (name, value) in fields {
            writer = writer.message(7, &field(name, value));
        }
        writer.finish()
    }

    #[test]
    fn password_zones_are_present() {
        assert!(KEYCHAIN_ZONES.contains(&"Passwords"));
        assert!(KEYCHAIN_ZONES.contains(&"Manatee"));
    }

    #[test]
    fn retrieve_request_has_expected_fields() {
        let zone = record_zone_identifier("Passwords", "user");
        let raw = build_retrieve_changes_request(&zone, Some(b"next"), 500);
        let fields = decode_fields(&raw).unwrap_or_else(|e| panic!("decode: {e}"));
        assert_eq!(first_bytes(&fields, 1), Some(b"next".as_slice()));
        assert_eq!(first_u64(&fields, 4), Some(500));
    }

    #[test]
    fn parses_item_fields_and_reference_values() {
        let raw = record(
            "UUID-item",
            "item",
            &[
                ("wrappedkey", value_string("d3JhcA==")),
                ("data", value_bytes(b"\x00\x01iv+ct")),
                ("encver", value_integer(2)),
                ("parentkeyref", value_reference("classC-uuid")),
            ],
        );
        let parsed = parse_record(&raw).unwrap_or_else(|error| panic!("parse: {error}"));
        assert_eq!(parsed.name, "UUID-item");
        assert_eq!(parsed.record_type, "item");
        assert_eq!(parsed.string("wrappedkey"), Some("d3JhcA=="));
        assert_eq!(parsed.bytes("data"), Some(b"\x00\x01iv+ct".as_slice()));
        assert_eq!(parsed.integer("encver"), Some(2));
        assert_eq!(parsed.string("parentkeyref"), Some("classC-uuid"));
    }

    #[test]
    fn parses_change_page_and_continuation() {
        let item = record("item-1", "item", &[("encver", value_integer(2))]);
        let change = Writer::new().message(5, &item).finish();
        let response = Writer::new()
            .message(1, &change)
            .bytes(2, b"NEXT")
            .uint64(4, 1)
            .finish();
        let page = parse_retrieve_changes_response(&response)
            .unwrap_or_else(|error| panic!("parse: {error}"));
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.records[0].name, "item-1");
        assert_eq!(page.continuation.as_deref(), Some(b"NEXT".as_slice()));
        assert_eq!(page.status, 1);
    }
}
