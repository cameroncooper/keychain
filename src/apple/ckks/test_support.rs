//! Synthetic wire fixtures only; not a production CloudKit write encoder.
use super::*;

pub fn server_record(record: &Record, zone: &ZoneIdentity, tag: &str) -> Result<Record> {
    let record_id = Writer::new()
        .message(1, &identifier(&record.name, 1))
        .message(2, &record_zone_identifier(&zone.name, &zone.owner))
        .finish();
    let mut wire = Writer::new()
        .string(1, tag)
        .message(2, &record_id)
        .message(3, &Writer::new().string(1, &record.record_type).finish());
    for (name, value) in &record.fields {
        let value = match value {
            FieldValue::Bytes(value) => Writer::new().bytes(2, value).finish(),
            FieldValue::String(value) => Writer::new().string(7, value).finish(),
            FieldValue::Integer(value) => Writer::new().uint64(4, *value as u64).finish(),
            FieldValue::Reference(value) => Writer::new()
                .message(
                    9,
                    &Writer::new()
                        .message(
                            2,
                            &Writer::new()
                                .message(1, &identifier(value, 1))
                                .message(2, &record_zone_identifier(&zone.name, &zone.owner))
                                .finish(),
                        )
                        .finish(),
                )
                .finish(),
            _ => {
                return Err(Error::InvalidData(
                    "unsupported synthetic fixture field".into(),
                ));
            }
        };
        wire = wire.message(
            7,
            &Writer::new()
                .message(1, &Writer::new().string(1, name).finish())
                .message(2, &value)
                .finish(),
        );
    }
    parse_record(&wire.bytes(999, b"opaque future server metadata").finish())
}
