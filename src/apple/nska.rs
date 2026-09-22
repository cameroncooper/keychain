//! Minimal, bounded `NSKeyedArchiver` object-graph expansion.

use std::collections::BTreeSet;
use std::io::Cursor;

use plist::{Dictionary, Uid, Value};

use crate::{Error, Result};

const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBJECTS: usize = 100_000;
const MAX_DEPTH: usize = 128;

fn uid(value: u64) -> Value {
    Value::Uid(Uid::new(value))
}

pub fn archive_ies_ciphertext(
    ephemeral_sender_public: &[u8],
    ciphertext: &[u8],
    authentication_code: &[u8],
) -> Result<Vec<u8>> {
    let mut padded_ciphertext = ciphertext.to_vec();
    padded_ciphertext.resize(padded_ciphertext.len() + 113, 0);

    let mut mutable_data_class = Dictionary::new();
    mutable_data_class.insert("$classname".into(), Value::String("NSMutableData".into()));
    mutable_data_class.insert(
        "$classes".into(),
        Value::Array(
            ["NSMutableData", "NSData", "NSObject"]
                .into_iter()
                .map(|name| Value::String(name.into()))
                .collect(),
        ),
    );
    let mut public_key_object = Dictionary::new();
    public_key_object.insert("$class".into(), uid(3));
    public_key_object.insert(
        "NS.data".into(),
        Value::Data(ephemeral_sender_public.to_vec()),
    );

    let objects = vec![
        Value::String("$null".into()),
        Value::Data(authentication_code.to_vec()),
        Value::Data(padded_ciphertext),
        Value::Dictionary(mutable_data_class),
        Value::Dictionary(public_key_object),
    ];
    let mut top = Dictionary::new();
    top.insert("SFIESAuthenticationCode".into(), uid(1));
    top.insert("SFCiphertext".into(), uid(2));
    top.insert(
        "SFEphemeralSenderPublicKeyExternaRepresentation".into(),
        uid(4),
    );
    let mut archive = Dictionary::new();
    archive.insert("$version".into(), Value::Integer(100_000.into()));
    archive.insert("$archiver".into(), Value::String("NSKeyedArchiver".into()));
    archive.insert("$top".into(), Value::Dictionary(top));
    archive.insert("$objects".into(), Value::Array(objects));
    let mut data = Vec::new();
    Value::Dictionary(archive)
        .to_writer_binary(&mut data)
        .map_err(|error| {
            Error::InvalidData(format!("could not encode NSKeyedArchiver: {error}"))
        })?;
    Ok(data)
}

pub fn expand(data: &[u8]) -> Result<Value> {
    if data.len() > MAX_ARCHIVE_BYTES {
        return Err(Error::InvalidData(
            "NSKeyedArchiver exceeds size limit".into(),
        ));
    }
    let archive = Value::from_reader(Cursor::new(data))?;
    let root = archive
        .as_dictionary()
        .ok_or_else(|| Error::InvalidData("NSKeyedArchiver root is not a dictionary".into()))?;
    let objects = root
        .get("$objects")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::InvalidData("NSKeyedArchiver has no $objects array".into()))?;
    if objects.len() > MAX_OBJECTS {
        return Err(Error::InvalidData(
            "NSKeyedArchiver has too many objects".into(),
        ));
    }
    let top = root
        .get("$top")
        .ok_or_else(|| Error::InvalidData("NSKeyedArchiver has no $top".into()))?;
    let node = top
        .as_dictionary()
        .and_then(|value| value.get("root"))
        .unwrap_or(top);
    resolve(node, objects, 0, &mut BTreeSet::new())
}

fn resolve(
    node: &Value,
    objects: &[Value],
    depth: usize,
    active: &mut BTreeSet<usize>,
) -> Result<Value> {
    if depth > MAX_DEPTH {
        return Err(Error::InvalidData(
            "NSKeyedArchiver nesting is too deep".into(),
        ));
    }
    match node {
        Value::Uid(uid) => {
            let index = usize::try_from(uid.get())
                .map_err(|_| Error::InvalidData("NSKeyedArchiver UID overflow".into()))?;
            let target = objects
                .get(index)
                .ok_or_else(|| Error::InvalidData("NSKeyedArchiver UID out of range".into()))?;
            if !active.insert(index) {
                return Err(Error::InvalidData("NSKeyedArchiver reference cycle".into()));
            }
            let value = resolve(target, objects, depth + 1, active);
            active.remove(&index);
            value
        }
        Value::String(value) if value == "$null" => Ok(Value::String(String::new())),
        Value::Array(values) => values
            .iter()
            .map(|value| resolve(value, objects, depth + 1, active))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        Value::Dictionary(values) => {
            let is_object = values.contains_key("$class");
            let mut out = Dictionary::new();
            for (key, value) in values {
                if key.starts_with('$') {
                    continue;
                }
                out.insert(key.clone(), resolve(value, objects, depth + 1, active)?);
            }
            if is_object {
                for wrapper in ["NS.data", "NS.string", "NS.objects"] {
                    if let Some(value) = out.remove(wrapper) {
                        return Ok(value);
                    }
                }
            }
            Ok(Value::Dictionary(out))
        }
        value => Ok(value.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nsdata_archive(values: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut class = Dictionary::new();
        class.insert("$classname".into(), Value::String("NSMutableData".into()));
        class.insert(
            "$classes".into(),
            Value::Array(
                ["NSMutableData", "NSData", "NSObject"]
                    .into_iter()
                    .map(|name| Value::String(name.into()))
                    .collect(),
            ),
        );
        let mut objects = vec![Value::String("$null".into()), Value::Dictionary(class)];
        let mut top_object = Dictionary::new();
        for (name, bytes) in values {
            let data_index = objects.len() as u64;
            objects.push(Value::Data(bytes.clone()));
            let wrapper_index = objects.len() as u64;
            let mut wrapper = Dictionary::new();
            wrapper.insert("$class".into(), uid(1));
            wrapper.insert("NS.data".into(), uid(data_index));
            objects.push(Value::Dictionary(wrapper));
            top_object.insert((*name).into(), uid(wrapper_index));
        }
        let root_index = objects.len() as u64;
        objects.push(Value::Dictionary(top_object));
        let mut top = Dictionary::new();
        top.insert("root".into(), uid(root_index));
        let mut archive = Dictionary::new();
        archive.insert("$version".into(), Value::Integer(100_000.into()));
        archive.insert("$archiver".into(), Value::String("NSKeyedArchiver".into()));
        archive.insert("$top".into(), Value::Dictionary(top));
        archive.insert("$objects".into(), Value::Array(objects));
        let mut data = Vec::new();
        Value::Dictionary(archive)
            .to_writer_binary(&mut data)
            .unwrap_or_else(|error| panic!("archive: {error}"));
        data
    }

    #[test]
    fn rejects_non_archive() {
        assert!(expand(b"not a plist").is_err());
    }

    #[test]
    fn unwraps_realistic_nsdata_objects() {
        let public = [&[4_u8][..], &[0xab; 96][..]].concat();
        let archive = nsdata_archive(&[
            (
                "SFEphemeralSenderPublicKeyExternaRepresentation",
                public.clone(),
            ),
            ("SFIESAuthenticationCode", vec![0x11; 16]),
        ]);
        let expanded = expand(&archive).unwrap_or_else(|error| panic!("expand: {error}"));
        let fields = expanded
            .as_dictionary()
            .unwrap_or_else(|| panic!("dictionary"));
        assert_eq!(
            fields
                .get("SFEphemeralSenderPublicKeyExternaRepresentation")
                .and_then(Value::as_data),
            Some(public.as_slice())
        );
        assert_eq!(
            fields
                .get("SFIESAuthenticationCode")
                .and_then(Value::as_data),
            Some(&[0x11; 16][..])
        );
    }

    #[test]
    fn archives_apple_ies_ciphertext_shape() {
        let public = [&[4_u8][..], &[0xab; 96][..]].concat();
        let archive = archive_ies_ciphertext(&public, &[1, 2, 3], &[0x11; 16])
            .unwrap_or_else(|error| panic!("archive: {error}"));
        let expanded = expand(&archive).unwrap_or_else(|error| panic!("expand: {error}"));
        let fields = expanded
            .as_dictionary()
            .unwrap_or_else(|| panic!("dictionary"));
        assert_eq!(
            fields
                .get("SFEphemeralSenderPublicKeyExternaRepresentation")
                .and_then(Value::as_data),
            Some(public.as_slice())
        );
        assert_eq!(
            fields
                .get("SFIESAuthenticationCode")
                .and_then(Value::as_data),
            Some(&[0x11; 16][..])
        );
        let ciphertext = fields
            .get("SFCiphertext")
            .and_then(Value::as_data)
            .unwrap_or_else(|| panic!("ciphertext"));
        assert_eq!(&ciphertext[..3], &[1, 2, 3]);
        assert_eq!(ciphertext.len(), 116);
        assert!(ciphertext[3..].iter().all(|byte| *byte == 0));
    }
}
