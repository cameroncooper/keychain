use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use p384::ecdsa::signature::hazmat::PrehashVerifier;
use p384::ecdsa::{Signature, VerifyingKey};
use p384::pkcs8::DecodePublicKey;
use plist::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use zeroize::Zeroizing;

use super::ckks::{FieldValue, Record};
use super::crypto::{aes_siv_unwrap, decrypt_item, ecies_decrypt};
use super::cuttlefish::tlkshare_signing_data;
use super::nska;
use crate::credential;
use crate::proto::{decode_fields, first_bytes, first_string};
use crate::secret::zeroize_plist_dictionary;
use crate::security::{KeyRef, SecurityBackend};
use crate::{Error, Result};

const AAD_EXCLUDED: &[&str] = &[
    "gen",
    "pcspublickey",
    "UUID",
    "data",
    "pcsservice",
    "pcspublicidentity",
    "parentkeyref",
    "uploadver",
    "wrappedkey",
    "encver",
];

#[derive(Clone)]
pub struct RecoveredTlk {
    pub uuid: String,
    pub zone_name: String,
    pub keyclass: String,
    pub key: Zeroizing<Vec<u8>>,
}

fn little_endian_8(value: i64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

pub fn authenticated_data_v2(record: &Record, parent_key_id: &str) -> Result<Vec<Vec<u8>>> {
    let mut aad = BTreeMap::from([
        ("UUID".to_owned(), record.name.as_bytes().to_vec()),
        (
            "encver".to_owned(),
            little_endian_8(record.integer("encver").unwrap_or(2)),
        ),
        (
            "gen".to_owned(),
            little_endian_8(record.integer("gen").unwrap_or(0)),
        ),
        ("wrappedkey".to_owned(), parent_key_id.as_bytes().to_vec()),
    ]);
    if let Some(value) = record.integer("pcsservice") {
        aad.insert("pcsservice".into(), little_endian_8(value));
    }
    for key in ["pcspublicidentity", "pcspublickey"] {
        if let Some(value) = record.bytes(key) {
            aad.insert(key.into(), value.to_vec());
        }
    }
    let excluded: BTreeSet<_> = AAD_EXCLUDED.iter().copied().collect();
    for (name, value) in &record.fields {
        if excluded.contains(name.as_str()) || name.starts_with("server_") {
            continue;
        }
        let encoded = match value {
            FieldValue::Bytes(value) => value.clone(),
            FieldValue::String(value) | FieldValue::Reference(value) => value.as_bytes().to_vec(),
            FieldValue::Integer(value) => little_endian_8(*value),
            FieldValue::Double(value) => (*value as u64).to_le_bytes().to_vec(),
            FieldValue::Date(value) => OffsetDateTime::from_unix_timestamp(*value as i64)
                .map_err(|_| Error::InvalidData(format!("invalid CKKS date {value}")))?
                .format(&Rfc3339)
                .map_err(|_| Error::InvalidData("could not format CKKS date".into()))?
                .into_bytes(),
        };
        aad.insert(name.clone(), encoded);
    }
    Ok(aad.into_values().collect())
}

pub fn unwrap_authenticated_tlkshares(
    shares: &[Record],
    our_peer_id: &str,
    expected_sender: &str,
    sender_signing_spki: &[u8],
    backend: &dyn SecurityBackend,
    encryption_key: &KeyRef,
    recipient_public_x963: &[u8],
) -> Result<Vec<RecoveredTlk>> {
    let verifying_key = VerifyingKey::from_public_key_der(sender_signing_spki).map_err(|_| {
        Error::InvalidData("TLKShare sender has an invalid P-384 signing key".into())
    })?;
    let mut recovered: BTreeMap<String, RecoveredTlk> = BTreeMap::new();
    for share in shares {
        if share.string("receiver") != Some(our_peer_id)
            || share.string("sender") != Some(expected_sender)
        {
            continue;
        }
        let wrapped_b64 = share
            .string("wrappedkey")
            .ok_or_else(|| Error::InvalidData("TLKShare has no wrappedkey".into()))?;
        let wrapped = B64
            .decode(wrapped_b64)
            .map_err(|_| Error::InvalidData("TLKShare wrappedkey is not base64".into()))?;
        let receiver_public = share.string("receiverPublicEncryptionKey").ok_or_else(|| {
            Error::InvalidData("TLKShare has no receiver public encryption key".into())
        })?;
        let receiver_public = B64.decode(receiver_public).map_err(|_| {
            Error::InvalidData("TLKShare receiver public encryption key is not base64".into())
        })?;
        if receiver_public != recipient_public_x963 {
            return Err(Error::Security(
                "TLKShare receiver public key does not match the recovered peer key".into(),
            ));
        }
        let curve = nonnegative_integer(share, "curve", 4)?;
        let epoch = nonnegative_integer(share, "epoch", 1)?;
        let poisoned = nonnegative_integer(share, "poisoned", 0)?;
        let version = nonnegative_integer(share, "version", 0)?;
        if curve != 4 || epoch != 1 || poisoned != 0 || version != 0 {
            return Err(Error::InvalidData(format!(
                "unsupported TLKShare parameters: curve={curve}, epoch={epoch}, poisoned={poisoned}, version={version}"
            )));
        }
        let signature = share
            .string("signature")
            .ok_or_else(|| Error::InvalidData("TLKShare has no signature".into()))?;
        let signature = B64
            .decode(signature)
            .map_err(|_| Error::InvalidData("TLKShare signature is not base64".into()))?;
        let signature = Signature::from_der(&signature)
            .map_err(|_| Error::InvalidData("TLKShare has an invalid P-384 signature".into()))?;
        let signed = tlkshare_signing_data(
            our_peer_id,
            expected_sender,
            &wrapped,
            curve,
            epoch,
            poisoned,
            version,
        );
        verifying_key
            .verify_prehash(&Sha256::digest(&signed), &signature)
            .map_err(|_| Error::Security("TLKShare sender signature did not verify".into()))?;

        let serialized = decrypt_tlkshare(wrapped_b64, backend, encryption_key)?;
        let fields = decode_fields(&serialized)?;
        let uuid = first_string(&fields, 1)?
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::InvalidData("serialized TLK has no UUID".into()))?;
        let zone_name = first_string(&fields, 2)?
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::InvalidData("serialized TLK has no zone name".into()))?;
        let keyclass = first_string(&fields, 3)?
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::InvalidData("serialized TLK has no key class".into()))?;
        let key = first_bytes(&fields, 4)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Error::InvalidData("serialized TLK has no key bytes".into()))?;
        if key.len() != 64 {
            return Err(Error::InvalidData(format!(
                "serialized TLK {uuid} is not a 64-byte AES-SIV key"
            )));
        }
        if share.string("parentkeyref").is_some_and(|id| id != uuid) {
            return Err(Error::Security(
                "TLKShare record parent does not match its encrypted key UUID".into(),
            ));
        }
        if share
            .string("service")
            .is_some_and(|service| service != zone_name)
        {
            return Err(Error::Security(
                "TLKShare service does not match its encrypted key zone".into(),
            ));
        }
        let material = RecoveredTlk {
            uuid: uuid.clone(),
            zone_name,
            keyclass,
            key: Zeroizing::new(key.to_vec()),
        };
        if let Some(existing) = recovered.get(&uuid) {
            if existing.key.as_slice() != material.key.as_slice()
                || existing.zone_name != material.zone_name
                || existing.keyclass != material.keyclass
            {
                return Err(Error::Security(format!(
                    "conflicting authenticated TLKShares exist for {uuid}"
                )));
            }
        } else {
            recovered.insert(uuid, material);
        }
    }
    Ok(recovered.into_values().collect())
}

fn nonnegative_integer(record: &Record, name: &str, default: u64) -> Result<u64> {
    match record.integer(name) {
        None => Ok(default),
        Some(value) => u64::try_from(value)
            .map_err(|_| Error::InvalidData(format!("TLKShare {name} is negative"))),
    }
}

fn decrypt_tlkshare(
    wrapped: &str,
    backend: &dyn SecurityBackend,
    encryption_key: &KeyRef,
) -> Result<Zeroizing<Vec<u8>>> {
    let archive = B64
        .decode(wrapped)
        .map_err(|_| Error::InvalidData("TLKShare wrappedkey is not base64".into()))?;
    let ies = nska::expand(&archive)?;
    let ies = ies
        .as_dictionary()
        .ok_or_else(|| Error::InvalidData("IESCiphertext is not a dictionary".into()))?;
    let data = |name: &str| -> Result<&[u8]> {
        ies.get(name)
            .and_then(Value::as_data)
            .ok_or_else(|| Error::InvalidData(format!("IESCiphertext has no {name}")))
    };
    let ephemeral = data("SFEphemeralSenderPublicKeyExternaRepresentation")?;
    let stored_ciphertext = data("SFCiphertext")?;
    let authentication_code = data("SFIESAuthenticationCode")?;
    let ciphertext = if stored_ciphertext.len() > 97 + 16 {
        &stored_ciphertext[..stored_ciphertext.len() - (97 + 16)]
    } else {
        stored_ciphertext
    };
    ecies_decrypt(
        backend,
        encryption_key,
        ephemeral,
        ciphertext,
        authentication_code,
    )
}

pub fn unwrap_class_keys(
    sync_keys: &[Record],
    tlks: &BTreeMap<String, Zeroizing<Vec<u8>>>,
) -> BTreeMap<String, Zeroizing<Vec<u8>>> {
    let mut keys = BTreeMap::new();
    for sync_key in sync_keys {
        let Some(parent) = sync_key.string("parentkeyref") else {
            continue;
        };
        let Some(tlk) = tlks.get(parent) else {
            continue;
        };
        let Some(wrapped) = sync_key.string("wrappedkey") else {
            continue;
        };
        let Ok(wrapped) = B64.decode(wrapped) else {
            continue;
        };
        if let Ok(key) = aes_siv_unwrap(tlk, &wrapped, &[]) {
            keys.insert(sync_key.name.clone(), key);
        }
    }
    keys
}

#[derive(Clone, Debug)]
pub struct DecryptedItem {
    pub record_id: String,
    pub fields: plist::Dictionary,
}

impl Drop for DecryptedItem {
    fn drop(&mut self) {
        zeroize_plist_dictionary(&mut self.fields);
    }
}

pub fn decrypt_items(
    items: &[Record],
    class_keys: &BTreeMap<String, Zeroizing<Vec<u8>>>,
) -> Vec<DecryptedItem> {
    let mut decrypted = Vec::new();
    for item in items {
        let Some(parent) = item.string("parentkeyref") else {
            continue;
        };
        let Some(class_key) = class_keys.get(parent) else {
            continue;
        };
        let (Some(data), Some(wrapped)) = (item.bytes("data"), item.string("wrappedkey")) else {
            continue;
        };
        let Ok(wrapped) = B64.decode(wrapped) else {
            continue;
        };
        let Ok(item_key) = aes_siv_unwrap(class_key, &wrapped, &[]) else {
            continue;
        };
        let Ok(aad) = authenticated_data_v2(item, parent) else {
            continue;
        };
        let Ok(plaintext) = decrypt_item(&item_key, data, &aad) else {
            continue;
        };
        let Ok(Value::Dictionary(fields)) = Value::from_reader(Cursor::new(plaintext.as_slice()))
        else {
            continue;
        };
        decrypted.push(DecryptedItem {
            record_id: item.name.clone(),
            fields,
        });
    }
    decrypted
}

pub fn build_credentials(
    records_by_type: &BTreeMap<String, Vec<Record>>,
    tlks: BTreeMap<String, Zeroizing<Vec<u8>>>,
) -> credential::Projection {
    let class_keys = unwrap_class_keys(
        records_by_type
            .get("synckey")
            .map(Vec::as_slice)
            .unwrap_or_default(),
        &tlks,
    );
    let items = decrypt_items(
        records_by_type
            .get("item")
            .map(Vec::as_slice)
            .unwrap_or_default(),
        &class_keys,
    );
    credential::from_items(&items)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apple::crypto::ecies_encrypt;
    use crate::apple::cuttlefish::{encode_serialized_key, tlkshare_signing_data};
    use crate::apple::nska::archive_ies_ciphertext;
    use crate::paths::AppPaths;
    use crate::security::{KeyUsage, SoftwareFileBackend};

    #[test]
    fn aad_is_sorted_and_uses_parent_id() {
        let record = Record {
            name: "uuid".into(),
            record_type: "item".into(),
            fields: BTreeMap::from([
                ("gen".into(), FieldValue::Integer(3)),
                ("encver".into(), FieldValue::Integer(2)),
                ("zfield".into(), FieldValue::String("last".into())),
            ]),
        };
        let aad =
            authenticated_data_v2(&record, "parent").unwrap_or_else(|error| panic!("AAD: {error}"));
        assert_eq!(aad[0], b"uuid");
        assert_eq!(aad[3], b"parent");
        assert_eq!(aad[4], b"last");
    }

    #[test]
    fn authenticated_tlkshare_round_trip_and_signature_check() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths =
            AppPaths::for_test(temp.path()).unwrap_or_else(|error| panic!("paths: {error}"));
        let backend = SoftwareFileBackend::new(paths);
        let signing = backend
            .generate_p384(KeyUsage::Signing)
            .unwrap_or_else(|error| panic!("signing: {error}"));
        let encryption = backend
            .generate_p384(KeyUsage::Agreement)
            .unwrap_or_else(|error| panic!("encryption: {error}"));
        let public_x963 = backend
            .public_x963(&encryption)
            .unwrap_or_else(|error| panic!("public: {error}"));
        let signing_spki = backend
            .public_spki(&signing)
            .unwrap_or_else(|error| panic!("SPKI: {error}"));
        let serialized = encode_serialized_key("tlk-id", "Passwords", "tlk", &[0x42; 64]);
        let encrypted = ecies_encrypt(&public_x963, &serialized)
            .unwrap_or_else(|error| panic!("encrypt: {error}"));
        let wrapped = archive_ies_ciphertext(
            &encrypted.ephemeral_sender_public,
            &encrypted.ciphertext,
            &encrypted.authentication_code,
        )
        .unwrap_or_else(|error| panic!("archive: {error}"));
        let signed = tlkshare_signing_data("peer", "peer", &wrapped, 4, 1, 0, 0);
        let signature = backend
            .sign_p384_sha256(&signing, &signed)
            .unwrap_or_else(|error| panic!("sign: {error}"));
        let mut record = Record {
            name: "share-record".into(),
            record_type: "tlkshare".into(),
            fields: BTreeMap::from([
                ("receiver".into(), FieldValue::String("peer".into())),
                ("sender".into(), FieldValue::String("peer".into())),
                (
                    "receiverPublicEncryptionKey".into(),
                    FieldValue::String(B64.encode(&public_x963)),
                ),
                (
                    "wrappedkey".into(),
                    FieldValue::String(B64.encode(&wrapped)),
                ),
                (
                    "signature".into(),
                    FieldValue::String(B64.encode(&signature)),
                ),
                ("curve".into(), FieldValue::Integer(4)),
                ("epoch".into(), FieldValue::Integer(1)),
                (
                    "parentkeyref".into(),
                    FieldValue::Reference("tlk-id".into()),
                ),
                ("service".into(), FieldValue::String("Passwords".into())),
            ]),
        };
        let recovered = unwrap_authenticated_tlkshares(
            &[record.clone()],
            "peer",
            "peer",
            &signing_spki,
            &backend,
            &encryption,
            &public_x963,
        )
        .unwrap_or_else(|error| panic!("unwrap: {error}"));
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].uuid, "tlk-id");
        assert_eq!(recovered[0].zone_name, "Passwords");
        assert_eq!(recovered[0].keyclass, "tlk");
        assert_eq!(recovered[0].key.as_slice(), &[0x42; 64]);

        let signature = record
            .fields
            .get_mut("signature")
            .and_then(|value| match value {
                FieldValue::String(value) => Some(value),
                _ => None,
            })
            .unwrap_or_else(|| panic!("signature"));
        signature.push('A');
        assert!(
            unwrap_authenticated_tlkshares(
                &[record],
                "peer",
                "peer",
                &signing_spki,
                &backend,
                &encryption,
                &public_x963,
            )
            .is_err()
        );
    }
}
