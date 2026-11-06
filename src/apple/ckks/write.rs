//! Offline preparation of new CKKS items. No transport, updates, key rotation or
//! network retry is exposed here. Upload must additionally compare the current
//! key pointer and reconcile uncertain server outcomes before claiming a save.

use std::collections::BTreeMap;
use std::io::{self, Write};

use base64::{Engine, engine::general_purpose::STANDARD};
use rand::RngCore;
use zeroize::Zeroizing;

use super::{FieldValue, Record};
use crate::apple::crypto::{aes_siv_wrap_key, encrypt_item};
use crate::apple::pipeline::{
    DecryptedItem, RecoveredTlk, authenticated_data_v2, unwrap_class_keys,
};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyClass {
    WhenUnlocked,
    AfterFirstUnlock,
}
impl KeyClass {
    pub fn name(self) -> &'static str {
        match self {
            Self::WhenUnlocked => "classA",
            Self::AfterFirstUnlock => "classC",
        }
    }
    fn protection(self) -> &'static str {
        match self {
            Self::WhenUnlocked => "ak",
            Self::AfterFirstUnlock => "ck",
        }
    }
}

/// A class key resolved from the explicit current pointer and zone-bound,
/// authenticated TLKs. Never pick an arbitrary decryptable/stale class key.
pub struct CurrentKey {
    zone: String,
    pointer: Record,
    key_id: String,
    class: KeyClass,
    key: Zeroizing<Vec<u8>>,
    occupied: std::collections::BTreeSet<String>,
}

impl CurrentKey {
    /// `zone_records` must be a complete single-zone snapshot, as returned by
    /// retrieve_zone. Authenticated roots for other zones are never usable here.
    pub fn from_snapshot(
        zone: &str,
        zone_records: &[Record],
        authenticated_tlks: &[RecoveredTlk],
        class: KeyClass,
    ) -> Result<Self> {
        if !super::KEYCHAIN_ZONES.contains(&zone) || zone_records.len() > 65536 {
            return Err(invalid("unknown zone or oversized snapshot"));
        }
        let mut roots = BTreeMap::new();
        for tlk in authenticated_tlks
            .iter()
            .filter(|tlk| tlk.zone_name == zone)
        {
            if tlk.keyclass != "tlk" || tlk.key.len() != 64 {
                return Err(invalid("invalid authenticated TLK class or length"));
            }
            uuid::Uuid::parse_str(&tlk.uuid)
                .map_err(|_| invalid("invalid authenticated TLK UUID"))?;
            if let Some(previous) = roots.insert(tlk.uuid.clone(), tlk.key.clone()) {
                if previous.as_slice() != tlk.key.as_slice() {
                    return Err(Error::Security(
                        "conflicting authenticated zone roots".into(),
                    ));
                }
            }
        }
        if roots.is_empty() {
            return Err(Error::Refused(
                "no authenticated TLK for the write zone".into(),
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        for record in zone_records {
            if !names.insert(record.name.clone()) {
                return Err(invalid("duplicate record in write snapshot"));
            }
        }
        let pointer = zone_records
            .iter()
            .find(|record| record.record_type == "currentkey" && record.name == class.name())
            .ok_or_else(|| invalid("missing current class-key pointer"))?;
        let key_id = pointer
            .string("parentkeyref")
            .ok_or_else(|| invalid("current class-key pointer has no target"))?;
        uuid::Uuid::parse_str(key_id).map_err(|_| invalid("invalid class-key UUID"))?;
        if roots.contains_key(key_id) {
            return Err(invalid("a TLK cannot be used as an item class key"));
        }
        let sync_key = zone_records
            .iter()
            .find(|record| record.record_type == "synckey" && record.name == key_id)
            .ok_or_else(|| invalid("current class-key record is missing"))?;
        if sync_key.string("class") != Some(class.name()) {
            return Err(Error::Security(
                "current class-key target has the wrong class".into(),
            ));
        }
        let sync_keys: Vec<_> = zone_records
            .iter()
            .filter(|record| record.record_type == "synckey")
            .cloned()
            .collect();
        let mut resolved = unwrap_class_keys(&sync_keys, &roots)?;
        let key = resolved.remove(key_id).ok_or_else(|| {
            Error::Security("current class key is not rooted in an authenticated TLK".into())
        })?;
        Ok(Self {
            zone: zone.into(),
            pointer: pointer.clone(),
            key_id: key_id.into(),
            class,
            key,
            occupied: names,
        })
    }

    pub fn zone(&self) -> &str {
        &self.zone
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    /// Preserve the selected pointer, including any retained server encoding and
    /// change tag, for the upload coordinator's atomic precondition.
    pub fn current_pointer(&self) -> &Record {
        &self.pointer
    }

    pub fn seal_new_item(&self, item: &DecryptedItem) -> Result<Record> {
        let id = uuid::Uuid::parse_str(&item.record_id)
            .map_err(|_| invalid("new item ID is not a UUID"))?;
        if id.get_version_num() != 4 || self.occupied.contains(&item.record_id) {
            return Err(Error::Refused(
                "new CKKS item requires an unused UUID v4".into(),
            ));
        }
        if item
            .fields
            .get("vwht")
            .and_then(plist::Value::as_string)
            .is_some_and(|hint| hint != self.zone)
        {
            return Err(Error::Security(
                "item view hint does not match the write zone".into(),
            ));
        }
        if item.fields.get("pdmn").and_then(plist::Value::as_string)
            != Some(self.class.protection())
        {
            return Err(Error::Security(
                "item protection does not match the selected class key".into(),
            ));
        }
        if item.fields.get("sync").and_then(plist::Value::as_boolean) != Some(true) {
            return Err(invalid(
                "only explicitly synchronizable items can be prepared",
            ));
        }
        let secret_length = item
            .fields
            .get("v_Data")
            .and_then(plist::Value::as_data)
            .ok_or_else(|| invalid("new item has no secret data"))?
            .len();
        let mut plaintext = BoundedPlaintext(Zeroizing::new(Vec::new()));
        // These are local sync intent/identity fields, not part of Apple's
        // kSecDbSyncFlag projection. The incoming side restores them itself.
        let sync_fields: BTreeMap<_, _> = item
            .fields
            .iter()
            .filter(|(name, _)| !matches!(name.as_str(), "sync" | "UUID"))
            .collect();
        plist::to_writer_binary(&mut plaintext, &sync_fields)?;
        let mut item_key = Zeroizing::new([0u8; 64]);
        rand::rngs::OsRng.fill_bytes(item_key.as_mut());
        let wrapped = aes_siv_wrap_key(&self.key, item_key.as_ref())?;
        let mut record = Record {
            server: None,
            name: item.record_id.clone(),
            record_type: "item".into(),
            fields: BTreeMap::from([
                (
                    "parentkeyref".into(),
                    FieldValue::Reference(self.key_id.clone()),
                ),
                (
                    "wrappedkey".into(),
                    FieldValue::String(STANDARD.encode(wrapped)),
                ),
                ("gen".into(), FieldValue::Integer(0)),
                ("encver".into(), FieldValue::Integer(2)),
            ]),
        };
        let aad = authenticated_data_v2(&record, &self.key_id)?;
        let data = encrypt_item(item_key.as_ref(), &plaintext.0, &aad, secret_length < 20)?;
        record.fields.insert("data".into(), FieldValue::Bytes(data));
        Ok(record)
    }
}

// Prevent an oversized plaintext from being fully allocated before rejecting it.
struct BoundedPlaintext(Zeroizing<Vec<u8>>);
impl Write for BoundedPlaintext {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > (1024 * 1024usize).saturating_sub(self.0.len()) {
            return Err(io::Error::other("CKKS plaintext exceeds the 1-MiB limit"));
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn invalid(message: &str) -> Error {
    Error::InvalidData(format!("CKKS write preparation: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PasskeyCredential, PasskeyProvenance};
    use crate::security::{KeyAlgorithm, KeyRef, KeyUsage, SecurityBackend, SoftwareFileBackend};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    struct Fixture {
        records: Vec<Record>,
        tlks: Vec<RecoveredTlk>,
        class_key: Vec<u8>,
        passkey: PasskeyCredential,
        private: Zeroizing<Vec<u8>>,
    }
    impl Fixture {
        fn new() -> Result<Self> {
            let tlk_id = uuid::Uuid::new_v4().to_string();
            let class_id = uuid::Uuid::new_v4().to_string();
            let root = vec![1; 64];
            let class_key = vec![2; 64];
            let records = vec![
                Record {
                    server: None,
                    name: "classA".into(),
                    record_type: "currentkey".into(),
                    fields: BTreeMap::from([(
                        "parentkeyref".into(),
                        FieldValue::Reference(class_id.clone()),
                    )]),
                },
                Record {
                    server: None,
                    name: class_id,
                    record_type: "synckey".into(),
                    fields: BTreeMap::from([
                        ("parentkeyref".into(), FieldValue::Reference(tlk_id.clone())),
                        ("class".into(), FieldValue::String("classA".into())),
                        (
                            "wrappedkey".into(),
                            FieldValue::String(
                                STANDARD.encode(aes_siv_wrap_key(&root, &class_key)?),
                            ),
                        ),
                    ]),
                },
            ];
            let tlks = vec![RecoveredTlk {
                uuid: tlk_id,
                zone_name: "Passwords".into(),
                keyclass: "tlk".into(),
                key: Zeroizing::new(root),
            }];
            let secret =
                p256::SecretKey::from_slice(&[7u8; 32]).map_err(|_| invalid("synthetic scalar"))?;
            let point = secret.public_key().to_encoded_point(false);
            let mut private = Zeroizing::new(point.as_bytes().to_vec());
            private.extend_from_slice(&secret.to_bytes());
            let passkey = PasskeyCredential {
                provenance: PasskeyProvenance::Synced,
                id: uuid::Uuid::new_v4().to_string(),
                rp_id: "example.com".into(),
                credential_id: URL_SAFE_NO_PAD.encode([3u8; 20]),
                user_handle: URL_SAFE_NO_PAD.encode(b"user"),
                username: "User".into(),
                display_name: "Test User".into(),
                created_at: 1700000000.0,
                modified_at: 1700000001.0,
                signing_key: KeyRef {
                    backend_id: "software-file".into(),
                    key_id: "synthetic".into(),
                    usage: KeyUsage::WebAuthnSigning,
                    algorithm: KeyAlgorithm::P256,
                },
            };
            Ok(Self {
                records,
                tlks,
                class_key,
                passkey,
                private,
            })
        }
        fn current(&self) -> Result<CurrentKey> {
            CurrentKey::from_snapshot(
                "Passwords",
                &self.records,
                &self.tlks,
                KeyClass::WhenUnlocked,
            )
        }
        fn item(&self) -> Result<DecryptedItem> {
            crate::passkey::encode_sync_item(&self.passkey, &self.private)
        }
    }

    #[test]
    fn new_passkey_encryption_reenters_existing_sync_pipeline_without_changing_identity()
    -> Result<()> {
        let f = Fixture::new()?;
        let current = f.current()?;
        let item = f.item()?;
        let record = current.seal_new_item(&item)?;
        assert_eq!(current.zone(), "Passwords");
        assert_eq!(
            current.key_id(),
            record.string("parentkeyref").unwrap_or_default()
        );
        assert_eq!(record.integer("gen"), Some(0));
        assert_eq!(record.integer("encver"), Some(2));
        assert_eq!(
            STANDARD
                .decode(record.string("wrappedkey").unwrap_or_default())
                .map_err(|_| invalid("wrapped encoding"))?
                .len(),
            80
        );
        let class_keys =
            BTreeMap::from([(current.key_id().into(), Zeroizing::new(f.class_key.clone()))]);
        let decoded =
            crate::apple::pipeline::decrypt_items(std::slice::from_ref(&record), &class_keys);
        assert_eq!(decoded.len(), 1);
        assert!(!decoded[0].fields.contains_key("sync"));
        assert!(!decoded[0].fields.contains_key("UUID"));
        assert_eq!(
            decoded[0]
                .fields
                .get("v_Data")
                .and_then(plist::Value::as_data),
            Some(f.private.as_slice())
        );
        let grouped = BTreeMap::from([
            ("item".into(), vec![record.clone()]),
            ("synckey".into(), vec![f.records[1].clone()]),
        ]);
        let roots = BTreeMap::from([(f.tlks[0].uuid.clone(), f.tlks[0].key.clone())]);
        let mut projection = crate::apple::pipeline::build_credentials(&grouped, roots)?;
        assert!(projection.credentials.is_empty());
        assert_eq!(projection.passkeys.len(), 1);
        let recovered = projection.passkeys.remove(0);
        assert_eq!(recovered.record_id, f.passkey.id);
        assert_eq!(recovered.rp_id, f.passkey.rp_id);
        assert_eq!(recovered.username, f.passkey.username);
        assert_eq!(recovered.created_at, f.passkey.created_at);
        assert_eq!(recovered.modified_at, f.passkey.modified_at);
        let root = tempfile::tempdir().map_err(|e| Error::io("test root", e))?;
        let backend = SoftwareFileBackend::new(crate::paths::AppPaths::for_test(root.path())?);
        let imported = recovered.import(&backend)?;
        assert_eq!(imported.credential_id, f.passkey.credential_id);
        assert_eq!(imported.user_handle, f.passkey.user_handle);
        assert_eq!(backend.public_x963(&imported.signing_key)?, f.private[..65]);
        assert_ne!(
            current.seal_new_item(&item)?.fields["wrappedkey"],
            record.fields["wrappedkey"]
        );
        Ok(())
    }

    #[test]
    fn write_key_requires_current_pointer_correct_class_and_zone_authenticated_roots() -> Result<()>
    {
        let f = Fixture::new()?;
        assert!(
            CurrentKey::from_snapshot("Manatee", &f.records, &f.tlks, KeyClass::WhenUnlocked)
                .is_err()
        );
        assert!(
            CurrentKey::from_snapshot("Passwords", &f.records, &[], KeyClass::WhenUnlocked)
                .is_err()
        );
        assert!(
            CurrentKey::from_snapshot(
                "Passwords",
                &f.records[1..],
                &f.tlks,
                KeyClass::WhenUnlocked
            )
            .is_err()
        );
        assert!(
            CurrentKey::from_snapshot("Passwords", &f.records, &f.tlks, KeyClass::AfterFirstUnlock)
                .is_err()
        );
        let mut records = f.records.clone();
        records.push(records[0].clone());
        assert!(
            CurrentKey::from_snapshot("Passwords", &records, &f.tlks, KeyClass::WhenUnlocked)
                .is_err()
        );
        records = f.records.clone();
        records[1]
            .fields
            .insert("class".into(), FieldValue::String("classC".into()));
        assert!(
            CurrentKey::from_snapshot("Passwords", &records, &f.tlks, KeyClass::WhenUnlocked)
                .is_err()
        );
        records = f.records.clone();
        records[1].fields.insert(
            "wrappedkey".into(),
            FieldValue::String(STANDARD.encode([0u8; 80])),
        );
        assert!(
            CurrentKey::from_snapshot("Passwords", &records, &f.tlks, KeyClass::WhenUnlocked)
                .is_err()
        );
        let mut roots = f.tlks.clone();
        roots[0].key[0] ^= 1;
        assert!(
            CurrentKey::from_snapshot("Passwords", &f.records, &roots, KeyClass::WhenUnlocked)
                .is_err()
        );
        let mut class_c = f.records.clone();
        class_c[0].name = "classC".into();
        class_c[1]
            .fields
            .insert("class".into(), FieldValue::String("classC".into()));
        let current =
            CurrentKey::from_snapshot("Passwords", &class_c, &f.tlks, KeyClass::AfterFirstUnlock)?;
        let mut item = f.item()?;
        assert!(current.seal_new_item(&item).is_err());
        item.fields
            .insert("pdmn".into(), plist::Value::String("ck".into()));
        assert!(current.seal_new_item(&item).is_ok());
        Ok(())
    }

    #[test]
    fn preparation_enforces_provenance_policy_and_identity_and_detects_ciphertext_tampering()
    -> Result<()> {
        let mut f = Fixture::new()?;
        let current = f.current()?;
        let mut item = f.item()?;
        item.fields
            .insert("pdmn".into(), plist::Value::String("ck".into()));
        assert!(current.seal_new_item(&item).is_err());
        item = f.item()?;
        item.fields
            .insert("vwht".into(), plist::Value::String("Manatee".into()));
        assert!(current.seal_new_item(&item).is_err());
        item = f.item()?;
        item.fields
            .insert("sync".into(), plist::Value::Boolean(false));
        assert!(current.seal_new_item(&item).is_err());
        item = f.item()?;
        item.fields
            .insert("notes".into(), plist::Value::Data(vec![0; 1024 * 1024]));
        assert!(current.seal_new_item(&item).is_err());
        let record = current.seal_new_item(&f.item()?)?;
        f.records.push(record.clone());
        assert!(f.current()?.seal_new_item(&f.item()?).is_err());
        let keys = BTreeMap::from([(current.key_id().into(), Zeroizing::new(f.class_key.clone()))]);
        let mut modified = record.clone();
        modified.fields.insert("gen".into(), FieldValue::Integer(1));
        assert!(crate::apple::pipeline::decrypt_items(&[modified], &keys).is_empty());
        let mut modified = record;
        let Some(FieldValue::Bytes(data)) = modified.fields.get_mut("data") else {
            return Err(invalid("fixture data"));
        };
        data[0] ^= 1;
        assert!(crate::apple::pipeline::decrypt_items(&[modified], &keys).is_empty());
        f.passkey.provenance = PasskeyProvenance::DeviceBound;
        assert!(f.item().is_err());
        f.passkey.provenance = PasskeyProvenance::Synced;
        f.passkey.signing_key.backend_id = "sep-native-v1".into();
        assert!(f.item().is_err());
        f.passkey.signing_key.backend_id = "software-file".into();
        f.passkey.modified_at = f64::INFINITY;
        assert!(f.item().is_err());
        f.passkey.modified_at = 1700000001.0;
        f.private[96] ^= 1;
        assert!(f.item().is_err());
        Ok(())
    }
}
