use super::*;
use crate::apple::octagon_keys::{PeerKeySet, build_permanent_info};
use crate::model::MobileMeState;
use crate::paths::AppPaths;
use crate::security::SoftwareFileBackend;
use std::collections::BTreeMap;

struct Fixture {
    _directory: tempfile::TempDir,
    backend: SoftwareFileBackend,
    account: AccountState,
    device: DeviceIdentity,
    peer: OctagonState,
}
impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir().map_err(|e| Error::io("test fixture", e))?;
        let backend = SoftwareFileBackend::new(AppPaths::for_test(directory.path())?);
        let keys = PeerKeySet::generate(&backend)?;
        let permanent = build_permanent_info(&backend, &keys, "synthetic-machine", "Mac", 1, 0)?;
        let account = AccountState {
            schema_version: 1,
            username: "synthetic@example.com".into(),
            adsid: "synthetic-adsid".into(),
            logged_in_at: 0,
            mobileme: MobileMeState {
                dsid: "synthetic-dsid".into(),
                auth_token: "must-not-export-auth-token".into(),
                cloudkit_user_id: Some("synthetic-owner".into()),
                tokens: BTreeMap::from([
                    (
                        "cloudKitToken".into(),
                        "must-not-export-cloudkit-token".into(),
                    ),
                    ("pet".into(), "must-not-export-pet".into()),
                ]),
                minted_at: 0,
            },
            webservices: BTreeMap::new(),
        };
        let peer = OctagonState {
            schema_version: 1,
            account_fingerprint: crate::apple::octagon::account_fingerprint(&account),
            peer_id: permanent.peer_id,
            signing_key: keys.signing,
            encryption_key: keys.encryption,
            permanent: SignedInfoState {
                data_b64: STANDARD.encode(permanent.signed.info),
                signature_b64: STANDARD.encode(permanent.signed.signature),
            },
            trust_state: OctagonTrustState::Joined,
            created_at: 0,
        };
        let device = DeviceIdentity {
            schema_version: 1,
            device_id: uuid::Uuid::new_v4().to_string(),
            local_user_uuid: uuid::Uuid::new_v4().to_string(),
            serial: "synthetic".into(),
        };
        Ok(Self {
            _directory: directory,
            backend,
            account,
            device,
            peer,
        })
    }
    fn bootstrap(&self) -> Result<Bootstrap> {
        self.backend
            .prepare_account_bootstrap(1001, &self.account, &self.device, &self.peer)
    }
    fn share(&self, id: &str, material: &[u8; 64]) -> Result<crate::apple::ckks::Record> {
        use crate::apple::ckks::{FieldValue, Record};
        use crate::apple::{
            crypto::ecies_encrypt,
            cuttlefish::{encode_serialized_key, tlkshare_signing_data},
            nska::archive_ies_ciphertext,
        };
        let public = self.backend.public_x963(&self.peer.encryption_key)?;
        let serialized = Zeroizing::new(encode_serialized_key(id, "Passwords", "tlk", material));
        let encrypted = ecies_encrypt(&public, &serialized)?;
        let wrapped = archive_ies_ciphertext(
            &encrypted.ephemeral_sender_public,
            &encrypted.ciphertext,
            &encrypted.authentication_code,
        )?;
        let signature = self.backend.sign_p384_sha256(
            &self.peer.signing_key,
            &tlkshare_signing_data(&self.peer.peer_id, &self.peer.peer_id, &wrapped, 4, 1, 0, 0),
        )?;
        Ok(Record {
            server: None,
            name: format!("share-{}", uuid::Uuid::new_v4()),
            record_type: "tlkshare".into(),
            fields: BTreeMap::from([
                (
                    "receiver".into(),
                    FieldValue::String(self.peer.peer_id.clone()),
                ),
                (
                    "sender".into(),
                    FieldValue::String(self.peer.peer_id.clone()),
                ),
                (
                    "receiverPublicEncryptionKey".into(),
                    FieldValue::String(STANDARD.encode(public)),
                ),
                (
                    "wrappedkey".into(),
                    FieldValue::String(STANDARD.encode(wrapped)),
                ),
                (
                    "signature".into(),
                    FieldValue::String(STANDARD.encode(signature)),
                ),
                ("curve".into(), FieldValue::Integer(4)),
                ("epoch".into(), FieldValue::Integer(1)),
                ("parentkeyref".into(), FieldValue::Reference(id.into())),
                ("service".into(), FieldValue::String("Passwords".into())),
            ]),
        })
    }
}

#[test]
fn bootstrap_preserves_signed_identity_and_omits_signing_private_key_tokens_and_vault() -> Result<()>
{
    let f = Fixture::new()?;
    let package = f.bootstrap()?.encode()?;
    let restored = Bootstrap::decode(&package)?;
    assert!(restored.scope.account_fingerprint == f.peer.account_fingerprint);
    assert_eq!(restored.scope.peer_id, f.peer.peer_id);
    let private = Zeroizing::new(
        STANDARD
            .decode(&restored.agreement_x963)
            .map_err(|_| invalid("test agreement"))?,
    );
    assert_eq!(
        &private[..97],
        f.backend.public_x963(&f.peer.encryption_key)?
    );
    let signing = STANDARD.encode(
        f.backend
            .export_private_x963_for_test(&f.peer.signing_key)?,
    );
    let text = std::str::from_utf8(&package).map_err(|_| invalid("test encoding"))?;
    for secret in [
        &signing,
        "must-not-export-auth-token",
        "must-not-export-cloudkit-token",
        "must-not-export-pet",
    ] {
        assert!(!text.contains(secret));
    }
    Ok(())
}

#[test]
fn bootstrap_rejects_changed_scalar_permanent_signature_policy_and_unknown_fields() -> Result<()> {
    let f = Fixture::new()?;
    let package = f.bootstrap()?;
    for case in 0..8 {
        let mut value = serde_json::to_value(&package)?;
        match case {
            0 => value["version"] = 2.into(),
            1 => value["scope"]["owner"] = 0.into(),
            2 => value["scope"]["peer_id"] = format!("SHA256:{}", STANDARD.encode([1; 32])).into(),
            3 => value["scope"]["zone"]["name"] = "Manatee".into(),
            4 => value["agreement_x963"] = STANDARD.encode([0; 145]).into(),
            5 => {
                let mut private = STANDARD
                    .decode(&package.agreement_x963)
                    .map_err(|_| invalid("test scalar"))?;
                private[144] ^= 1;
                value["agreement_x963"] = STANDARD.encode(private).into();
            }
            6 => {
                let data = STANDARD
                    .decode(&package.permanent.data_b64)
                    .map_err(|_| invalid("test data"))?;
                let mut signature = STANDARD
                    .decode(&package.permanent.signature_b64)
                    .map_err(|_| invalid("test signature"))?;
                signature[10] ^= 1;
                let mut bound = data;
                bound.extend_from_slice(&signature);
                value["permanent"]["signature_b64"] = STANDARD.encode(signature).into();
                value["scope"]["peer_id"] = tphash_sha256(&bound).into();
            }
            _ => value["uploaded"] = true.into(),
        }
        assert!(Bootstrap::decode(&serde_json::to_vec(&value)?).is_err());
    }
    let mut different = f.peer.clone();
    different.account_fingerprint = format!("SHA256:{}", STANDARD.encode([9; 32]));
    assert!(
        f.backend
            .prepare_account_bootstrap(1001, &f.account, &f.device, &different)
            .is_err()
    );
    Ok(())
}

#[test]
#[ignore = "requires root; temporary account registry only, no SEP or Apple IO"]
fn root_account_enrollment_is_idempotent_immutable_and_refuses_missing_roots() -> Result<()> {
    let f = Fixture::new()?;
    let input = f.bootstrap()?;
    let directory = tempfile::tempdir().map_err(|e| Error::io("test registry", e))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(directory.path(), e))?;
    let registry = super::super::registry::Registry::open(directory.path())?;
    let worker = WorkerSettings {
        uid: 65534,
        socket: "/run/synthetic-worker/worker.sock".into(),
    };
    let first = registry.enroll_account(1001, &input, worker.clone())?;
    let mut broker = crate::broker::Broker::new(
        super::super::registry::Registry::open(directory.path())?,
        1001,
        "/nonexistent-synthetic-sep".into(),
        false,
    );
    assert_eq!(
        broker.creation_storage_choices()?,
        vec![crate::model::PasskeyProvenance::DeviceBound]
    );
    broker.allow_item_decrypt = true;
    broker.allow_synced_creation = true;
    assert_eq!(
        broker.creation_storage_choices()?,
        vec![
            crate::model::PasskeyProvenance::DeviceBound,
            crate::model::PasskeyProvenance::Synced
        ]
    );
    assert!(registry.browser_credentials(1001)?.is_empty());
    let public = registry.backend.public_x963(first.agreement())?;
    assert_eq!(public, f.backend.public_x963(&f.peer.encryption_key)?);
    let id = uuid::Uuid::new_v4().to_string();
    let share = f.share(&id, &[0x42; 64])?;
    {
        use crate::apple::ckks::{
            test_support::server_record,
            upload::{Binding, UploadIo},
        };
        use crate::proto::Writer;
        let binding = Binding {
            owner: 1001,
            account_fingerprint: first.scope().account_fingerprint.clone(),
            peer_id: first.scope().peer_id.clone(),
            transaction: uuid::Uuid::new_v4(),
            request_sha256: "ab".repeat(32),
            zone: first.scope().zone.clone(),
        };
        let wire = server_record(&share, &binding.zone, "synthetic-share-tag")?
            .server
            .ok_or_else(|| invalid("test wire"))?
            .encoded_record;
        let page = Writer::new()
            .message(1, &Writer::new().message(5, &wire).finish())
            .uint64(4, 3)
            .finish();
        let check = || Ok(());
        let (client, server) = crate::apple::worker::tests::pair(
            &binding,
            &check,
            std::time::Instant::now() + std::time::Duration::from_secs(3),
        )?;
        let thread =
            crate::apple::worker::tests::root_read_fixture(server, binding.clone(), vec![], page);
        // Recovery has no shares. A complete live-zone share must bootstrap the
        // authenticated snapshot, reused before capture without another fetch.
        let mut io = registry.account_upload_io(1001, client, &check)?;
        io.fetch_zone(&binding.zone, &check)?;
        drop(io);
        thread
            .join()
            .unwrap_or_else(|_| panic!("root wire fixture"))?;
    }
    // Live-only shares are required as well as recovery metadata; none of the
    // plaintext root bytes come from a claimed worker success/root field.
    let recovered = first.authenticate_roots(
        &registry.backend,
        &[],
        std::slice::from_ref(&share),
        &|| Ok(()),
    )?;
    assert_eq!(recovered[0].key.as_slice(), &[0x42; 64]);
    let duplicate = first.authenticate_roots(
        &registry.backend,
        std::slice::from_ref(&share),
        std::slice::from_ref(&share),
        &|| Ok(()),
    )?;
    assert_eq!(duplicate.len(), 1);
    let conflicting = f.share(&id, &[0x43; 64])?;
    assert!(
        first
            .authenticate_roots(
                &registry.backend,
                std::slice::from_ref(&share),
                &[conflicting],
                &|| Ok(())
            )
            .is_err()
    );
    let mut wrong = share.clone();
    wrong.fields.insert(
        "signature".into(),
        crate::apple::ckks::FieldValue::String(STANDARD.encode([0; 100])),
    );
    assert!(
        first
            .authenticate_roots(&registry.backend, &[wrong], &[], &|| Ok(()))
            .is_err()
    );
    assert!(
        first
            .authenticate_roots(&registry.backend, &[share], &[], &|| Err(Error::Refused(
                "synthetic cancellation".into()
            )))
            .is_err()
    );
    let encrypted = crate::paths::read_bounded(&registry.account_path(1001))?;
    registry.enroll_account(1001, &input, worker.clone())?;
    assert_eq!(
        crate::paths::read_bounded(&registry.account_path(1001))?,
        encrypted
    );
    let mut changed = f.bootstrap()?;
    changed.scope.account_fingerprint = format!("SHA256:{}", STANDARD.encode([8; 32]));
    assert!(
        registry
            .enroll_account(1001, &changed, worker.clone())
            .is_err()
    );
    assert!(
        registry
            .enroll_account(1002, &input, worker.clone())
            .is_err()
    );
    assert!(
        registry
            .enroll_account(
                1001,
                &input,
                WorkerSettings {
                    uid: 1001,
                    ..worker.clone()
                }
            )
            .is_err()
    );
    // Simulate a crash after key import but before account metadata persistence.
    std::fs::remove_file(registry.account_path(1001))
        .map_err(|e| Error::io(directory.path(), e))?;
    assert!(
        registry
            .enroll_account(1001, &changed, worker.clone())
            .is_err()
    );
    let recovered = registry.enroll_account(1001, &input, worker)?;
    assert_eq!(first.agreement(), recovered.agreement());
    drop(registry);
    let registry = super::super::registry::Registry::open(directory.path())?;
    assert_eq!(registry.load_account(1001)?.agreement(), first.agreement());
    let intent_path = registry.intent_path(1001);
    let intent = crate::paths::read_bounded(&intent_path)?;
    std::fs::remove_file(&intent_path).map_err(|e| Error::io(&intent_path, e))?;
    assert!(registry.load_account(1001).is_err());
    assert!(broker.creation_storage_choices().is_err());
    assert!(
        registry
            .enroll_account(1001, &input, first.worker().clone())
            .is_err()
    );
    assert!(!intent_path.exists());
    crate::paths::create_private_exclusive(&intent_path, &intent)?;
    let root = directory.path().join("state/software.key");
    std::fs::remove_file(&root).map_err(|e| Error::io(&root, e))?;
    assert!(registry.load_account(1001).is_err());
    assert!(!root.exists());
    Ok(())
}
