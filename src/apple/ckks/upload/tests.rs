use super::super::{FieldValue, test_support::server_record};
use super::*;
use crate::security::{FileRootKeySource, KeyRef, RootKeySource, SoftwareFileBackend};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[test]
fn read_only_readiness_requires_a_resolvable_current_class_a_key() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let mut snapshot = fixture
        .io
        .fetch_zone(&fixture.plan.binding().zone, &|| Ok(()))?;
    let (records, roots) = snapshot.readiness_counts()?;
    assert_eq!(records, snapshot.records.len());
    assert_eq!(roots, 1);
    snapshot
        .records
        .retain(|record| record.record_type != "currentkey");
    assert!(snapshot.readiness_counts().is_err());
    Ok(())
}

#[test]
fn read_only_readiness_rejects_a_class_key_wrapped_under_another_root() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let mut snapshot = fixture
        .io
        .fetch_zone(&fixture.plan.binding().zone, &|| Ok(()))?;
    snapshot.tlks[0].key[0] ^= 1;
    assert!(snapshot.readiness_counts().is_err());
    Ok(())
}

#[test]
fn proposed_record_review_requires_absence_and_preserves_pointer_preconditions() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let mut snapshot = fixture
        .io
        .fetch_zone(&fixture.plan.binding().zone, &|| Ok(()))?;
    let proposed = Uuid::new_v4();
    let review = snapshot.review_new_record(proposed)?;
    assert_eq!(review.record_id, proposed);
    assert_eq!(review.pointer_record_sha256.len(), 64);
    assert_eq!(review.pointer_change_tag_sha256.len(), 64);
    assert_eq!(
        snapshot.review_new_record(proposed)?.pointer_record_sha256,
        review.pointer_record_sha256
    );
    assert!(snapshot.review_new_record(Uuid::nil()).is_err());
    // Reuse of any existing UUID is refused, even under different case.
    let existing = snapshot
        .records
        .iter()
        .find_map(|record| Uuid::parse_str(&record.name).ok())
        .ok_or_else(|| invalid("fixture has no class-key UUID"))?;
    assert!(snapshot.review_new_record(existing).is_err());
    let pointer = snapshot
        .records
        .iter_mut()
        .find(|record| record.record_type == "currentkey")
        .ok_or_else(|| invalid("fixture pointer"))?;
    pointer.server = None;
    assert!(snapshot.review_new_record(proposed).is_err());
    Ok(())
}

/// Offline cross-module integration fixture. Runs the real encoder, CKKS
/// encryption, durable coordinator and simulated fetch/decrypt verification.
/// No receipt constructor is exposed to production or browser IPC.
pub(crate) fn verified_for(
    binding: Binding,
    credential: PasskeyCredential,
    private_x963: &[u8],
) -> Result<VerifiedUpload> {
    let mut f = Fixture::new()?;
    f.io.zone = binding.zone.clone();
    f.io.records =
        f.io.records
            .iter()
            .map(|record| {
                let tag = record
                    .server
                    .as_ref()
                    .and_then(|metadata| metadata.change_tag.as_deref())
                    .ok_or_else(|| invalid("test change tag"))?;
                server_record(record, &binding.zone, tag)
            })
            .collect::<Result<Vec<_>>>()?;
    let snapshot = f.io.fetch_zone(&binding.zone, &|| Ok(()))?;
    let current = CurrentKey::from_snapshot(
        &binding.zone.name,
        &snapshot.records,
        &snapshot.tlks,
        KeyClass::WhenUnlocked,
    )?;
    let item = crate::passkey::encode_sync_item(&credential, private_x963)?;
    let record = current.seal_new_item(&item)?;
    let plan = PreparedUpload::from_snapshot(
        binding,
        credential,
        private_x963
            .get(..65)
            .ok_or_else(|| invalid("test public point"))?,
        record,
        &snapshot,
    )?;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(plan)?;
    session.advance(&mut f.io, &|| Ok(()))?;
    session.verified_upload()
}

/// A disposable server with authenticated synthetic class keys, no network.
pub(crate) fn synthetic_io(zone: ZoneIdentity) -> Result<impl UploadIo> {
    let mut fixture = Fixture::new()?;
    fixture.io.zone = zone.clone();
    fixture.io.records = fixture
        .io
        .records
        .iter()
        .map(|record| {
            let tag = record
                .server
                .as_ref()
                .and_then(|metadata| metadata.change_tag.as_deref())
                .ok_or_else(|| invalid("test tag"))?;
            server_record(record, &zone, tag)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(fixture.io)
}

#[test]
fn resume_before_preparation_never_calls_the_factory_for_an_existing_or_corrupt_journal()
-> Result<()> {
    let f = Fixture::new()?;
    let binding = f.plan.binding().clone();
    let session = UploadStore::new(&f.directory, &f.backend)?
        .resume_or_prepare(&binding, || Ok(f.plan.clone()))?;
    let path = session.path.clone();
    drop(session);
    let session = UploadStore::new(&f.directory, &f.backend)?
        .resume_or_prepare(&binding, || panic!("existing journal re-encrypted"))?;
    let public = STANDARD
        .decode(&f.plan.0.public_sec1)
        .map_err(|_| invalid("test public"))?;
    session.verify_identity(&binding, &f.plan.0.credential, &public)?;
    let mut wrong = f.plan.0.credential.clone();
    wrong.credential_id = URL_SAFE_NO_PAD.encode([9u8; 20]);
    assert!(session.verify_identity(&binding, &wrong, &public).is_err());
    drop(session);
    atomic_write_private(&path, b"corrupt journal")?;
    assert!(
        UploadStore::new(&f.directory, &f.backend)?
            .resume_or_prepare(&binding, || panic!("corrupt journal replaced"))
            .is_err()
    );
    Ok(())
}

#[test]
fn prepare_checks_encrypted_identity_before_creating_a_journal() -> Result<()> {
    let mut f = Fixture::new()?;
    let snapshot = f.io.fetch_zone(&f.plan.0.binding.zone, &|| Ok(()))?;
    let other = p256::SecretKey::from_slice(&[8u8; 32]).map_err(|_| invalid("test key"))?;
    let public = other.public_key().to_encoded_point(false);
    assert!(
        PreparedUpload::from_snapshot(
            f.plan.0.binding.clone(),
            f.plan.0.credential.clone(),
            public.as_bytes(),
            f.plan.0.record.clone(),
            &snapshot
        )
        .is_err()
    );
    let expected = STANDARD
        .decode(&f.plan.0.public_sec1)
        .map_err(|_| invalid("test point"))?;
    let mut metadata = f.plan.0.credential.clone();
    metadata.username = "different-user".into();
    assert!(
        PreparedUpload::from_snapshot(
            f.plan.0.binding.clone(),
            metadata,
            &expected,
            f.plan.0.record.clone(),
            &snapshot
        )
        .is_err()
    );
    assert!(
        std::fs::read_dir(&f.directory)
            .map_err(|e| Error::io(&f.directory, e))?
            .next()
            .is_none()
    );
    Ok(())
}

#[test]
fn snapshot_fetch_requires_all_pages_and_rejects_partial_or_repeated_cursors() -> Result<()> {
    use crate::proto::{Writer, decode_fields, first_bytes};
    let f = Fixture::new()?;
    let change = |record: &Record| -> Result<Vec<u8>> {
        Ok(Writer::new()
            .message(
                5,
                &record
                    .server
                    .as_ref()
                    .ok_or_else(|| invalid("test server metadata"))?
                    .encoded_record,
            )
            .finish())
    };
    let first = Writer::new()
        .message(1, &change(&f.io.records[0])?)
        .bytes(2, b"cursor-1")
        .uint64(4, 1)
        .finish();
    let last = Writer::new()
        .message(1, &change(&f.io.records[1])?)
        .uint64(4, 3)
        .finish();
    let mut calls = 0;
    let snapshot = Snapshot::fetch_with(f.io.zone.clone(), f.io.tlks.clone(), |request| {
        calls += 1;
        if calls == 1 {
            assert!(first_bytes(&decode_fields(request)?, 1).is_none());
            Ok(first.clone())
        } else {
            assert_eq!(
                first_bytes(&decode_fields(request)?, 1),
                Some(b"cursor-1".as_slice())
            );
            Ok(last.clone())
        }
    })?;
    assert_eq!(calls, 2);
    assert_eq!(snapshot.records.len(), 2);
    let repeat = Writer::new().bytes(2, b"cursor-1").uint64(4, 1).finish();
    assert!(
        Snapshot::fetch_with(f.io.zone.clone(), f.io.tlks.clone(), |_| Ok(repeat.clone())).is_err()
    );
    assert!(
        Snapshot::fetch_with(f.io.zone.clone(), f.io.tlks.clone(), |_| Ok(Writer::new()
            .uint64(4, 1)
            .finish()))
        .is_err()
    );
    Ok(())
}

struct FailableRoot {
    inner: FileRootKeySource,
    denied: Arc<AtomicBool>,
}
impl RootKeySource for FailableRoot {
    fn root_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        if self.denied.load(Ordering::Acquire) {
            return Err(Error::Refused("synthetic persistence failure".into()));
        }
        self.inner.root_key()
    }
}
struct Fixture {
    _root: tempfile::TempDir,
    directory: PathBuf,
    backend: SoftwareFileBackend,
    denied: Arc<AtomicBool>,
    plan: PreparedUpload,
    io: FakeIo,
}
impl Fixture {
    fn new() -> Result<Self> {
        let root = tempfile::tempdir().map_err(|e| Error::io("temporary root", e))?;
        let paths = crate::paths::AppPaths::for_test(&root.path().join("crypto"))?;
        let denied = Arc::new(AtomicBool::new(false));
        let source = FailableRoot {
            inner: FileRootKeySource::new(paths.clone()),
            denied: denied.clone(),
        };
        let backend = SoftwareFileBackend::with_root_source(paths, Box::new(source));
        let directory = root.path().join("uploads");
        std::fs::create_dir(&directory).map_err(|e| Error::io(&directory, e))?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io(&directory, e))?;
        let zone = ZoneIdentity {
            name: "Passwords".into(),
            owner: "test-ck-owner".into(),
        };
        let binding = Binding {
            owner: 1001,
            account_fingerprint: format!("SHA256:{}", STANDARD.encode([1u8; 32])),
            peer_id: format!("SHA256:{}", STANDARD.encode([2u8; 32])),
            transaction: Uuid::new_v4(),
            request_sha256: "a1".repeat(32),
            zone: zone.clone(),
        };
        let id = binding.transaction.to_string();
        let credential = PasskeyCredential {
            provenance: PasskeyProvenance::Synced,
            id: id.clone(),
            rp_id: "example.com".into(),
            credential_id: URL_SAFE_NO_PAD.encode([3u8; 20]),
            user_handle: URL_SAFE_NO_PAD.encode(b"user"),
            username: "User".into(),
            display_name: "Test User".into(),
            created_at: 1700000000.0,
            modified_at: 1700000000.0,
            signing_key: KeyRef {
                backend_id: "sep-protected-software-v1".into(),
                key_id: id,
                usage: KeyUsage::WebAuthnSigning,
                algorithm: KeyAlgorithm::P256,
            },
        };
        let secret = p256::SecretKey::from_slice(&[7u8; 32]).map_err(|_| invalid("test scalar"))?;
        let public = secret.public_key().to_encoded_point(false);
        let mut private = Zeroizing::new(public.as_bytes().to_vec());
        private.extend_from_slice(&secret.to_bytes());
        let tlk_id = Uuid::new_v4().to_string();
        let class_id = Uuid::new_v4().to_string();
        let root_key = [4u8; 64];
        let class_key = [5u8; 64];
        let pointer = Record {
            server: None,
            name: "classA".into(),
            record_type: "currentkey".into(),
            fields: BTreeMap::from([(
                "parentkeyref".into(),
                FieldValue::Reference(class_id.clone()),
            )]),
        };
        let class = Record {
            server: None,
            name: class_id,
            record_type: "synckey".into(),
            fields: BTreeMap::from([
                ("parentkeyref".into(), FieldValue::Reference(tlk_id.clone())),
                ("class".into(), FieldValue::String("classA".into())),
                (
                    "wrappedkey".into(),
                    FieldValue::String(STANDARD.encode(crate::apple::crypto::aes_siv_wrap_key(
                        &root_key, &class_key,
                    )?)),
                ),
            ]),
        };
        let records = vec![
            server_record(&pointer, &zone, "pointer-1")?,
            server_record(&class, &zone, "key-1")?,
        ];
        let tlks = vec![RecoveredTlk {
            uuid: tlk_id,
            zone_name: zone.name.clone(),
            keyclass: "tlk".into(),
            key: Zeroizing::new(root_key.to_vec()),
        }];
        let current =
            CurrentKey::from_snapshot(&zone.name, &records, &tlks, KeyClass::WhenUnlocked)?;
        let record =
            current.seal_new_item(&crate::passkey::encode_sync_item(&credential, &private)?)?;
        let snapshot = Snapshot::new(zone.clone(), records.clone(), tlks.clone())?;
        let plan = PreparedUpload::from_snapshot(
            binding,
            credential,
            public.as_bytes(),
            record,
            &snapshot,
        )?;
        let io = FakeIo {
            zone,
            records,
            tlks,
            remote: None,
            writes: vec![],
            lost_response: false,
            commit: true,
            reject: false,
            tamper_fetch: false,
            fail_fetch: false,
            poison_ack: None,
            sparse_ack: false,
        };
        Ok(Self {
            _root: root,
            directory,
            backend,
            denied,
            plan,
            io,
        })
    }
}
struct FakeIo {
    zone: ZoneIdentity,
    records: Vec<Record>,
    tlks: Vec<RecoveredTlk>,
    remote: Option<Record>,
    writes: Vec<(Uuid, Record)>,
    lost_response: bool,
    commit: bool,
    reject: bool,
    tamper_fetch: bool,
    fail_fetch: bool,
    poison_ack: Option<Arc<AtomicBool>>,
    sparse_ack: bool,
}
impl UploadIo for FakeIo {
    fn fetch_zone(
        &mut self,
        zone: &ZoneIdentity,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Snapshot> {
        check()?;
        assert_eq!(zone, &self.zone);
        if self.fail_fetch {
            return Err(Error::Apple(
                "synthetic authentication/fetch refusal".into(),
            ));
        }
        let mut records = self.records.clone();
        if let Some(remote) = &self.remote {
            let mut record = remote.clone();
            if self.tamper_fetch {
                record.fields.insert("gen".into(), FieldValue::Integer(999));
                record = server_record(&record, zone, "tampered")?;
            }
            records.push(record);
        }
        Snapshot::new(zone.clone(), records, self.tlks.clone())
    }
    fn create_atomic(
        &mut self,
        attempt: Uuid,
        zone: &ZoneIdentity,
        record: &Record,
        pointer: &Record,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<SaveOutcome> {
        check()?;
        assert_eq!(zone, &self.zone);
        self.writes.push((attempt, record.clone()));
        let current = self
            .records
            .iter()
            .find(|current| current.name == pointer.name)
            .ok_or_else(|| invalid("test pointer missing"))?;
        if self.reject
            || self.remote.is_some()
            || current.record_type != pointer.record_type
            || current.fields != pointer.fields
            || current.server_precondition(zone)?.change_tag
                != pointer.server_precondition(zone)?.change_tag
        {
            return Ok(SaveOutcome::PreconditionFailed);
        }
        if self.commit {
            self.remote = Some(server_record(record, zone, "saved-1")?);
        }
        if self.lost_response {
            return Err(Error::Apple("synthetic lost response".into()));
        }
        if let Some(denied) = &self.poison_ack {
            denied.store(true, Ordering::Release);
        }
        let mut ack = self
            .remote
            .clone()
            .ok_or_else(|| invalid("no simulated server record"))?;
        if self.sparse_ack {
            ack.fields.clear();
            ack = server_record(&ack, zone, "saved-1")?;
        }
        Ok(SaveOutcome::Accepted(ack))
    }
}

#[test]
fn cancellation_after_acceptance_preserves_uncertain_attempt_and_reconciles_without_resend()
-> Result<()> {
    let mut f = Fixture::new()?;
    let canceled = Arc::new(AtomicBool::new(false));
    f.io.poison_ack = Some(canceled.clone());
    let check = || {
        if canceled.load(Ordering::Acquire) {
            Err(crate::security::sep::ProviderError::Canceled.into())
        } else {
            Ok(())
        }
    };
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    assert!(session.advance(&mut f.io, &check).is_err());
    assert!(matches!(session.phase()?, Phase::Attempted { .. }));
    assert!(session.verified_upload().is_err());
    assert_eq!(f.io.writes.len(), 1);
    drop(session);
    canceled.store(false, Ordering::Release);
    f.io.poison_ack = None;
    let mut resumed = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
    resumed.advance(&mut f.io, &check)?;
    assert!(matches!(resumed.phase()?, Phase::FetchVerified { .. }));
    assert_eq!(f.io.writes.len(), 1);
    Ok(())
}

#[test]
fn rejected_upload_reencrypts_the_same_key_and_reopens_without_losing_prior_ciphertext()
-> Result<()> {
    let mut f = Fixture::new()?;
    let private = private_fixture(7)?;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    f.io.reject = true;
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    let attempts = session.journal.attempts.clone();
    rotate_class_key(&mut f.io)?;
    session.reprepare_after_rejection(&mut f.io, &|| Ok(()), |binding, credential, snapshot| {
        PreparedUpload::encrypt_from_snapshot(
            binding.clone(),
            credential.clone(),
            &private,
            snapshot,
        )
    })?;
    assert_eq!(session.phase()?, &Phase::Prepared);
    assert_eq!(session.journal.attempts, attempts);
    assert_eq!(session.journal.superseded.len(), 1);
    assert_eq!(session.journal.superseded[0].record, f.plan.0.record);
    assert_eq!(session.credential(), &f.plan.0.credential);
    assert_ne!(
        session.journal.plan.record.string("parentkeyref"),
        f.plan.0.record.string("parentkeyref")
    );
    assert_ne!(
        session.journal.plan.record.bytes("data"),
        f.plan.0.record.bytes("data")
    );
    assert_eq!(f.io.writes.len(), 1); // Reprepare never sends.
    let cipher = session.journal.plan.record.clone();
    drop(session);
    let mut session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
    assert_eq!(session.journal.plan.record, cipher);
    assert_eq!(session.journal.superseded[0].record, f.plan.0.record);
    f.io.reject = false;
    session.advance(&mut f.io, &|| Ok(()))?;
    assert_eq!(f.io.writes.len(), 2);
    assert_eq!(f.io.writes[1].1, cipher);
    session.verified_upload()?.verify_identity(
        f.plan.binding(),
        &f.plan.0.credential,
        &private[..65],
    )?;
    Ok(())
}

#[test]
fn a_late_commit_of_superseded_ciphertext_is_verified_without_sending_the_new_plan() -> Result<()> {
    let mut f = Fixture::new()?;
    let private = private_fixture(7)?;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    f.io.lost_response = true;
    f.io.commit = false;
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    assert_eq!(session.journal.superseded.len(), 0);
    assert!(
        session
            .reprepare_after_rejection(&mut f.io, &|| Ok(()), |_, _, _| panic!(
                "uncertain upload reached re-encryption"
            ))
            .is_err()
    );
    session.retry_after_absence(&mut f.io, &|| Ok(()))?;
    f.io.reject = true;
    f.io.lost_response = false;
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    assert_eq!(session.phase()?, &Phase::Rejected);
    rotate_class_key(&mut f.io)?;
    session.reprepare_after_rejection(&mut f.io, &|| Ok(()), |binding, credential, snapshot| {
        PreparedUpload::encrypt_from_snapshot(
            binding.clone(),
            credential.clone(),
            &private,
            snapshot,
        )
    })?;
    drop(session);
    let mut session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
    f.io.remote = Some(server_record(
        &f.plan.0.record,
        &f.io.zone,
        "late-original",
    )?);
    session.advance(&mut f.io, &|| Ok(()))?;
    assert_eq!(f.io.writes.len(), 2);
    assert!(
        matches!(session.phase()?,Phase::FetchVerified {change_tag} if change_tag == "late-original")
    );
    session.verified_upload()?.verify_identity(
        f.plan.binding(),
        &f.plan.0.credential,
        &private[..65],
    )?;
    drop(session);
    let session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
    session.verified_upload()?.verify_identity(
        f.plan.binding(),
        &f.plan.0.credential,
        &private[..65],
    )?;
    Ok(())
}

#[test]
fn reencrypt_refuses_wrong_identity_stale_keys_failed_fetch_and_existing_records() -> Result<()> {
    let mut f = Fixture::new()?;
    let private = private_fixture(7)?;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    assert!(
        session
            .reprepare_after_rejection(&mut f.io, &|| Ok(()), |_, _, _| panic!(
                "prepared upload reached re-encryption"
            ))
            .is_err()
    );
    f.io.reject = true;
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    let original = std::fs::read(&session.path).map_err(|e| Error::io(&session.path, e))?;
    f.io.fail_fetch = true;
    assert!(
        session
            .reprepare_after_rejection(&mut f.io, &|| Ok(()), |_, _, _| panic!(
                "failed fetch reached secret callback"
            ))
            .is_err()
    );
    f.io.fail_fetch = false;
    let wrong_private = private_fixture(9)?;
    assert!(
        session
            .reprepare_after_rejection(&mut f.io, &|| Ok(()), |binding, credential, snapshot| {
                PreparedUpload::encrypt_from_snapshot(
                    binding.clone(),
                    credential.clone(),
                    &wrong_private,
                    snapshot,
                )
            })
            .is_err()
    );
    for field in 0..7 {
        let mut changed = f.plan.clone();
        match field {
            0 => changed.0.binding.owner += 1,
            1 => {
                changed.0.binding.account_fingerprint =
                    format!("SHA256:{}", STANDARD.encode([9u8; 32]))
            }
            2 => changed.0.binding.peer_id = format!("SHA256:{}", STANDARD.encode([9u8; 32])),
            3 => changed.0.binding.request_sha256 = "f1".repeat(32),
            4 => changed.0.binding.transaction = Uuid::new_v4(),
            5 => changed.0.credential.username = "another account".into(),
            _ => changed.0.binding.zone.owner = "another owner".into(),
        }
        assert!(
            session
                .reprepare_after_rejection(&mut f.io, &|| Ok(()), |_, _, _| Ok(changed))
                .is_err()
        );
    }
    rotate_class_key(&mut f.io)?;
    assert!(
        session
            .reprepare_after_rejection(&mut f.io, &|| Ok(()), |_, _, _| Ok(f.plan.clone()))
            .is_err()
    );
    assert!(
        session
            .reprepare_after_rejection(&mut f.io, &|| Ok(()), |_, _, _| Err(Error::Refused(
                "synthetic canceled decrypt".into()
            )))
            .is_err()
    );
    assert_eq!(
        std::fs::read(&session.path).map_err(|e| Error::io(&session.path, e))?,
        original
    );
    assert_eq!(session.phase()?, &Phase::Rejected);
    assert!(session.journal.superseded.is_empty());
    f.io.remote = Some(server_record(
        &f.plan.0.record,
        &f.io.zone,
        "already-present",
    )?);
    assert!(
        session
            .reprepare_after_rejection(&mut f.io, &|| Ok(()), |_, _, _| panic!(
                "existing record reached secret callback"
            ))
            .is_err()
    );
    session.advance(&mut f.io, &|| Ok(()))?;
    assert!(
        session
            .reprepare_after_rejection(&mut f.io, &|| Ok(()), |_, _, _| panic!(
                "verified upload reached re-encryption"
            ))
            .is_err()
    );
    assert_eq!(f.io.writes.len(), 1);
    session.verified_upload()?.verify_identity(
        f.plan.binding(),
        &f.plan.0.credential,
        &private[..65],
    )?;
    Ok(())
}

#[test]
fn reencrypt_checkpoint_failure_poisoning_reopens_the_durable_plan() -> Result<()> {
    let mut f = Fixture::new()?;
    let private = private_fixture(7)?;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    f.io.reject = true;
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    rotate_class_key(&mut f.io)?;
    assert!(
        session
            .reprepare_after_rejection(&mut f.io, &|| Ok(()), |binding, credential, snapshot| {
                let plan = PreparedUpload::encrypt_from_snapshot(
                    binding.clone(),
                    credential.clone(),
                    &private,
                    snapshot,
                )?;
                f.denied.store(true, Ordering::Release);
                Ok(plan)
            })
            .is_err()
    );
    assert!(session.phase().is_err());
    assert!(session.verified_upload().is_err());
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    f.denied.store(false, Ordering::Release);
    drop(session);
    let mut session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
    assert_eq!(session.phase()?, &Phase::Rejected);
    assert_eq!(session.journal.plan.record, f.plan.0.record);
    assert!(session.journal.superseded.is_empty());
    session.reprepare_after_rejection(&mut f.io, &|| Ok(()), |binding, credential, snapshot| {
        PreparedUpload::encrypt_from_snapshot(
            binding.clone(),
            credential.clone(),
            &private,
            snapshot,
        )
    })?;
    f.io.reject = false;
    session.advance(&mut f.io, &|| Ok(()))?;
    assert!(matches!(session.phase()?, Phase::FetchVerified { .. }));
    assert_eq!(f.io.writes.len(), 2);
    Ok(())
}

#[test]
fn reencrypt_history_is_bounded_and_refuses_unrecognized_ciphertext() -> Result<()> {
    let mut f = Fixture::new()?;
    let private = private_fixture(7)?;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    f.io.reject = true;
    for _ in 0..MAX_REBASES {
        assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
        session.reprepare_after_rejection(
            &mut f.io,
            &|| Ok(()),
            |binding, credential, snapshot| {
                PreparedUpload::encrypt_from_snapshot(
                    binding.clone(),
                    credential.clone(),
                    &private,
                    snapshot,
                )
            },
        )?;
    }
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    let original = read_bounded(&session.path)?;
    assert!(
        session
            .reprepare_after_rejection(&mut f.io, &|| Ok(()), |_, _, _| panic!(
                "exhausted budget reached secret callback"
            ))
            .is_err()
    );
    assert_eq!(session.journal.superseded.len(), MAX_REBASES);
    assert_eq!(session.journal.superseded[0].record, f.plan.0.record);
    assert_eq!(session.phase()?, &Phase::Rejected);
    assert_eq!(read_bounded(&session.path)?, original);
    // Same identity under a new, never-prepared ciphertext is still refused.
    let snapshot = f.io.fetch_zone(&f.io.zone.clone(), &|| Ok(()))?;
    let foreign = PreparedUpload::encrypt_from_snapshot(
        f.plan.0.binding.clone(),
        f.plan.0.credential.clone(),
        &private,
        &snapshot,
    )?;
    f.io.remote = Some(server_record(
        &foreign.0.record,
        &f.io.zone,
        "unknown-ciphertext",
    )?);
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    assert!(session.verified_upload().is_err());
    assert_eq!(session.journal.attempts.len(), MAX_REBASES + 1);
    assert_eq!(f.io.writes.len(), MAX_REBASES + 1);
    assert_eq!(session.journal.plan.record.record_type, "item");
    // The previous ciphertext remains usable even after exhausting rebases.
    f.io.remote = Some(server_record(&f.plan.0.record, &f.io.zone, "late-known")?);
    session.advance(&mut f.io, &|| Ok(()))?;
    assert!(session.verified_upload().is_ok());
    Ok(())
}

fn private_fixture(byte: u8) -> Result<Zeroizing<Vec<u8>>> {
    let key = p256::SecretKey::from_slice(&[byte; 32]).map_err(|_| invalid("test scalar"))?;
    let mut private = Zeroizing::new(key.public_key().to_encoded_point(false).as_bytes().to_vec());
    private.extend_from_slice(&key.to_bytes());
    Ok(private)
}

fn rotate_class_key(io: &mut FakeIo) -> Result<()> {
    let key_id = Uuid::new_v4().to_string();
    let root = io.tlks.first().ok_or_else(|| invalid("test root"))?;
    let class = Record {
        server: None,
        name: key_id.clone(),
        record_type: "synckey".into(),
        fields: BTreeMap::from([
            (
                "parentkeyref".into(),
                FieldValue::Reference(root.uuid.clone()),
            ),
            ("class".into(), FieldValue::String("classA".into())),
            (
                "wrappedkey".into(),
                FieldValue::String(STANDARD.encode(crate::apple::crypto::aes_siv_wrap_key(
                    &root.key, &[6u8; 64],
                )?)),
            ),
        ]),
    };
    io.records
        .push(server_record(&class, &io.zone, "rotated-key")?);
    let pointer = io
        .records
        .first_mut()
        .ok_or_else(|| invalid("test pointer"))?;
    pointer
        .fields
        .insert("parentkeyref".into(), FieldValue::Reference(key_id));
    *pointer = server_record(pointer, &io.zone, "pointer-2")?;
    Ok(())
}

#[test]
fn resume_refuses_a_superseded_plan_with_changed_credential_identity() -> Result<()> {
    let mut f = Fixture::new()?;
    let private = private_fixture(7)?;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    f.io.reject = true;
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    session.reprepare_after_rejection(&mut f.io, &|| Ok(()), |binding, credential, snapshot| {
        PreparedUpload::encrypt_from_snapshot(
            binding.clone(),
            credential.clone(),
            &private,
            snapshot,
        )
    })?;
    let path = session.path.clone();
    let original = Zeroizing::new(serde_json::to_vec(&session.journal)?);
    drop(session);
    for field in ["owner", "account", "request", "public", "metadata"] {
        let mut value: serde_json::Value = serde_json::from_slice(&original)?;
        let previous = &mut value["superseded"][0];
        match field {
            "owner" => previous["binding"]["owner"] = serde_json::json!(1002),
            "account" => {
                previous["binding"]["account_fingerprint"] =
                    serde_json::json!(format!("SHA256:{}", STANDARD.encode([9u8; 32])))
            }
            "request" => previous["binding"]["request_sha256"] = serde_json::json!("f1".repeat(32)),
            "public" => {
                previous["public_sec1"] =
                    serde_json::json!(STANDARD.encode(&private_fixture(9)?[..65]))
            }
            _ => previous["credential"]["username"] = serde_json::json!("another user"),
        }
        let plain = Zeroizing::new(serde_json::to_vec(&value)?);
        atomic_write_private(&path, &f.backend.seal(Purpose::SyncUpload, &plain)?)?;
        assert!(
            UploadStore::new(&f.directory, &f.backend)?
                .resume(f.plan.binding())
                .is_err()
        );
    }
    atomic_write_private(&path, &f.backend.seal(Purpose::SyncUpload, &original)?)?;
    assert!(
        UploadStore::new(&f.directory, &f.backend)?
            .resume(f.plan.binding())
            .is_ok()
    );
    Ok(())
}

#[test]
fn verified_backup_registration_requires_matching_receipt_and_fresh_protected_signature()
-> Result<()> {
    use crate::passkey::registration::CreationContext;
    use crate::security::authorization::{AuthorizedSignature, SigningProtection};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    let mut f = Fixture::new()?;
    let credential = f.plan.0.credential.clone();
    let details = serde_json::json!({
        "rp":{"id":credential.rp_id,"name":"Example"},
        "user":{"id":credential.user_handle,"name":credential.username,"displayName":credential.display_name},
        "challenge":URL_SAFE_NO_PAD.encode([23u8;32]),
        "pubKeyCredParams":[{"type":"public-key","alg":-7}],
        "extensions":{"remoteDesktopClientOverride":{"origin":"https://example.com","sameOriginWithAncestors":true}}
    });
    let context = CreationContext::parse(&details.to_string())?;
    f.plan.0.binding.request_sha256 = context.binding().into();
    let binding = f.plan.0.binding.clone();
    let public = STANDARD
        .decode(&f.plan.0.public_sec1)
        .map_err(|_| invalid("test public"))?;
    let key = SigningKey::from_slice(&[7u8; 32]).map_err(|_| invalid("test key"))?;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    assert!(session.verified_upload().is_err());
    session.advance(&mut f.io, &|| Ok(()))?;
    let receipt = session.verified_upload()?;
    let sign = |protection, uv| {
        let key = &key;
        move |reference: &KeyRef, message: &[u8], _| -> Result<AuthorizedSignature> {
            let signature: Signature = key.sign(message);
            Ok(AuthorizedSignature::new(
                signature.to_der().as_bytes().to_vec(),
                reference,
                message,
                uv,
                protection,
            ))
        }
    };
    let registration = context.finish_synced_registration(
        &binding,
        &receipt,
        &credential,
        &public,
        sign(SigningProtection::SepProtectedSoftware, true),
    )?;
    let auth = URL_SAFE_NO_PAD
        .decode(registration.response.authenticator_data)
        .map_err(|_| invalid("test auth"))?;
    assert_eq!(auth[32], 0x5d);
    assert_eq!(registration.id, credential.credential_id);
    for (protection, uv) in [
        (SigningProtection::Software, true),
        (SigningProtection::SepNative, true),
        (SigningProtection::SepProtectedSoftware, false),
    ] {
        assert!(
            context
                .finish_synced_registration(
                    &binding,
                    &receipt,
                    &credential,
                    &public,
                    sign(protection, uv)
                )
                .is_err()
        );
    }
    // Every binding component is checked before invoking the signer.
    for field in 0..6 {
        let mut changed = binding.clone();
        match field {
            0 => changed.owner += 1,
            1 => changed.account_fingerprint = format!("SHA256:{}", STANDARD.encode([9u8; 32])),
            2 => changed.peer_id = format!("SHA256:{}", STANDARD.encode([9u8; 32])),
            3 => changed.transaction = Uuid::new_v4(),
            4 => changed.request_sha256 = "f1".repeat(32),
            _ => changed.zone.owner = "another-owner".into(),
        }
        assert!(
            context
                .finish_synced_registration(
                    &changed,
                    &receipt,
                    &credential,
                    &public,
                    |_, _, _| panic!("changed binding reached signer")
                )
                .is_err()
        );
    }
    let mut changed = credential.clone();
    changed.credential_id = URL_SAFE_NO_PAD.encode([9u8; 20]);
    assert!(
        context
            .finish_synced_registration(&binding, &receipt, &changed, &public, |_, _, _| panic!(
                "changed credential reached signer"
            ))
            .is_err()
    );
    assert!(
        context
            .finish_synced_registration(
                &binding,
                &receipt,
                &credential,
                &[0u8; 65],
                |_, _, _| panic!("changed point reached signer")
            )
            .is_err()
    );
    let mut changed_details = details;
    changed_details["challenge"] = serde_json::json!(URL_SAFE_NO_PAD.encode([24u8; 32]));
    let changed_context = CreationContext::parse(&changed_details.to_string())?;
    assert!(
        changed_context
            .finish_synced_registration(&binding, &receipt, &credential, &public, |_, _, _| panic!(
                "changed request reached signer"
            ))
            .is_err()
    );
    drop(session);
    let reopened = UploadStore::new(&f.directory, &f.backend)?.resume(&binding)?;
    reopened
        .verified_upload()?
        .verify_identity(&binding, &credential, &public)?;
    Ok(())
}

#[test]
fn inspection_compares_fields_without_advancing_or_sending() -> Result<()> {
    let mut f = Fixture::new()?;
    let session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    let absent = f.io.fetch_zone(&f.plan.binding().zone, &|| Ok(()))?;
    assert!(!session.compare_snapshot(&absent)?.present);
    let mut snapshot = absent;
    let mut record = f.plan.0.record.clone();
    record.name = record.name.to_uppercase();
    let key = record
        .fields
        .keys()
        .next()
        .cloned()
        .ok_or_else(|| invalid("fixture fields"))?;
    record.fields.remove(&key);
    snapshot.records.push(record);
    let comparison = session.compare_snapshot(&snapshot)?;
    assert!(comparison.present && comparison.same_type);
    assert!(!comparison.exact_name);
    assert_eq!(comparison.missing_fields, vec![key]);
    assert!(comparison.differing_fields.is_empty());
    assert_eq!(session.phase()?, &Phase::Prepared);
    assert!(f.io.writes.is_empty());
    snapshot.zone.owner = "different-owner".into();
    assert!(session.compare_snapshot(&snapshot).is_err());
    Ok(())
}

#[test]
fn accepted_upload_requires_independent_fetch_and_reopens_without_another_write() -> Result<()> {
    let mut f = Fixture::new()?;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    assert_eq!(session.phase()?, &Phase::Prepared);
    assert!(
        UploadStore::new(&f.directory, &f.backend)?
            .resume(f.plan.binding())
            .is_err()
    ); // Per-transaction lock.
    session.advance(&mut f.io, &|| Ok(()))?;
    assert!(matches!(session.phase()?, Phase::FetchVerified { .. }));
    assert_eq!(f.io.writes.len(), 1);
    assert_eq!(session.credential(), &f.plan.0.credential);
    drop(session);
    let mut session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
    session.advance(&mut f.io, &|| Ok(()))?;
    assert_eq!(f.io.writes.len(), 1);
    let bytes = std::fs::read(&session.path).map_err(|e| Error::io(&session.path, e))?;
    assert!(!bytes.windows(b"Test User".len()).any(|s| s == b"Test User"));
    assert!(f.backend.open(Purpose::Vault, &bytes).is_err());
    Ok(())
}

#[test]
fn ambiguous_commit_reconciles_exact_identity_and_never_resends_automatically() -> Result<()> {
    let mut f = Fixture::new()?;
    f.io.lost_response = true;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    assert!(matches!(session.phase()?, Phase::Attempted { .. }));
    drop(session);
    let mut session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
    session.advance(&mut f.io, &|| Ok(()))?; // Server already has this exact ciphertext/key.
    assert!(matches!(session.phase()?, Phase::FetchVerified { .. }));
    assert_eq!(f.io.writes.len(), 1);
    Ok(())
}

#[test]
fn unresolved_absence_requires_explicit_retry_with_identical_ciphertext() -> Result<()> {
    let mut f = Fixture::new()?;
    f.io.lost_response = true;
    f.io.commit = false;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    assert_eq!(f.io.writes.len(), 1);
    session.retry_after_absence(&mut f.io, &|| Ok(()))?;
    f.io.lost_response = false;
    f.io.commit = true;
    session.advance(&mut f.io, &|| Ok(()))?;
    assert_eq!(f.io.writes.len(), 2);
    assert_ne!(f.io.writes[0].0, f.io.writes[1].0);
    assert_eq!(f.io.writes[0].1, f.io.writes[1].1);
    assert!(matches!(session.phase()?, Phase::FetchVerified { .. }));
    Ok(())
}

#[test]
fn changed_pointer_or_atomic_rejection_preserves_key_without_sending_again() -> Result<()> {
    for reject_at_server in [false, true] {
        let mut f = Fixture::new()?;
        f.io.reject = reject_at_server;
        if !reject_at_server {
            f.io.records[0] = server_record(&f.io.records[0], &f.io.zone, "rotated-tag")?;
        }
        let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
        assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
        assert_eq!(session.phase()?, &Phase::Rejected);
        assert_eq!(f.io.writes.len(), usize::from(reject_at_server));
        drop(session);
        let mut session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
        assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
        assert_eq!(
            session.credential().signing_key,
            f.plan.0.credential.signing_key
        );
        assert_eq!(f.io.writes.len(), usize::from(reject_at_server));
    }
    Ok(())
}

#[test]
fn sparse_ack_requires_complete_independent_fetch_and_cannot_hide_tampering() -> Result<()> {
    for tamper in [false, true] {
        let mut f = Fixture::new()?;
        f.io.sparse_ack = true;
        f.io.tamper_fetch = tamper;
        let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
        assert_eq!(session.advance(&mut f.io, &|| Ok(())).is_ok(), !tamper);
        assert_eq!(session.verified_upload().is_ok(), !tamper);
        assert_eq!(f.io.writes.len(), 1);
        if tamper {
            assert!(matches!(session.phase()?, Phase::Accepted { .. }));
        } else {
            assert!(matches!(session.phase()?, Phase::FetchVerified { .. }));
        }
    }
    Ok(())
}

#[test]
fn acceptance_or_http_success_is_not_fetch_verification_when_payload_changes() -> Result<()> {
    let mut f = Fixture::new()?;
    f.io.tamper_fetch = true;
    let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    assert!(matches!(session.phase()?, Phase::Accepted { .. }));
    assert!(
        session
            .reprepare_after_rejection(&mut f.io, &|| Ok(()), |_, _, _| panic!(
                "accepted upload reached re-encryption"
            ))
            .is_err()
    );
    assert!(session.verified_upload().is_err());
    assert_eq!(f.io.writes.len(), 1);
    drop(session);
    let mut session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
    assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
    assert!(!matches!(session.phase()?, Phase::FetchVerified { .. }));
    Ok(())
}

#[test]
fn checkpoint_failures_poison_memory_and_reconcile_the_durable_attempt_after_reopen() -> Result<()>
{
    for after_send in [false, true] {
        let mut f = Fixture::new()?;
        let mut session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
        if after_send {
            f.io.poison_ack = Some(f.denied.clone());
        } else {
            f.denied.store(true, Ordering::Release);
        }
        assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
        assert!(session.phase().is_err());
        assert!(session.verified_upload().is_err());
        assert!(session.advance(&mut f.io, &|| Ok(())).is_err());
        assert_eq!(f.io.writes.len(), usize::from(after_send));
        f.denied.store(false, Ordering::Release);
        drop(session);
        let mut session = UploadStore::new(&f.directory, &f.backend)?.resume(f.plan.binding())?;
        if after_send {
            assert!(matches!(session.phase()?, Phase::Attempted { .. }));
        } else {
            assert_eq!(session.phase()?, &Phase::Prepared);
        }
        f.io.poison_ack = None;
        session.advance(&mut f.io, &|| Ok(()))?;
        assert!(matches!(session.phase()?, Phase::FetchVerified { .. }));
        assert_eq!(f.io.writes.len(), 1);
    }
    Ok(())
}

#[test]
fn resume_refuses_changed_account_peer_request_or_plan_and_detects_ciphertext_tampering()
-> Result<()> {
    let f = Fixture::new()?;
    let session = UploadStore::new(&f.directory, &f.backend)?.prepare(f.plan.clone())?;
    drop(session);
    for field in ["account", "peer", "request", "owner", "zone"] {
        let mut binding = f.plan.binding().clone();
        match field {
            "account" => {
                binding.account_fingerprint = format!("SHA256:{}", STANDARD.encode([9u8; 32]))
            }
            "peer" => binding.peer_id = format!("SHA256:{}", STANDARD.encode([9u8; 32])),
            "request" => binding.request_sha256 = "f1".repeat(32),
            "owner" => binding.owner += 1,
            _ => binding.zone.owner = "different-owner".into(),
        }
        assert!(
            UploadStore::new(&f.directory, &f.backend)?
                .resume(&binding)
                .is_err()
        );
    }
    let mut changed = f.plan.clone();
    changed.0.public_sec1 = STANDARD.encode([0u8; 65]);
    assert!(
        UploadStore::new(&f.directory, &f.backend)?
            .prepare(changed)
            .is_err()
    );
    let path = f
        .directory
        .join(format!("upload-{}.enc", f.plan.binding().transaction));
    let mut bytes = read_bounded(&path)?;
    let end = bytes.len() - 1;
    bytes[end] ^= 1;
    atomic_write_private(&path, &bytes)?;
    assert!(
        UploadStore::new(&f.directory, &f.backend)?
            .resume(f.plan.binding())
            .is_err()
    );
    Ok(())
}
