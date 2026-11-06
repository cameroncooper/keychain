//! Explicit administrator diagnostic, never installed as an owner/browser API.
//! Default inspection performs no network, key creation or fingerprint capture.
use clap::{Parser, ValueEnum};
use keychain::apple::ckks::upload::{
    Binding, NewRecordReview, Phase, SaveOutcome, Snapshot, UploadIo,
};
use keychain::apple::ckks::{Record, ZoneIdentity};
use keychain::apple::worker::WorkerClient;
use keychain::broker::Broker;
use keychain::broker::registry::Registry;
use keychain::broker::{SyncedCreationRequest, UploadRecovery};
use keychain::passkey::registration::CreationContext;
use keychain::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    registry: PathBuf,
    #[arg(long, default_value = "/etc/keychain/upload-test-review.json")]
    review: PathBuf,
    /// Root-owned, frozen WebAuthn request from the real RP, not an invented challenge.
    #[arg(long)]
    request: PathBuf,
    #[arg(long, value_enum, default_value_t = Mode::Inspect)]
    mode: Mode,
    /// Required for either write mode. Also requires explicit human coordination.
    #[arg(long)]
    confirm_record: Option<Uuid>,
    /// For an explicitly approved retry, confirm the original uncertain attempt.
    #[arg(long)]
    confirm_attempt: Option<Uuid>,
    #[arg(long, default_value = "/dev/sep-bio")]
    device: PathBuf,
}
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    Inspect,
    Negative,
    RetryNegative,
    Positive,
}
#[derive(Deserialize)]
struct Review {
    owner: u32,
    account_fingerprint: String,
    zone: String,
    current_class_a_resolved: bool,
    proposed_record: NewRecordReview,
    proposed_rp_id: String,
    proposed_origin: String,
    proposed_username: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NegativeEvidence {
    binding: Binding,
    pointer_record_sha256: String,
    ciphertext_sha256: String,
}
#[derive(Serialize)]
struct AttemptEvidence<'a> {
    attempt: Uuid,
    zone: &'a ZoneIdentity,
    item: &'a Record,
    pointer: &'a Record,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedAttempt {
    attempt: Uuid,
    zone: ZoneIdentity,
    item: Record,
    pointer: Record,
}
fn refused(message: &str) -> Error {
    Error::Refused(message.into())
}
fn hash(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data))
}
fn private_read(path: &Path) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(refused("diagnostic paths must be absolute"));
    }
    for ancestor in path.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor).map_err(|e| Error::io(ancestor, e))?;
        if meta.uid() != 0
            || meta.file_type().is_symlink()
            || meta.mode() & 0o022 != 0
            || (ancestor == path && (!meta.is_file() || meta.permissions().mode() & 0o077 != 0))
            || (ancestor != path && !meta.is_dir())
        {
            return Err(refused("unsafe administrator diagnostic input"));
        }
    }
    keychain::paths::read_bounded(path)
}

/// Change exactly one byte inside the unique canonical top-level tag field.
/// Reparse and require the complete projected record and server metadata to
/// remain identical except that tag and its one encoded byte. No target edits.
fn wrong_tag(pointer: &Record, zone: &ZoneIdentity) -> Result<Record> {
    let metadata = pointer.server_precondition(zone)?;
    let tag = metadata
        .change_tag
        .as_deref()
        .ok_or_else(|| refused("missing tag"))?;
    let mut changed = tag.as_bytes().to_vec();
    let index = changed
        .iter()
        .position(u8::is_ascii_alphanumeric)
        .ok_or_else(|| refused("tag has no safely mutable ASCII character"))?;
    changed[index] = if changed[index] == b'0' { b'1' } else { b'0' };
    let needle = keychain::proto::Writer::new().string(1, tag).finish();
    let offsets: Vec<_> = metadata
        .encoded_record
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == needle).then_some(offset))
        .collect();
    let [offset] = offsets.as_slice() else {
        return Err(refused("tag encoding is ambiguous"));
    };
    let mut expected = pointer.clone();
    let modified = expected
        .server
        .as_mut()
        .ok_or_else(|| refused("missing metadata"))?;
    let tag_start = offset + needle.len() - tag.len();
    modified.encoded_record[tag_start + index] = changed[index];
    modified.change_tag = Some(String::from_utf8(changed).map_err(|_| refused("tag encoding"))?);
    let parsed = keychain::apple::ckks::parse_record(&modified.encoded_record)?;
    if parsed != expected {
        return Err(refused("negative probe changed more than the tag"));
    }
    expected.server_precondition(zone)?;
    Ok(expected)
}

struct ScopedIo<'a> {
    inner: &'a mut dyn UploadIo,
    zone: ZoneIdentity,
    review: NewRecordReview,
    negative: bool,
    attempted: bool,
    rejected: bool,
    ciphertext_sha256: Option<String>,
    attempt_path: PathBuf,
    expected_ciphertext_sha256: Option<String>,
}
impl ScopedIo<'_> {
    fn check_pointer(&self, pointer: &Record) -> Result<()> {
        let meta = pointer.server_precondition(&self.zone)?;
        if hash(&meta.encoded_record) != self.review.pointer_record_sha256
            || hash(meta.change_tag.as_deref().unwrap_or_default())
                != self.review.pointer_change_tag_sha256
            || pointer.string("parentkeyref") != Some(self.review.current_class_key_id.as_str())
        {
            return Err(refused(
                "pointer changed since review; prepare a new review",
            ));
        }
        Ok(())
    }
    fn check_absence(&mut self, check: &dyn Fn() -> Result<()>) -> Result<()> {
        let snapshot = self.inner.fetch_zone(&self.zone, check)?;
        let current = snapshot.review_new_record(self.review.record_id)?;
        if current.pointer_record_sha256 != self.review.pointer_record_sha256
            || current.pointer_change_tag_sha256 != self.review.pointer_change_tag_sha256
            || current.current_class_key_id != self.review.current_class_key_id
        {
            return Err(refused("hierarchy differs from reviewed scope"));
        }
        check()
    }
}
impl UploadIo for ScopedIo<'_> {
    fn fetch_zone(
        &mut self,
        zone: &ZoneIdentity,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Snapshot> {
        if zone != &self.zone {
            return Err(refused("fetch outside reviewed zone"));
        }
        self.inner.fetch_zone(zone, check)
    }
    fn create_atomic(
        &mut self,
        attempt: Uuid,
        zone: &ZoneIdentity,
        item: &Record,
        pointer: &Record,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<SaveOutcome> {
        check()?;
        if self.attempted || zone != &self.zone || item.name != self.review.record_id.to_string() {
            return Err(refused("probe permits one send for the reviewed UUID only"));
        }
        self.check_pointer(pointer)?;
        let ciphertext_sha256 = hash(serde_json::to_vec(item)?);
        if self
            .expected_ciphertext_sha256
            .as_ref()
            .is_some_and(|expected| expected != &ciphertext_sha256)
        {
            return Err(refused(
                "confirmed-absence retry changed the retained ciphertext",
            ));
        }
        let altered = if self.negative {
            Some(wrong_tag(pointer, zone)?)
        } else {
            None
        };
        // Freeze before IO, even if it fails or returns an ambiguous response.
        self.attempted = true;
        self.ciphertext_sha256 = Some(ciphertext_sha256);
        // The diagnostic deliberately alters a precondition outside the normal
        // encrypted coordinator journal. Retain the exact attempted ciphertext
        // and pointer input BEFORE sending, including on loss of the reply.
        // These are encrypted CloudKit records/public metadata, never a scalar.
        keychain::paths::create_private_exclusive(
            &self.attempt_path,
            &serde_json::to_vec(&AttemptEvidence {
                attempt,
                zone,
                item,
                pointer: altered.as_ref().unwrap_or(pointer),
            })?,
        )?;
        let result = self.inner.create_atomic(
            attempt,
            zone,
            item,
            altered.as_ref().unwrap_or(pointer),
            check,
        )?;
        check()?;
        self.rejected = matches!(result, SaveOutcome::PreconditionFailed);
        if self.negative && !self.rejected {
            return Err(refused(
                "negative probe was accepted; stop and retain the key/journal",
            ));
        }
        Ok(result)
    }
}

fn run(args: Args) -> Result<()> {
    if keychain_sep_driver::peer::effective_uid() != 0 {
        return Err(refused("administrator diagnostic requires root"));
    }
    keychain_sep_driver::memory::make_process_nondumpable()
        .map_err(|e| Error::io("memory policy", e))?;
    let review: Review = serde_json::from_slice(&private_read(&args.review)?)?;
    if review.owner == 0
        || !review.current_class_a_resolved
        || review.zone != "Passwords"
        || review.proposed_record.record_id.get_version_num() != 4
    {
        return Err(refused("invalid account review"));
    }
    let details =
        String::from_utf8(private_read(&args.request)?).map_err(|_| refused("request encoding"))?;
    let context = CreationContext::parse(&details)?;
    if context.rp_id() != review.proposed_rp_id
        || context.origin() != review.proposed_origin
        || context.username() != review.proposed_username
    {
        return Err(refused("request differs from reviewed RP/account"));
    }
    if private_read(Path::new("/etc/keychain/sep-owner"))?
        != format!("{}\n", review.owner).as_bytes()
    {
        return Err(refused("owner differs from the explicit SEP pairing"));
    }
    // Never create a missing registry/root during diagnostic inspection.
    private_read(&args.registry.join(format!("account-{}.enc", review.owner)))?;
    let registry = Registry::open(&args.registry)?;
    let account = registry.load_account(review.owner)?;
    if account.scope().account_fingerprint != review.account_fingerprint
        || account.scope().zone.name != review.zone
    {
        return Err(refused("enrolled account differs from review"));
    }
    let binding = Binding {
        owner: review.owner,
        account_fingerprint: review.account_fingerprint,
        peer_id: account.scope().peer_id.clone(),
        transaction: review.proposed_record.record_id,
        request_sha256: hash(details.as_bytes()),
        zone: account.scope().zone.clone(),
    };
    if args.mode == Mode::Inspect {
        println!("scope/request valid; no worker, key creation, capture or save started");
        let journal_path = args
            .registry
            .join(format!("upload-{}.enc", binding.transaction));
        if journal_path
            .try_exists()
            .map_err(|e| Error::io(&journal_path, e))?
        {
            let session = registry.uploads()?.resume(&binding)?;
            let phase = match session.phase()? {
                Phase::Prepared => "prepared",
                Phase::Attempted { .. } => "attempted/uncertain",
                Phase::Accepted { .. } => "accepted",
                Phase::FetchVerified { .. } => "fetch-verified",
                Phase::Rejected => "rejected",
            };
            println!("saved upload phase: {phase}");
        }
        let attempted = args.registry.join(format!(
            "probe-attempt-negative-{}.json",
            binding.transaction
        ));
        if attempted
            .try_exists()
            .map_err(|e| Error::io(&attempted, e))?
        {
            let saved: SavedAttempt = serde_json::from_slice(&private_read(&attempted)?)?;
            if saved.zone != binding.zone {
                return Err(refused("saved attempt belongs to another zone"));
            }
            keychain::apple::cloudkit::atomic::validate_create_request(
                &account.device(),
                &binding,
                saved.attempt,
                &saved.item,
                &saved.pointer,
            )?;
            println!(
                "saved negative request passes offline coordinator/worker wire validation; not resent"
            );
        }
        return Ok(());
    }
    if args.confirm_record != Some(binding.transaction) {
        return Err(refused(
            "write mode requires --confirm-record with the reviewed UUID",
        ));
    }
    registry.item_recipient()?;
    let proof_path = args
        .registry
        .join(format!("negative-{}.json", binding.transaction));
    let negative = matches!(args.mode, Mode::Negative | Mode::RetryNegative);
    if negative
        && proof_path
            .try_exists()
            .map_err(|e| Error::io(&proof_path, e))?
    {
        return Err(refused(
            "negative probe already completed; do not replay it",
        ));
    }
    let mut expected_ciphertext_sha256 = None;
    if args.mode == Mode::Negative {
        let saved = args.registry.join(format!(
            "probe-attempt-negative-{}.json",
            binding.transaction
        ));
        if saved.try_exists().map_err(|e| Error::io(&saved, e))? {
            return Err(refused(
                "negative request already attempted; inspect/reconcile and explicitly approve any retry",
            ));
        }
    }
    if args.mode == Mode::RetryNegative {
        let saved_path = args.registry.join(format!(
            "probe-attempt-negative-{}.json",
            binding.transaction
        ));
        let saved: SavedAttempt = serde_json::from_slice(&private_read(&saved_path)?)?;
        if args.confirm_attempt != Some(saved.attempt)
            || saved.zone != binding.zone
            || saved.item.name != binding.transaction.to_string()
        {
            return Err(refused(
                "retry requires --confirm-attempt matching the original uncertain request",
            ));
        }
        let session = registry.uploads()?.resume(&binding)?;
        if !matches!(session.phase()?, Phase::Attempted { attempt } if *attempt == saved.attempt) {
            return Err(refused(
                "only the specifically confirmed uncertain attempt may be retried",
            ));
        }
        expected_ciphertext_sha256 = Some(hash(serde_json::to_vec(&saved.item)?));
    }
    if args.mode == Mode::Positive {
        let proof: NegativeEvidence = serde_json::from_slice(&private_read(&proof_path)?)?;
        if proof.binding != binding
            || proof.pointer_record_sha256 != review.proposed_record.pointer_record_sha256
        {
            return Err(refused("negative evidence differs from this request"));
        }
        if registry.uploads()?.resume(&binding)?.phase()? != &Phase::Rejected {
            return Err(refused(
                "positive probe requires a definitely rejected journal; reconcile uncertainty separately",
            ));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let check = || {
        if Instant::now() >= deadline {
            return Err(refused("diagnostic expired; do not resend"));
        }
        Ok(())
    };
    let client = WorkerClient::connect(
        &account.worker().socket,
        account.worker().uid,
        binding.clone(),
        deadline,
        &check,
        &check,
    )?;
    let mut inner = registry.account_upload_io(review.owner, client, &check)?;
    let response_directory = args.registry.clone();
    inner.audit_save_responses(move |attempt, response| {
        keychain::paths::create_private_exclusive(
            &response_directory.join(format!("save-response-{attempt}.bin")),
            response,
        )
    });
    let mut io = ScopedIo {
        inner: &mut inner,
        zone: binding.zone.clone(),
        review: review.proposed_record,
        negative,
        attempted: false,
        rejected: false,
        ciphertext_sha256: None,
        attempt_path: if args.mode == Mode::RetryNegative {
            args.registry.join(format!(
                "probe-attempt-negative-retry-{}-{}.json",
                binding.transaction,
                args.confirm_attempt
                    .ok_or_else(|| refused("missing confirmed attempt"))?
            ))
        } else {
            args.registry.join(format!(
                "probe-attempt-{}-{}.json",
                if negative { "negative" } else { "positive" },
                binding.transaction
            ))
        },
        expected_ciphertext_sha256,
    };
    io.check_absence(&check)?;
    let mut broker = Broker::new(registry, review.owner, args.device, false);
    broker.allow_item_decrypt = true;
    broker.allow_synced_creation = true;
    let outcome = broker.create_synced_registration(
        SyncedCreationRequest {
            binding: binding.clone(),
            request_details_json: details,
            recovery: if args.mode == Mode::Positive {
                UploadRecovery::ReencryptRejected
            } else if args.mode == Mode::RetryNegative {
                UploadRecovery::RetryConfirmedAbsent
            } else {
                UploadRecovery::Reconcile
            },
        },
        &mut io,
        Arc::new(AtomicBool::new(false)),
    );
    if negative {
        if outcome.is_ok() || !io.attempted || !io.rejected {
            let detail = outcome
                .err()
                .map(|error| error.to_string())
                .unwrap_or_else(|| "unexpected registration success".into());
            return Err(refused(&format!(
                "negative probe incomplete/uncertain (attempted={}, explicit_rejection={}): {detail}; retain state and do not resend",
                io.attempted, io.rejected,
            )));
        }
        io.check_absence(&check)?;
        if broker.registry.uploads()?.resume(&binding)?.phase()? != &Phase::Rejected {
            return Err(refused("negative journal not definitely rejected"));
        }
        let proof = NegativeEvidence {
            binding,
            pointer_record_sha256: io.review.pointer_record_sha256.clone(),
            ciphertext_sha256: io
                .ciphertext_sha256
                .ok_or_else(|| refused("no attempted ciphertext"))?,
        };
        keychain::paths::create_private_exclusive(&proof_path, &serde_json::to_vec(&proof)?)?;
        println!(
            "negative precondition explicitly rejected; complete authenticated fetch confirms absence and unchanged pointer"
        );
    } else {
        let registration = outcome?;
        let output = args
            .registry
            .join(format!("registration-{}.json", binding.transaction));
        keychain::paths::create_private_exclusive(&output, &serde_json::to_vec(&registration)?)?;
        println!(
            "positive creation and fetch/decrypt verification complete; registration response saved privately"
        );
    }
    Ok(())
}
fn main() {
    if let Err(error) = run(Args::parse()) {
        eprintln!("icloud-write-check: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keychain::proto::Writer;
    fn fixture() -> Result<(ZoneIdentity, Record, Record, NewRecordReview)> {
        let zone = ZoneIdentity {
            name: "Passwords".into(),
            owner: "synthetic-owner".into(),
        };
        let id = |name: &str| {
            Writer::new()
                .message(1, &Writer::new().string(1, name).uint64(2, 1).finish())
                .message(
                    2,
                    &keychain::apple::ckks::record_zone_identifier(&zone.name, &zone.owner),
                )
                .finish()
        };
        let parent = Uuid::new_v4().to_string();
        let reference = Writer::new()
            .message(9, &Writer::new().message(2, &id(&parent)).finish())
            .finish();
        let raw = Writer::new()
            .string(1, "synthetic-tag-123")
            .message(2, &id("classA"))
            .message(3, &Writer::new().string(1, "currentkey").finish())
            .message(
                7,
                &Writer::new()
                    .message(1, &Writer::new().string(1, "parentkeyref").finish())
                    .message(2, &reference)
                    .finish(),
            )
            .bytes(999, b"unknown opaque server field retained")
            .finish();
        let pointer = keychain::apple::ckks::parse_record(&raw)?;
        let record_id = Uuid::new_v4();
        let item = Record {
            name: record_id.to_string(),
            record_type: "item".into(),
            fields: Default::default(),
            server: None,
        };
        let review = NewRecordReview {
            record_id,
            current_class_key_id: parent,
            pointer_record_sha256: hash(raw),
            pointer_change_tag_sha256: hash("synthetic-tag-123"),
        };
        Ok((zone, pointer, item, review))
    }
    #[test]
    fn diagnostic_changes_one_tag_byte_and_preserves_the_pointer_and_unknown_fields() -> Result<()>
    {
        let (zone, pointer, _, _) = fixture()?;
        let changed = wrong_tag(&pointer, &zone)?;
        assert_eq!(pointer.fields, changed.fields);
        assert_eq!(pointer.name, changed.name);
        let original = pointer.server_precondition(&zone)?;
        let altered = changed.server_precondition(&zone)?;
        assert_ne!(original.change_tag, altered.change_tag);
        assert_eq!(original.encoded_record.len(), altered.encoded_record.len());
        assert_eq!(
            original
                .encoded_record
                .iter()
                .zip(&altered.encoded_record)
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
        let mut ambiguous = pointer.clone();
        let meta = ambiguous
            .server
            .as_mut()
            .ok_or_else(|| refused("fixture metadata"))?;
        meta.encoded_record.extend(
            Writer::new()
                .bytes(998, &Writer::new().string(1, "synthetic-tag-123").finish())
                .finish(),
        );
        assert!(wrong_tag(&ambiguous, &zone).is_err());
        Ok(())
    }
    struct Fake {
        calls: usize,
        outcome: u8,
        seen: Option<Record>,
    }
    impl UploadIo for Fake {
        fn fetch_zone(&mut self, _: &ZoneIdentity, _: &dyn Fn() -> Result<()>) -> Result<Snapshot> {
            Err(refused("no fake fetch"))
        }
        fn create_atomic(
            &mut self,
            _: Uuid,
            _: &ZoneIdentity,
            item: &Record,
            pointer: &Record,
            _: &dyn Fn() -> Result<()>,
        ) -> Result<SaveOutcome> {
            self.calls += 1;
            self.seen = Some(pointer.clone());
            match self.outcome {
                0 => Ok(SaveOutcome::PreconditionFailed),
                1 => Err(refused("synthetic lost reply")),
                _ => Ok(SaveOutcome::Accepted(item.clone())),
            }
        }
    }
    #[test]
    fn diagnostic_refuses_replays_after_rejection_uncertainty_and_unexpected_acceptance()
    -> Result<()> {
        for outcome in 0..3 {
            let directory = tempfile::tempdir().map_err(|e| Error::io("fixture directory", e))?;
            let (zone, pointer, item, review) = fixture()?;
            let mut fake = Fake {
                calls: 0,
                outcome,
                seen: None,
            };
            let mut io = ScopedIo {
                inner: &mut fake,
                zone: zone.clone(),
                review,
                negative: true,
                attempted: false,
                rejected: false,
                ciphertext_sha256: None,
                attempt_path: directory.path().join("attempt.json"),
                expected_ciphertext_sha256: None,
            };
            let result = io.create_atomic(Uuid::new_v4(), &zone, &item, &pointer, &|| Ok(()));
            assert_eq!(result.is_ok(), outcome == 0);
            assert_eq!(io.rejected, outcome == 0);
            assert!(
                io.create_atomic(Uuid::new_v4(), &zone, &item, &pointer, &|| Ok(()))
                    .is_err()
            );
            assert_eq!(fake.calls, 1);
            let persisted: serde_json::Value = serde_json::from_slice(
                &keychain::paths::read_bounded(&directory.path().join("attempt.json"))?,
            )?;
            let saved_pointer: Record = serde_json::from_value(persisted["pointer"].clone())?;
            assert_eq!(saved_pointer.fields, pointer.fields);
            assert_ne!(
                saved_pointer
                    .server
                    .as_ref()
                    .and_then(|meta| meta.change_tag.as_deref()),
                pointer
                    .server
                    .as_ref()
                    .and_then(|meta| meta.change_tag.as_deref())
            );
            assert_eq!(
                fake.seen
                    .ok_or_else(|| refused("fake did not observe request"))?
                    .fields,
                pointer.fields
            );
        }
        Ok(())
    }
    #[test]
    fn changed_scope_or_pointer_and_cancellation_cannot_start_a_send() -> Result<()> {
        let (zone, pointer, mut item, review) = fixture()?;
        let directory = tempfile::tempdir().map_err(|e| Error::io("fixture directory", e))?;
        let mut fake = Fake {
            calls: 0,
            outcome: 0,
            seen: None,
        };
        let mut io = ScopedIo {
            inner: &mut fake,
            zone: zone.clone(),
            review,
            negative: true,
            attempted: false,
            rejected: false,
            ciphertext_sha256: None,
            attempt_path: directory.path().join("attempt.json"),
            expected_ciphertext_sha256: None,
        };
        assert!(
            io.create_atomic(Uuid::new_v4(), &zone, &item, &pointer, &|| Err(refused(
                "canceled"
            )))
            .is_err()
        );
        let altered = wrong_tag(&pointer, &zone)?;
        assert!(
            io.create_atomic(Uuid::new_v4(), &zone, &item, &altered, &|| Ok(()))
                .is_err()
        );
        item.name = Uuid::new_v4().to_string();
        assert!(
            io.create_atomic(Uuid::new_v4(), &zone, &item, &pointer, &|| Ok(()))
                .is_err()
        );
        assert!(!io.attempted);
        assert_eq!(fake.calls, 0);
        assert!(!directory.path().join("attempt.json").exists());
        Ok(())
    }

    #[test]
    fn confirmed_absence_retry_cannot_replace_the_original_ciphertext() -> Result<()> {
        let (zone, pointer, mut item, review) = fixture()?;
        let directory = tempfile::tempdir().map_err(|e| Error::io("fixture directory", e))?;
        let expected = hash(serde_json::to_vec(&item)?);
        item.fields.insert(
            "data".into(),
            keychain::apple::ckks::FieldValue::Bytes(vec![9; 48]),
        );
        let mut fake = Fake {
            calls: 0,
            outcome: 0,
            seen: None,
        };
        let mut io = ScopedIo {
            inner: &mut fake,
            zone: zone.clone(),
            review,
            negative: true,
            attempted: false,
            rejected: false,
            ciphertext_sha256: None,
            attempt_path: directory.path().join("attempt.json"),
            expected_ciphertext_sha256: Some(expected),
        };
        assert!(
            io.create_atomic(Uuid::new_v4(), &zone, &item, &pointer, &|| Ok(()))
                .is_err()
        );
        assert!(!io.attempted);
        assert_eq!(fake.calls, 0);
        assert!(!directory.path().join("attempt.json").exists());
        Ok(())
    }
}
