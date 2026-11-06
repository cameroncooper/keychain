//! Durable, storage-neutral upload coordination. A production transport must
//! implement atomic unchanged-pointer/create-only semantics; no Apple write
//! implementation or browser authorization grant is provided by this module.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::write::{CurrentKey, KeyClass};
use super::{Record, ZoneIdentity};
use crate::apple::pipeline::{RecoveredTlk, unwrap_class_keys};
use crate::model::{PasskeyCredential, PasskeyProvenance};
use crate::paths::{atomic_write_private, create_private_exclusive, read_bounded};
use crate::security::{KeyAlgorithm, KeyUsage, Purpose, SecurityBackend};
use crate::{Error, Result};

const MAX_JOURNAL: usize = 8 * 1024 * 1024;
const MAX_REBASES: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub owner: u32,
    pub account_fingerprint: String,
    pub peer_id: String,
    pub transaction: Uuid,
    pub request_sha256: String,
    pub zone: ZoneIdentity,
}
impl Binding {
    pub(crate) fn validate(&self) -> Result<()> {
        let tphash = |value: &str| {
            value
                .strip_prefix("SHA256:")
                .filter(|value| value.len() == 44)
                .and_then(|value| STANDARD.decode(value).ok())
                .is_some_and(|value| value.len() == 32)
        };
        if self.owner == 0
            || self.transaction.get_version_num() != 4
            || !tphash(&self.account_fingerprint)
            || !tphash(&self.peer_id)
            || self.request_sha256.len() != 64
            || hex::decode(&self.request_sha256).is_err()
            || self.zone.name != "Passwords"
            || self.zone.owner.is_empty()
            || self.zone.owner.len() > 512
        {
            return Err(invalid("invalid account/peer/request/zone binding"));
        }
        Ok(())
    }
}

/// Construct only from an authenticated, complete single-zone fetch. Possession
/// of TLS-authenticated records does not authenticate TLKs: callers must obtain
/// the roots from verified Octagon shares, as the regular sync pipeline does.
pub struct Snapshot {
    zone: ZoneIdentity,
    records: Vec<Record>,
    tlks: Vec<RecoveredTlk>,
}
impl Snapshot {
    /// Verify the current class-A hierarchy without decrypting any item.
    /// Counts are diagnostic metadata, never an upload authorization receipt.
    pub(crate) fn readiness_counts(&self) -> Result<(usize, usize)> {
        crate::security::secret_compute(|| {
            let _current = CurrentKey::from_snapshot(
                &self.zone.name,
                &self.records,
                &self.tlks,
                KeyClass::WhenUnlocked,
            )?;
            let roots = self
                .tlks
                .iter()
                .filter(|root| root.zone_name == self.zone.name)
                .map(|root| &root.uuid)
                .collect::<BTreeSet<_>>()
                .len();
            Ok((self.records.len(), roots))
        })
    }
    /// Fetch every page before absence can authorize a retry or a new save.
    pub fn fetch(
        transport: &crate::apple::cloudkit::CloudKitTransport<'_>,
        zone: ZoneIdentity,
        tlks: Vec<RecoveredTlk>,
    ) -> Result<Self> {
        if zone.owner != transport.user_id() {
            return Err(invalid(
                "fetch owner differs from the authenticated account",
            ));
        }
        Self::fetch_with(zone, tlks, |request| transport.fetch_records(request))
    }
    pub(crate) fn fetch_with(
        zone: ZoneIdentity,
        tlks: Vec<RecoveredTlk>,
        mut read: impl FnMut(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        let records = Self::fetch_records_with(&zone, &mut read)?;
        Self::new(zone, records, tlks)
    }
    /// Complete raw TLS-backed records before root authentication; never use
    /// these alone as absence/backup evidence. Snapshot construction follows it.
    pub(crate) fn fetch_records_with(
        zone: &ZoneIdentity,
        mut read: impl FnMut(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<Vec<Record>> {
        let zone_id = super::record_zone_identifier(&zone.name, &zone.owner);
        let mut records = Vec::new();
        let mut token: Option<Vec<u8>> = None;
        let mut seen = BTreeSet::new();
        let mut bytes = 0usize;
        for _ in 0..1000 {
            let request = super::build_retrieve_changes_request(&zone_id, token.as_deref(), 500);
            let page = super::parse_retrieve_changes_response(&read(&request)?)?;
            for record in &page.records {
                bytes = bytes
                    .checked_add(record.server_precondition(zone)?.encoded_record.len())
                    .ok_or_else(|| invalid("snapshot size overflow"))?;
            }
            if bytes > 64 * 1024 * 1024 || records.len() + page.records.len() > 65536 {
                return Err(invalid("snapshot exceeds bounds"));
            }
            records.extend(page.records);
            if page.status == 3 {
                return Ok(records);
            }
            let next = page
                .continuation
                .ok_or_else(|| invalid("missing page cursor"))?;
            if next.len() > 16 * 1024 || !seen.insert(next.clone()) {
                return Err(invalid("oversized or repeated page cursor"));
            }
            token = Some(next);
        }
        Err(invalid("snapshot exceeded the 1000-page bound"))
    }
    pub(crate) fn new(
        zone: ZoneIdentity,
        records: Vec<Record>,
        tlks: Vec<RecoveredTlk>,
    ) -> Result<Self> {
        if records.len() > 65536 || tlks.len() > 4096 {
            return Err(invalid("snapshot exceeds bounds"));
        }
        let mut seen = BTreeSet::new();
        let mut encoded_bytes = 0usize;
        for record in &records {
            if !seen.insert(&record.name) {
                return Err(invalid("duplicate snapshot record"));
            }
            let server = record.server_precondition(&zone)?;
            encoded_bytes = encoded_bytes
                .checked_add(server.encoded_record.len())
                .ok_or_else(|| invalid("snapshot size overflow"))?;
            if encoded_bytes > 64 * 1024 * 1024 {
                return Err(invalid("snapshot encoding exceeds bounds"));
            }
        }
        let mut roots = BTreeMap::new();
        for root in tlks.iter().filter(|root| root.zone_name == zone.name) {
            if root.keyclass != "tlk" || root.key.len() != 64 {
                return Err(invalid("invalid authenticated root"));
            }
            Uuid::parse_str(&root.uuid).map_err(|_| invalid("invalid authenticated TLK UUID"))?;
            if let Some(previous) = roots.insert(&root.uuid, &root.key) {
                if previous != &root.key {
                    return Err(invalid("conflicting authenticated roots"));
                }
            }
        }
        if roots.is_empty() {
            return Err(invalid("snapshot has no authenticated zone root"));
        }
        Ok(Self {
            zone,
            records,
            tlks,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanData {
    binding: Binding,
    credential: PasskeyCredential,
    public_sec1: String,
    record: Record,
    current_pointer: Record,
}

/// No Deserialize implementation: an untrusted IPC client cannot manufacture a
/// verified plan. The encrypted journal loads its private representation only.
#[derive(Clone)]
pub struct PreparedUpload(PlanData);

/// Evidence that the exact prepared credential was independently fetched and
/// decrypted after upload. This is neither a biometric grant nor evidence of
/// RP acceptance. It cannot be constructed or deserialized by an IPC client.
pub struct VerifiedUpload {
    binding: Binding,
    credential: PasskeyCredential,
    public_sec1: String,
}
impl VerifiedUpload {
    pub fn verify_identity(
        &self,
        binding: &Binding,
        credential: &PasskeyCredential,
        public_sec1: &[u8],
    ) -> Result<()> {
        if &self.binding != binding
            || &self.credential != credential
            || self.public_sec1 != STANDARD.encode(public_sec1)
        {
            return Err(Error::Security(
                "verified upload belongs to a different account, request or credential".into(),
            ));
        }
        Ok(())
    }
}

impl PreparedUpload {
    /// Encrypt the existing credential under the authenticated current class-A
    /// key. The caller keeps plaintext inside its selected-secret operation;
    /// neither this plan nor its journal contains a raw scalar.
    pub fn encrypt_from_snapshot(
        binding: Binding,
        credential: PasskeyCredential,
        private_x963: &[u8],
        snapshot: &Snapshot,
    ) -> Result<Self> {
        crate::security::secret_compute(|| {
            binding.validate()?;
            if snapshot.zone != binding.zone {
                return Err(invalid(
                    "encryption snapshot belongs to another account/zone",
                ));
            }
            let current = CurrentKey::from_snapshot(
                &binding.zone.name,
                &snapshot.records,
                &snapshot.tlks,
                KeyClass::WhenUnlocked,
            )?;
            let record = current.seal_new_passkey(&credential, private_x963)?;
            let public = private_x963
                .get(..65)
                .ok_or_else(|| invalid("truncated private key"))?;
            Self::from_snapshot(binding, credential, public, record, snapshot)
        })
    }

    pub fn from_snapshot(
        binding: Binding,
        credential: PasskeyCredential,
        public_sec1: &[u8],
        record: Record,
        snapshot: &Snapshot,
    ) -> Result<Self> {
        binding.validate()?;
        let current = CurrentKey::from_snapshot(
            &binding.zone.name,
            &snapshot.records,
            &snapshot.tlks,
            KeyClass::WhenUnlocked,
        )?;
        if snapshot.zone != binding.zone
            || snapshot.records.iter().any(|r| r.name == record.name)
            || record.string("parentkeyref") != Some(current.key_id())
        {
            return Err(invalid(
                "prepared item does not match an unused slot/current key",
            ));
        }
        let plan = PlanData {
            binding,
            credential,
            public_sec1: STANDARD.encode(public_sec1),
            record,
            current_pointer: current.current_pointer().clone(),
        };
        plan.validate()?;
        plan.verify_payload(&plan.record, snapshot)?;
        Ok(Self(plan))
    }
    pub fn binding(&self) -> &Binding {
        &self.0.binding
    }
}
impl PlanData {
    fn same_credential(&self, other: &Self) -> bool {
        self.binding == other.binding
            && self.credential == other.credential
            && self.public_sec1 == other.public_sec1
    }
    fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        let credential = &self.credential;
        let key = &credential.signing_key;
        if credential.id != self.binding.transaction.to_string()
            || credential.provenance != PasskeyProvenance::Synced
            || key.backend_id != "sep-protected-software-v1"
            || key.key_id != credential.id
            || key.usage != KeyUsage::WebAuthnSigning
            || key.algorithm != KeyAlgorithm::P256
            || self.record.server.is_some()
            || self.record.name != credential.id
            || self.record.record_type != "item"
            || self.record.integer("gen") != Some(0)
            || self.record.integer("encver") != Some(2)
            || self.current_pointer.name != "classA"
            || self.current_pointer.record_type != "currentkey"
            || self.record.string("parentkeyref") != self.current_pointer.string("parentkeyref")
            || self.record.fields.len() != 5
        {
            return Err(invalid(
                "prepared identity, key policy or ciphertext fields do not match",
            ));
        }
        self.current_pointer
            .server_precondition(&self.binding.zone)?;
        let public = STANDARD
            .decode(&self.public_sec1)
            .map_err(|_| invalid("invalid public encoding"))?;
        if public.len() != 65
            || public[0] != 4
            || p256::PublicKey::from_sec1_bytes(&public).is_err()
        {
            return Err(invalid("invalid expected P-256 public point"));
        }
        let data = self
            .record
            .bytes("data")
            .ok_or_else(|| invalid("missing item ciphertext"))?;
        let wrapped = self
            .record
            .string("wrappedkey")
            .and_then(|s| STANDARD.decode(s).ok())
            .ok_or_else(|| invalid("invalid wrapped item key"))?;
        if data.len() < 32 || data.len() > 1024 * 1024 + 128 || wrapped.len() != 80 {
            return Err(invalid("invalid ciphertext/wrapped-key length"));
        }
        Ok(())
    }
    fn verify_payload(&self, record: &Record, snapshot: &Snapshot) -> Result<()> {
        if snapshot.zone != self.binding.zone
            || record.name != self.record.name
            || record.record_type != "item"
            || self
                .record
                .fields
                .iter()
                .any(|(key, value)| record.fields.get(key) != Some(value))
        {
            return Err(Error::Security(
                "fetched record differs from the prepared upload".into(),
            ));
        }
        let roots = snapshot
            .tlks
            .iter()
            .filter(|root| root.zone_name == self.binding.zone.name)
            .map(|root| (root.uuid.clone(), root.key.clone()))
            .collect();
        let sync_keys: Vec<_> = snapshot
            .records
            .iter()
            .filter(|r| r.record_type == "synckey")
            .cloned()
            .collect();
        let keys = unwrap_class_keys(&sync_keys, &roots)?;
        super::write::verify_new_passkey(record, &keys, &self.credential, &self.public_sec1)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Phase {
    Prepared,
    Attempted { attempt: Uuid },
    Accepted { attempt: Uuid, change_tag: String },
    FetchVerified { change_tag: String },
    Rejected,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    plan: PlanData,
    phase: Phase,
    attempts: Vec<Uuid>,
    /// Preserve earlier exact ciphertexts: a timed-out request can commit late
    /// even if a subsequent retry was explicitly rejected. All variants must
    /// represent the same immutable credential, account and browser request.
    superseded: Vec<PlanData>,
}

/// The accepted record must include its server encoding, tag and zone. A
/// precondition failure guarantees the ENTIRE atomic operation was rejected.
pub enum SaveOutcome {
    Accepted(Record),
    PreconditionFailed,
}
pub trait UploadIo {
    /// The current operation check is borrowed only for this call. Broker IO
    /// must poll it while waiting; a constructor-time guard is insufficient.
    fn fetch_zone(
        &mut self,
        zone: &ZoneIdentity,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Snapshot>;
    fn create_atomic(
        &mut self,
        attempt: Uuid,
        zone: &ZoneIdentity,
        record: &Record,
        unchanged_pointer: &Record,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<SaveOutcome>;
}

/// The containing private directory and encryption backend are supplied by the
/// broker registry. The same implementation uses temporary user-owned fixtures
/// in offline tests; it never creates a root, keypair, account or trust identity.
pub struct UploadStore<'a> {
    directory: PathBuf,
    backend: &'a dyn SecurityBackend,
}
pub struct Session<'a> {
    store: UploadStore<'a>,
    path: PathBuf,
    journal: Journal,
    _lock: File,
    healthy: bool,
}
impl<'a> UploadStore<'a> {
    pub fn new(directory: &Path, backend: &'a dyn SecurityBackend) -> Result<Self> {
        let meta = std::fs::symlink_metadata(directory).map_err(|e| Error::io(directory, e))?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != keychain_sep_driver::peer::effective_uid()
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(invalid("upload store must be a private owned directory"));
        }
        Ok(Self {
            directory: directory.into(),
            backend,
        })
    }
    fn lock(&self, transaction: Uuid) -> Result<File> {
        let path = self.directory.join(format!(".upload-{transaction}.lock"));
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| Error::io(&path, e))?;
        let meta = file.metadata().map_err(|e| Error::io(&path, e))?;
        if !meta.is_file()
            || meta.uid() != keychain_sep_driver::peer::effective_uid()
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(invalid("unsafe upload lock file"));
        }
        fs2::FileExt::try_lock_exclusive(&file)
            .map_err(|_| Error::Refused("this upload transaction is already active".into()))?;
        Ok(file)
    }
    pub fn prepare(self, upload: PreparedUpload) -> Result<Session<'a>> {
        upload.0.validate()?;
        let binding = upload.0.binding.clone();
        let lock = self.lock(binding.transaction)?;
        let path = self
            .directory
            .join(format!("upload-{}.enc", binding.transaction));
        if path.try_exists().map_err(|e| Error::io(&path, e))? {
            let session = self.load(path, lock, &binding)?;
            if serde_json::to_vec(&session.journal.plan)? != serde_json::to_vec(&upload.0)? {
                return Err(Error::Security(
                    "existing upload transaction has different prepared data".into(),
                ));
            }
            return Ok(session);
        }
        self.start(path, lock, upload)
    }

    /// Resume under the transaction lock before invoking any encryption factory.
    /// Missing/corrupt roots or existing journals are never treated as permission
    /// to generate another ciphertext. Only an absent journal calls `prepare`.
    pub fn resume_or_prepare(
        self,
        binding: &Binding,
        prepare: impl FnOnce() -> Result<PreparedUpload>,
    ) -> Result<Session<'a>> {
        binding.validate()?;
        let lock = self.lock(binding.transaction)?;
        let path = self
            .directory
            .join(format!("upload-{}.enc", binding.transaction));
        if path.try_exists().map_err(|e| Error::io(&path, e))? {
            return self.load(path, lock, binding);
        }
        let upload = prepare()?;
        upload.0.validate()?;
        if upload.binding() != binding {
            return Err(invalid("new upload differs from the selected transaction"));
        }
        self.start(path, lock, upload)
    }

    fn start(self, path: PathBuf, lock: File, upload: PreparedUpload) -> Result<Session<'a>> {
        let session = Session {
            store: self,
            path,
            journal: Journal {
                version: 1,
                plan: upload.0,
                phase: Phase::Prepared,
                attempts: vec![],
                superseded: vec![],
            },
            _lock: lock,
            healthy: true,
        };
        let envelope = session.envelope()?;
        create_private_exclusive(&session.path, &envelope)?;
        Ok(session)
    }
    pub fn resume(self, binding: &Binding) -> Result<Session<'a>> {
        binding.validate()?;
        let lock = self.lock(binding.transaction)?;
        let path = self
            .directory
            .join(format!("upload-{}.enc", binding.transaction));
        self.load(path, lock, binding)
    }
    fn load(self, path: PathBuf, lock: File, binding: &Binding) -> Result<Session<'a>> {
        let data = read_bounded(&path)?;
        if data.len() > MAX_JOURNAL + 128 {
            return Err(invalid("journal exceeds bound"));
        }
        let plain = self.backend.open(Purpose::SyncUpload, &data)?;
        if plain.len() > MAX_JOURNAL {
            return Err(invalid("journal plaintext exceeds bound"));
        }
        let journal: Journal = serde_json::from_slice(&plain)?;
        if journal.version != 1
            || journal.plan.binding != *binding
            || journal.attempts.len() > 16
            || journal.superseded.len() > MAX_REBASES
            || journal.attempts.iter().any(|id| id.get_version_num() != 4)
            || journal.attempts.iter().collect::<BTreeSet<_>>().len() != journal.attempts.len()
        {
            return Err(invalid("journal binding/version/attempt history mismatch"));
        }
        match &journal.phase {
            Phase::Attempted { attempt } | Phase::Accepted { attempt, .. }
                if journal.attempts.last() != Some(attempt) =>
            {
                return Err(invalid("invalid current upload attempt"));
            }
            Phase::Accepted { change_tag, .. } | Phase::FetchVerified { change_tag }
                if change_tag.is_empty() || change_tag.len() > 4096 =>
            {
                return Err(invalid("invalid saved server tag"));
            }
            _ => (),
        }
        journal.plan.validate()?;
        for previous in &journal.superseded {
            previous.validate()?;
            if !previous.same_credential(&journal.plan) {
                return Err(invalid("superseded upload changed its bound credential"));
            }
        }
        Ok(Session {
            store: self,
            path,
            journal,
            _lock: lock,
            healthy: true,
        })
    }
}
impl Session<'_> {
    pub fn verify_identity(
        &self,
        binding: &Binding,
        credential: &PasskeyCredential,
        public: &[u8],
    ) -> Result<()> {
        self.check_healthy()?;
        if &self.journal.plan.binding != binding
            || &self.journal.plan.credential != credential
            || self.journal.plan.public_sec1 != STANDARD.encode(public)
        {
            return Err(Error::Security(
                "saved upload differs from the selected credential or request".into(),
            ));
        }
        Ok(())
    }
    pub fn phase(&self) -> Result<&Phase> {
        self.check_healthy()?;
        Ok(&self.journal.phase)
    }
    pub fn credential(&self) -> &PasskeyCredential {
        &self.journal.plan.credential
    }
    /// Only a healthy durable FetchVerified checkpoint can supply backup
    /// evidence. An HTTP acknowledgement or a poisoned in-memory phase cannot.
    pub fn verified_upload(&self) -> Result<VerifiedUpload> {
        self.check_healthy()?;
        if !matches!(self.journal.phase, Phase::FetchVerified { .. }) {
            return Err(Error::Refused(
                "upload has not passed independent fetch/decrypt verification".into(),
            ));
        }
        Ok(VerifiedUpload {
            binding: self.journal.plan.binding.clone(),
            credential: self.journal.plan.credential.clone(),
            public_sec1: self.journal.plan.public_sec1.clone(),
        })
    }
    fn envelope(&self) -> Result<Vec<u8>> {
        let plain = Zeroizing::new(serde_json::to_vec(&self.journal)?);
        if plain.len() > MAX_JOURNAL {
            return Err(invalid("journal exceeds bound"));
        }
        self.store.backend.seal(Purpose::SyncUpload, &plain)
    }
    fn checkpoint(&mut self, phase: Phase) -> Result<()> {
        self.check_healthy()?;
        // A failed rename/fsync can leave either old or new bytes on disk. Never
        // trust in-memory phase after ANY persistence error; reopen/reconcile.
        self.healthy = false;
        self.journal.phase = phase;
        atomic_write_private(&self.path, &self.envelope()?)?;
        self.healthy = true;
        Ok(())
    }
    fn check_healthy(&self) -> Result<()> {
        if !self.healthy {
            return Err(Error::Refused(
                "upload checkpoint failed; reopen and reconcile this transaction".into(),
            ));
        }
        Ok(())
    }
    fn check_pointer(&self, snapshot: &Snapshot) -> Result<()> {
        if snapshot.zone != self.journal.plan.binding.zone {
            return Err(invalid("snapshot zone changed"));
        }
        let saved = &self.journal.plan.current_pointer;
        let current = snapshot
            .records
            .iter()
            .find(|record| record.name == saved.name)
            .ok_or_else(|| invalid("current pointer disappeared"))?;
        let metadata = current.server_precondition(&snapshot.zone)?;
        if current.record_type != saved.record_type
            || current.fields != saved.fields
            || metadata.change_tag != saved.server_precondition(&snapshot.zone)?.change_tag
        {
            return Err(Error::Refused(
                "current key/precondition changed; keep this key and prepare a reconciled upload"
                    .into(),
            ));
        }
        Ok(())
    }
    pub fn advance(&mut self, io: &mut dyn UploadIo, check: &dyn Fn() -> Result<()>) -> Result<()> {
        check()?;
        self.check_healthy()?;
        if matches!(self.journal.phase, Phase::FetchVerified { .. }) {
            return Ok(());
        }
        let zone = self.journal.plan.binding.zone.clone();
        let snapshot = io.fetch_zone(&zone, check)?;
        check()?;
        if let Some(record) = snapshot
            .records
            .iter()
            .find(|r| r.name == self.journal.plan.record.name)
        {
            let prepared = std::iter::once(&self.journal.plan)
                .chain(&self.journal.superseded)
                .find(|plan| {
                    plan.record.record_type == record.record_type
                        && plan
                            .record
                            .fields
                            .iter()
                            .all(|(key, value)| record.fields.get(key) == Some(value))
                })
                .ok_or_else(|| {
                    Error::Security(
                        "fetched record differs from every retained upload; refusing overwrite"
                            .into(),
                    )
                })?;
            prepared.verify_payload(record, &snapshot)?;
            check()?;
            let tag = record
                .server_precondition(&zone)?
                .change_tag
                .clone()
                .ok_or_else(|| invalid("fetched record omitted tag"))?;
            // No caller-supplied "uploaded" boolean: exact ciphertext, decrypted
            // identity and expected public point have all been checked here.
            return self.checkpoint(Phase::FetchVerified { change_tag: tag });
        }
        if !matches!(self.journal.phase, Phase::Prepared) {
            return Err(Error::Refused(
                "upload outcome is unresolved; no automatic resend or new key".into(),
            ));
        }
        if let Err(error) = self.check_pointer(&snapshot) {
            self.checkpoint(Phase::Rejected)?;
            return Err(error);
        }
        if self.journal.attempts.len() >= 16 {
            return Err(Error::Refused("upload retry budget exhausted".into()));
        }
        let attempt = Uuid::new_v4();
        check()?;
        self.journal.attempts.push(attempt);
        self.checkpoint(Phase::Attempted { attempt })?; // Must precede ANY send.
        let outcome = io.create_atomic(
            attempt,
            &zone,
            &self.journal.plan.record,
            &self.journal.plan.current_pointer,
            check,
        )?;
        check()?;
        match outcome {
            SaveOutcome::PreconditionFailed => {
                self.checkpoint(Phase::Rejected)?;
                return Err(Error::Refused(
                    "Apple rejected the atomic precondition; prepared key retained".into(),
                ));
            }
            SaveOutcome::Accepted(record) => {
                if record.name != self.journal.plan.record.name
                    || record.record_type != "item"
                    || self
                        .journal
                        .plan
                        .record
                        .fields
                        .iter()
                        .any(|(key, value)| record.fields.get(key) != Some(value))
                {
                    return Err(Error::Security(
                        "save acknowledgment did not identify the prepared record".into(),
                    ));
                }
                let tag = record
                    .server_precondition(&zone)?
                    .change_tag
                    .clone()
                    .ok_or_else(|| invalid("save acknowledgment omitted tag"))?;
                self.checkpoint(Phase::Accepted {
                    attempt,
                    change_tag: tag,
                })?;
            }
        }
        self.advance(io, check) // Independent post-acceptance fetch/decrypt, no resend.
    }
    /// Explicit retry only after a fresh complete snapshot reports absence and
    /// the original current-key precondition still holds. Ciphertext/identity
    /// remain unchanged. Known acceptance/rejection never takes this path.
    pub fn retry_after_absence(
        &mut self,
        io: &mut dyn UploadIo,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        check()?;
        self.check_healthy()?;
        if !matches!(self.journal.phase, Phase::Attempted { .. }) {
            return Err(Error::Refused(
                "only an uncertain attempt can be retried".into(),
            ));
        }
        let snapshot = io.fetch_zone(&self.journal.plan.binding.zone, check)?;
        check()?;
        if snapshot
            .records
            .iter()
            .any(|r| r.name == self.journal.plan.record.name)
        {
            return Err(Error::Refused(
                "the record exists; reconcile it instead of resending".into(),
            ));
        }
        self.check_pointer(&snapshot)?;
        check()?;
        self.checkpoint(Phase::Prepared)
    }

    /// Explicit re-encryption/rebase after a definite precondition rejection.
    /// First fetch complete absence; only then let the selected-secret operation
    /// prepare the same credential under that snapshot's authenticated key.
    /// This does not send. Earlier ciphertexts and attempt history stay durable
    /// so a late commit of an older request remains independently verifiable.
    pub fn reprepare_after_rejection(
        &mut self,
        io: &mut dyn UploadIo,
        check: &dyn Fn() -> Result<()>,
        prepare: impl FnOnce(&Binding, &PasskeyCredential, &Snapshot) -> Result<PreparedUpload>,
    ) -> Result<()> {
        check()?;
        self.check_healthy()?;
        if self.journal.phase != Phase::Rejected {
            return Err(Error::Refused(
                "only a rejected upload may be re-encrypted".into(),
            ));
        }
        if self.journal.attempts.len() >= 16 {
            return Err(Error::Refused("upload retry budget exhausted".into()));
        }
        if self.journal.superseded.len() >= MAX_REBASES {
            return Err(Error::Refused(
                "upload re-encryption budget exhausted; all prior ciphertexts retained".into(),
            ));
        }
        let snapshot = io.fetch_zone(&self.journal.plan.binding.zone, check)?;
        check()?;
        if snapshot.zone != self.journal.plan.binding.zone {
            return Err(invalid("re-encryption snapshot changed account/zone"));
        }
        if snapshot
            .records
            .iter()
            .any(|record| record.name == self.journal.plan.record.name)
        {
            return Err(Error::Refused(
                "the record exists; reconcile it before preparing another upload".into(),
            ));
        }
        let candidate = prepare(
            &self.journal.plan.binding,
            &self.journal.plan.credential,
            &snapshot,
        )?;
        check()?;
        if !candidate.0.same_credential(&self.journal.plan) {
            return Err(Error::Security(
                "re-encryption changed the credential, key or request binding".into(),
            ));
        }
        // Revalidate against the snapshot fetched by THIS operation, including
        // its fresh pointer/tag and independent decryption/public-key checks.
        let public = STANDARD
            .decode(&candidate.0.public_sec1)
            .map_err(|_| invalid("invalid re-encryption point"))?;
        let candidate = PreparedUpload::from_snapshot(
            candidate.0.binding,
            candidate.0.credential,
            &public,
            candidate.0.record,
            &snapshot,
        )?;
        check()?;
        if serde_json::to_vec(&candidate.0)? != serde_json::to_vec(&self.journal.plan)? {
            self.journal.superseded.push(self.journal.plan.clone());
            self.journal.plan = candidate.0;
        }
        // As with every checkpoint, persistence failure poisons this in-memory
        // session. Reopen to determine whether the old or new plan is durable.
        self.checkpoint(Phase::Prepared)
    }
}
fn invalid(message: &str) -> Error {
    Error::InvalidData(format!("CKKS upload: {message}"))
}

#[cfg(test)]
pub(crate) mod tests;
