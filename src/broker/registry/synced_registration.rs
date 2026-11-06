//! Durable broker-owned exportable key preparation. Drafts are deliberately
//! outside the generic import/verification namespace: neither sync nor a caller
//! with VerifyProtected can turn an unfinished iCloud registration into a key.

use super::*;
use crate::apple::ckks::upload::{Binding, VerifiedUpload};
use crate::passkey::registration::{CreationContext, Registration};
use crate::security::authorization::AuthorizedSignature;
use crate::security::{KeyAlgorithm, KeyRef, KeyUsage};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use sha1::{Digest, Sha1};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    binding: Binding,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftData {
    version: u32,
    binding: Binding,
    record: ProtectedRecord,
    phase: CreationPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CreationPhase {
    Prepared,
    Activating,
    Committed,
}

/// Only the root registry constructs this value. It contains a sealed scalar,
/// never plaintext, and does not imply biometric authorization or cloud backup.
pub struct SyncedCreation(DraftData);
impl SyncedCreation {
    pub fn binding(&self) -> &Binding {
        &self.0.binding
    }
    pub fn record(&self) -> &ProtectedRecord {
        &self.0.record
    }
}

impl Registry {
    fn synced_creation_filename(&self, id: &str, intent: bool) -> Result<PathBuf> {
        self.filename(id)?;
        Ok(self.directory.join(if intent {
            format!("synced-create-{id}.pending.enc")
        } else {
            format!("synced-create-{id}.enc")
        }))
    }

    pub(super) fn synced_creation_exists(&self, id: &str) -> Result<bool> {
        for intent in [false, true] {
            let path = self.synced_creation_filename(id, intent)?;
            if path.try_exists().map_err(|e| Error::io(&path, e))? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Metadata only, for sync's no-fallback decision. Intent without a durable
    /// key is an error rather than an empty state that could trigger an import.
    pub(super) fn synced_creation_summary(
        &self,
        id: &str,
        owner: u32,
    ) -> Result<Option<ProtectedSummary>> {
        let path = self.synced_creation_filename(id, false)?;
        if path.try_exists().map_err(|e| Error::io(&path, e))? {
            let data = self.read_synced_creation(id, owner)?;
            if data.phase == CreationPhase::Committed {
                return Ok(None);
            }
            return Ok(Some(data.record.into()));
        }
        if self.synced_creation_exists(id)? {
            return Err(Error::Refused(
                "synced registration has an interrupted key-creation intent".into(),
            ));
        }
        Ok(None)
    }

    fn read_synced_creation(&self, id: &str, owner: u32) -> Result<DraftData> {
        let path = self.synced_creation_filename(id, false)?;
        let data = read_bounded(&path)?;
        if data.len() > 64 * 1024 {
            return Err(Error::InvalidData(
                "synced registration draft exceeds limit".into(),
            ));
        }
        let plain = self.backend.open(Purpose::Vault, &data)?;
        let draft: DraftData = serde_json::from_slice(&plain)?;
        draft.binding.validate()?;
        draft.record.validate(id, owner)?;
        if draft.version != 1
            || draft.binding.owner != owner
            || draft.binding.transaction.to_string() != id
            || draft.record.revision != 1
            || draft.record.verified
            || draft.record.diagnostic
            || draft.record.recipient_id != self.item_recipient()?.id
        {
            return Err(Error::Security(
                "synced registration draft identity/policy mismatch".into(),
            ));
        }
        self.check_synced_active(&draft)?;
        Ok(draft)
    }

    /// Validate an interrupted or completed promotion without relying on its
    /// in-memory state. Later normal sync may refresh metadata or rewrap the
    /// same key; it cannot substitute the original public credential identity.
    fn check_synced_active(&self, draft: &DraftData) -> Result<Option<ProtectedRecord>> {
        let expected = &draft.record;
        let path = self.protected_filename(&expected.credential.id)?;
        if !path.try_exists().map_err(|e| Error::io(&path, e))? {
            return if draft.phase == CreationPhase::Committed {
                Err(Error::Security(
                    "committed synced credential is missing; refusing replacement".into(),
                ))
            } else {
                Ok(None)
            };
        }
        if draft.phase == CreationPhase::Prepared {
            return Err(Error::Security(
                "protected record collides with unpromoted registration".into(),
            ));
        }
        let active = self.read_protected(&path, &expected.credential.id, expected.owner)?;
        if !active.verified
            || active.diagnostic
            || active.credential.signing_key != expected.credential.signing_key
            || !crate::protection::same_identity(&active.credential, &expected.credential)
            || active.public_sec1 != expected.public_sec1
            || active.recipient_id != expected.recipient_id
            || (active.revision == 1 && active.sealed != expected.sealed)
            || (draft.phase == CreationPhase::Activating
                && (active.revision != 1 || active.credential != expected.credential))
        {
            return Err(Error::Security(
                "promoted registration changed its protected key or identity".into(),
            ));
        }
        Ok(Some(active))
    }

    /// Bind a new exportable key to an exact request, owner, account and peer.
    /// No Apple access or biometric capture occurs here. The durable intent
    /// precedes RNG; an interrupted intent never silently generates another key.
    /// Retrying an existing draft returns the exact same sealed key and metadata.
    pub fn prepare_synced_registration(
        &self,
        binding: &Binding,
        context: &CreationContext,
    ) -> Result<SyncedCreation> {
        binding.validate()?;
        if binding.request_sha256 != context.binding() {
            return Err(Error::Security(
                "synced registration request binding mismatch".into(),
            ));
        }
        let _lock = self.update_lock()?;
        let id = binding.transaction.to_string();
        let path = self.synced_creation_filename(&id, false)?;
        // Shared transaction IDs cannot switch between native creation, generic
        // imports and cloud creation, even if one path has not completed.
        for name in [
            format!("{id}.enc"),
            format!("{id}.pending.enc"),
            format!("protected-{id}.pending.enc"),
        ] {
            let other = self.directory.join(name);
            if other.try_exists().map_err(|e| Error::io(&other, e))? {
                return Err(Error::Refused(
                    "registration transaction already belongs to another storage path".into(),
                ));
            }
        }
        if path.try_exists().map_err(|e| Error::io(&path, e))? {
            let draft = self.read_synced_creation(&id, binding.owner)?;
            Self::check_synced_context(&draft, binding, context)?;
            return Ok(SyncedCreation(draft));
        }
        let active_path = self.protected_filename(&id)?;
        if active_path
            .try_exists()
            .map_err(|e| Error::io(&active_path, e))?
        {
            return Err(Error::Refused(
                "registration transaction already belongs to protected storage".into(),
            ));
        }
        let intent_path = self.synced_creation_filename(&id, true)?;
        if intent_path
            .try_exists()
            .map_err(|e| Error::io(&intent_path, e))?
        {
            let data = read_bounded(&intent_path)?;
            if data.len() > 4096 {
                return Err(Error::InvalidData(
                    "synced registration intent exceeds limit".into(),
                ));
            }
            let plain = self.backend.open(Purpose::Vault, &data)?;
            let intent: Intent = serde_json::from_slice(&plain)?;
            if intent.version != 1 || &intent.binding != binding {
                return Err(Error::Security(
                    "synced registration intent binding mismatch".into(),
                ));
            }
            return Err(Error::Refused("synced key creation was interrupted before durable storage; start a new registration explicitly".into()));
        }
        let mut count = 0;
        for entry in
            std::fs::read_dir(&self.directory).map_err(|e| Error::io(&self.directory, e))?
        {
            let entry = entry.map_err(|e| Error::io(&self.directory, e))?;
            count += usize::from(entry.path().extension().is_some_and(|e| e == "enc"));
        }
        if count >= 4096 {
            return Err(Error::Refused(
                "broker registry is full; no new key was created".into(),
            ));
        }
        if self
            .browser_credentials(binding.owner)?
            .iter()
            .any(|c| context.excludes(c))
        {
            return Err(Error::Refused("registration cannot proceed".into()));
        }
        let recipient = self.item_recipient()?;
        let intent = Intent {
            version: 1,
            binding: binding.clone(),
        };
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&intent)?);
        create_private_exclusive(&intent_path, &self.backend.seal(Purpose::Vault, &plain)?)?;

        // Allocate/protect before random bytes arrive. The scalar's canonical
        // storage stays here until sealing finishes; library key temporaries
        // zeroize on drop but are not claimed to be entirely locked memory.
        let mut memory = keychain_sep_driver::memory::SecretBuffer::new()
            .map_err(|e| Error::io("synced key generation memory", e))?;
        let scalar = &mut memory.as_mut_array()[..32];
        let mut public = None;
        for _ in 0..128 {
            rand::rngs::OsRng
                .try_fill_bytes(scalar)
                .map_err(|_| Error::Security("synced key randomness unavailable".into()))?;
            if let Ok(secret) = p256::SecretKey::from_slice(scalar) {
                public = Some(secret.public_key().to_encoded_point(false));
                break;
            }
        }
        let public = public
            .ok_or_else(|| Error::Security("could not generate a valid P-256 scalar".into()))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Security("system clock predates Unix epoch".into()))?
            .as_secs_f64();
        let credential = PasskeyCredential {
            provenance: PasskeyProvenance::Synced,
            id: id.clone(),
            rp_id: context.rp_id().into(),
            credential_id: URL_SAFE_NO_PAD.encode(Sha1::digest(public.as_bytes())),
            user_handle: context.user_handle().into(),
            username: context.username().into(),
            display_name: context.display_name().into(),
            created_at: now,
            modified_at: now,
            signing_key: KeyRef {
                backend_id: "sep-protected-software-v1".into(),
                key_id: id.clone(),
                algorithm: KeyAlgorithm::P256,
                usage: KeyUsage::WebAuthnSigning,
            },
        };
        let import =
            ProtectedImport::seal_scalar(binding.owner, &recipient, 0, credential, scalar, false)?;
        let draft = DraftData {
            version: 1,
            binding: binding.clone(),
            phase: CreationPhase::Prepared,
            record: ProtectedRecord {
                version: 1,
                owner: binding.owner,
                revision: 1,
                recipient_id: import.recipient_id,
                credential: import.credential,
                public_sec1: import.public_sec1,
                sealed: import.sealed,
                diagnostic: false,
                verified: false,
            },
        };
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&draft)?);
        // Absence was checked under the registry update lock; publish only a
        // complete fsynced envelope. Intent remains if rename/fsync is uncertain.
        atomic_write_private(&path, &self.backend.seal(Purpose::Vault, &plain)?)?;
        let stored = self.read_synced_creation(&id, binding.owner)?;
        Self::check_synced_context(&stored, binding, context)?;
        // Retain the intent as a transaction tombstone; no reusable grant lives
        // in either file, and retries consult the complete draft first.
        Ok(SyncedCreation(stored))
    }

    /// Finish only the saved request and key. The upload receipt authorizes no
    /// signing: the callback must return fresh, exact-message/key-bound SEP UV.
    /// `check` is the broker's cancellation/session/deadline guard. A late cancel
    /// suppresses delivery even if the durable credential already committed.
    pub fn finish_synced_registration(
        &self,
        binding: &Binding,
        context: &CreationContext,
        verified: &VerifiedUpload,
        signer: impl FnOnce(&ProtectedRecord, &[u8]) -> Result<AuthorizedSignature>,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Registration> {
        binding.validate()?;
        check()?;
        let id = binding.transaction.to_string();
        let draft = {
            let _lock = self.update_lock()?;
            let draft = self.read_synced_creation(&id, binding.owner)?;
            Self::check_synced_context(&draft, binding, context)?;
            self.refuse_synced_update_collision(&id)?;
            draft
        };
        let record = &draft.record;
        let public = decode_public(&record.public_sec1)?;
        let response = context.finish_synced_registration(
            binding,
            verified,
            &record.credential,
            &public,
            |_, message, _| signer(record, message),
        )?;
        check()?;
        {
            let _lock = self.update_lock()?;
            let mut current = self.read_synced_creation(&id, binding.owner)?;
            if serde_json::to_vec(&current)? != serde_json::to_vec(&draft)? {
                return Err(Error::Refused(
                    "registration changed during authorization; retry with fresh authorization"
                        .into(),
                ));
            }
            self.refuse_synced_update_collision(&id)?;
            check()?;
            if current.phase == CreationPhase::Prepared {
                current.phase = CreationPhase::Activating;
                self.write_synced_creation(&current)?;
            }
            // Once Activating is durable, an intermediate protected file is
            // hidden from lookup/use until Committed. Reopen on every retry.
            if self.check_synced_active(&current)?.is_none() {
                let mut active = current.record.clone();
                active.verified = true;
                self.write_protected(&active, true)?;
            }
            self.include_synced_record(&id, binding.owner)?;
            if current.phase != CreationPhase::Committed {
                current.phase = CreationPhase::Committed;
                self.write_synced_creation(&current)?;
            }
            // Reopen the complete durable chain before response delivery. A
            // failed read may follow a successful commit; retry still uses the
            // original key and requires new signing authorization.
            self.read_synced_creation(&id, binding.owner)?;
        }
        check()?;
        Ok(response)
    }

    fn refuse_synced_update_collision(&self, id: &str) -> Result<()> {
        for path in [
            self.filename(id)?,
            self.directory.join(format!("{id}.pending.enc")),
            self.pending_filename(id)?,
        ] {
            if path.try_exists().map_err(|e| Error::io(&path, e))? {
                return Err(Error::Refused(
                    "another credential operation owns this registration transaction".into(),
                ));
            }
        }
        Ok(())
    }

    fn write_synced_creation(&self, draft: &DraftData) -> Result<()> {
        let path = self.synced_creation_filename(&draft.record.credential.id, false)?;
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(draft)?);
        atomic_write_private(&path, &self.backend.seal(Purpose::Vault, &plain)?)
    }

    fn check_synced_context(
        draft: &DraftData,
        binding: &Binding,
        context: &CreationContext,
    ) -> Result<()> {
        let c = &draft.record.credential;
        if &draft.binding != binding
            || c.rp_id != context.rp_id()
            || c.user_handle != context.user_handle()
            || c.username != context.username()
            || c.display_name != context.display_name()
            || context.excludes(c)
        {
            return Err(Error::Security(
                "synced registration belongs to another request or identity".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
