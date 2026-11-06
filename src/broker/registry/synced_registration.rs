//! Durable broker-owned exportable key preparation. Drafts are deliberately
//! outside the generic import/verification namespace: neither sync nor a caller
//! with VerifyProtected can turn an unfinished iCloud registration into a key.

use super::*;
use crate::apple::ckks::upload::Binding;
use crate::passkey::registration::CreationContext;
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
        Ok(draft)
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
            format!("protected-{id}.enc"),
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
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    fn context() -> Result<CreationContext> {
        CreationContext::parse(&serde_json::json!({
            "rp":{"id":"example.com","name":"Example"},
            "user":{"id":URL_SAFE_NO_PAD.encode(b"user"),"name":"Test User","displayName":"Test"},
            "challenge":URL_SAFE_NO_PAD.encode([23u8;32]),
            "pubKeyCredParams":[{"type":"public-key","alg":-7}],
            "extensions":{"remoteDesktopClientOverride":{"origin":"https://example.com","sameOriginWithAncestors":true}}
        }).to_string())
    }
    fn binding(context: &CreationContext) -> Binding {
        Binding {
            owner: 1001,
            account_fingerprint: format!("SHA256:{}", STANDARD.encode([1u8; 32])),
            peer_id: format!("SHA256:{}", STANDARD.encode([2u8; 32])),
            transaction: Uuid::new_v4(),
            request_sha256: context.binding().into(),
            zone: crate::apple::ckks::ZoneIdentity {
                name: "Passwords".into(),
                owner: "test-cloud-owner".into(),
            },
        }
    }
    fn registry(dir: &Path) -> Result<Registry> {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::io(dir, e))?;
        let registry = Registry::open(dir)?;
        let secret = p256::SecretKey::from_slice(&[7u8; 32])
            .map_err(|_| Error::Security("test key".into()))?;
        let key: StoredSepKey = serde_json::from_value(serde_json::json!({
            "version":1,"reference":KeyRef {backend_id:"sep-native-v1".into(),key_id:Uuid::new_v4().to_string(),usage:KeyUsage::WebAuthnSigning,algorithm:KeyAlgorithm::P256},
            "policy":"biometry-any","wrapped_blob":STANDARD.encode(b"synthetic wrapped blob"),
            "public_sec1":STANDARD.encode(secret.public_key().to_encoded_point(false).as_bytes()),"allow_decrypt":true
        }))?;
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&key)?);
        create_private_exclusive(
            &dir.join("item-recipient.enc"),
            &registry.backend.seal(Purpose::KeyStore, &plain)?,
        )?;
        Ok(registry)
    }

    // This exercises root-owned persistence and real memory policy, but uses a
    // synthetic recipient and software decryption: no SEP, UI or Apple access.
    #[test]
    #[ignore = "requires root; disposable synthetic registry only, no hardware or network"]
    fn synced_creation_seals_one_stable_key_and_cannot_be_activated_as_an_import() -> Result<()> {
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
        let dir = tempfile::tempdir().map_err(|e| Error::io("temporary root", e))?;
        let registry = registry(dir.path())?;
        let context = context()?;
        let binding = binding(&context);
        let draft = registry.prepare_synced_registration(&binding, &context)?;
        assert_eq!(draft.binding(), &binding);
        let record = draft.record();
        assert!(!record.verified);
        assert_eq!(record.credential.provenance, PasskeyProvenance::Synced);
        assert_eq!(
            record.credential.signing_key.backend_id,
            "sep-protected-software-v1"
        );
        let public = STANDARD
            .decode(&record.public_sec1)
            .map_err(|_| Error::Security("test public".into()))?;
        assert_eq!(
            record.credential.credential_id,
            URL_SAFE_NO_PAD.encode(Sha1::digest(&public))
        );

        // Independently decrypt to prove the saved scalar matches its public
        // identity and exact item context. All secrets here are disposable.
        use aes_gcm::aead::{Aead, KeyInit, consts::U16};
        use p256::ecdh::diffie_hellman;
        use sha2::Sha256;
        let recipient = p256::SecretKey::from_slice(&[7u8; 32])
            .map_err(|_| Error::Security("test key".into()))?;
        let ephemeral = p256::PublicKey::from_sec1_bytes(&record.sealed[..65])
            .map_err(|_| Error::Security("test ephemeral".into()))?;
        let shared = diffie_hellman(recipient.to_nonzero_scalar(), ephemeral.as_affine());
        let mut material = zeroize::Zeroizing::new([0u8; 64]);
        for index in 1u32..=2 {
            let mut hash = Sha256::new();
            hash.update(shared.raw_secret_bytes());
            hash.update(index.to_be_bytes());
            hash.update(&record.sealed[..65]);
            let offset = (index as usize - 1) * 32;
            material[offset..offset + 32].copy_from_slice(&hash.finalize());
        }
        let cipher = aes_gcm::AesGcm::<aes::Aes256, U16>::new_from_slice(&material[..32])
            .map_err(|_| Error::Security("test cipher".into()))?;
        let plain = zeroize::Zeroizing::new(
            cipher
                .decrypt(
                    aes_gcm::Nonce::<U16>::from_slice(&material[32..48]),
                    &record.sealed[65..],
                )
                .map_err(|_| Error::Security("test decrypt".into()))?,
        );
        let expected = item_binding(
            binding.owner,
            1,
            &record.recipient_id,
            &record.credential,
            &record.public_sec1,
        )?;
        let scalar = crate::security::sep::envelope::item_view(&plain, plain.len(), &expected)?;
        let recovered = p256::SecretKey::from_slice(scalar)
            .map_err(|_| Error::Security("test scalar".into()))?;
        assert_eq!(
            recovered.public_key().to_encoded_point(false).as_bytes(),
            public
        );
        let disk = registry.backend.open(
            Purpose::Vault,
            &read_bounded(&registry.synced_creation_filename(&record.credential.id, false)?)?,
        )?;
        assert!(!disk.windows(32).any(|bytes| bytes == scalar));
        assert!(registry.browser_credentials(binding.owner)?.is_empty());
        let state = registry.protection_state(&record.credential.id, binding.owner)?;
        assert!(state.active.is_none());
        assert!(state.staged.is_some());
        assert!(
            registry
                .verification_record(&record.credential.id, binding.owner)
                .is_err()
        );
        assert!(
            registry
                .load_protected(&record.credential.id, binding.owner)
                .is_err()
        );
        let import = ProtectedImport::seal_scalar(
            binding.owner,
            &registry.item_recipient()?,
            0,
            record.credential.clone(),
            scalar,
            false,
        )?;
        assert!(registry.import_protected(binding.owner, import).is_err());
        assert!(
            registry
                .prepare_registration(binding.owner, binding.transaction, &context, || panic!(
                    "draft reached native CREATE"
                ))
                .is_err()
        );
        let original = serde_json::to_vec(record)?;
        drop(registry);
        let reopened = Registry::open(dir.path())?;
        let resumed = reopened.prepare_synced_registration(&binding, &context)?;
        assert_eq!(serde_json::to_vec(resumed.record())?, original);
        for field in 0..5 {
            let mut changed = binding.clone();
            match field {
                0 => changed.owner += 1,
                1 => changed.account_fingerprint = format!("SHA256:{}", STANDARD.encode([9u8; 32])),
                2 => changed.peer_id = format!("SHA256:{}", STANDARD.encode([9u8; 32])),
                3 => changed.request_sha256 = "a1".repeat(32),
                _ => changed.zone.owner = "other-owner".into(),
            }
            assert!(
                reopened
                    .prepare_synced_registration(&changed, &context)
                    .is_err()
            );
        }
        assert_eq!(
            serde_json::to_vec(
                reopened
                    .prepare_synced_registration(&binding, &context)?
                    .record()
            )?,
            original
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires root; disposable synthetic registry only, no hardware or network"]
    fn synced_creation_refuses_interrupted_intents_collisions_and_missing_recipient() -> Result<()>
    {
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
        let dir = tempfile::tempdir().map_err(|e| Error::io("temporary root", e))?;
        let registry = registry(dir.path())?;
        let context = context()?;
        let binding = binding(&context);
        let draft = registry.prepare_synced_registration(&binding, &context)?;
        let path = registry.synced_creation_filename(&draft.record().credential.id, false)?;
        // Simulate interruption after durable intent and before durable key.
        std::fs::remove_file(&path).map_err(|e| Error::io(&path, e))?;
        drop(registry);
        let registry = Registry::open(dir.path())?;
        assert!(
            registry
                .prepare_synced_registration(&binding, &context)
                .is_err()
        );
        assert!(!path.exists());
        assert!(
            registry
                .protection_state(&binding.transaction.to_string(), binding.owner)
                .is_err()
        );
        assert!(registry.browser_credentials(binding.owner)?.is_empty());
        let other = Binding {
            transaction: Uuid::new_v4(),
            ..binding.clone()
        };
        let collision = registry
            .directory
            .join(format!("{}.pending.enc", other.transaction));
        create_private_exclusive(&collision, b"native intent")?;
        assert!(
            registry
                .prepare_synced_registration(&other, &context)
                .is_err()
        );
        assert!(!registry.synced_creation_exists(&other.transaction.to_string())?);
        let recipient = registry.directory.join("item-recipient.enc");
        std::fs::remove_file(&recipient).map_err(|e| Error::io(&recipient, e))?;
        let another = Binding {
            transaction: Uuid::new_v4(),
            ..binding
        };
        assert!(
            registry
                .prepare_synced_registration(&another, &context)
                .is_err()
        );
        assert!(!registry.synced_creation_exists(&another.transaction.to_string())?);
        assert!(!recipient.exists());
        Ok(())
    }
}
