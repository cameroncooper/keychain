use super::*;
use crate::passkey::registration::CreationContext;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u32,
    owner: u32,
    transaction: Uuid,
    binding: String,
}

impl Registry {
    /// Persist the key before beginning biometric authorization or returning any
    /// registration response. A transaction can only resume its original request.
    pub(crate) fn prepare_registration(
        &self,
        owner: u32,
        transaction: Uuid,
        context: &CreationContext,
        create: impl FnOnce() -> Result<StoredSepKey>,
    ) -> Result<Record> {
        if transaction.get_version_num() != 4 {
            return Err(Error::InvalidData(
                "registration transaction must be a random UUID v4".into(),
            ));
        }
        let _lock = self.update_lock()?;
        let id = transaction.to_string();
        let path = self.filename(&id)?;
        if path.try_exists().map_err(|e| Error::io(&path, e))? {
            let record = self.load(&id, owner)?;
            Self::check_registration(&record, context)?;
            return Ok(record);
        }
        let intent_path = self.directory.join(format!("{id}.pending.enc"));
        if intent_path
            .try_exists()
            .map_err(|e| Error::io(&intent_path, e))?
        {
            let data = read_bounded(&intent_path)?;
            if data.len() > 4096 {
                return Err(Error::InvalidData(
                    "registration intent exceeds limit".into(),
                ));
            }
            let plain = self.backend.open(Purpose::Vault, &data)?;
            let intent: Intent = serde_json::from_slice(&plain)?;
            if intent.version != 1
                || intent.owner != owner
                || intent.transaction != transaction
                || intent.binding != context.binding()
            {
                return Err(Error::Security(
                    "registration intent identity mismatch".into(),
                ));
            }
            // CREATE may have completed without returning a durable wrapped key.
            // Never repeat it for this transaction, even after process restart.
            return Err(Error::Refused("registration key creation was interrupted before durable storage; start a new registration request explicitly".into()));
        }
        let credentials = self.browser_credentials(owner)?;
        if credentials.iter().any(|c| context.excludes(c)) {
            return Err(Error::Refused("registration cannot proceed".into()));
        }
        // Also bound abandoned Prepared records, not just eligible credentials.
        let count = std::fs::read_dir(&self.directory)
            .map_err(|e| Error::io(&self.directory, e))?
            .try_fold(0usize, |count, entry| -> Result<usize> {
                let entry = entry.map_err(|e| Error::io(&self.directory, e))?;
                Ok(count + usize::from(entry.path().extension().is_some_and(|e| e == "enc")))
            })?;
        if count >= 4096 {
            return Err(Error::Refused(
                "broker registry is full; no new key was created".into(),
            ));
        }
        let intent = Intent {
            version: 1,
            owner,
            transaction,
            binding: context.binding().into(),
        };
        let intent_plain = zeroize::Zeroizing::new(serde_json::to_vec(&intent)?);
        create_private_exclusive(
            &intent_path,
            &self.backend.seal(Purpose::Vault, &intent_plain)?,
        )?;
        let key = create()?;
        let mut credential_id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut credential_id);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Security("system clock predates Unix epoch".into()))?
            .as_secs_f64();
        let record = Record {
            version: 1,
            owner,
            diagnostic: false,
            registered: false,
            creation_binding: Some(context.binding().into()),
            credential: PasskeyCredential {
                provenance: PasskeyProvenance::DeviceBound,
                id,
                rp_id: context.rp_id().into(),
                credential_id: URL_SAFE_NO_PAD.encode(credential_id),
                user_handle: context.user_handle().into(),
                username: context.username().into(),
                display_name: context.display_name().into(),
                created_at: now,
                modified_at: now,
                signing_key: key.reference().clone(),
            },
            native_key: key,
        };
        self.save_new(&record)?;
        // Reopen the durable record before authorizing; persistence failure never
        // returns an identity that only existed in the original process memory.
        let stored = self.load(&record.credential.id, owner)?;
        Self::check_registration(&stored, context)?;
        std::fs::remove_file(&intent_path).map_err(|e| Error::io(&intent_path, e))?;
        std::fs::File::open(&self.directory)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| Error::io(&self.directory, e))?;
        Ok(stored)
    }

    fn check_registration(record: &Record, context: &CreationContext) -> Result<()> {
        if record.diagnostic
            || record.creation_binding.as_deref() != Some(context.binding())
            || record.credential.rp_id != context.rp_id()
            || record.credential.user_handle != context.user_handle()
            || record.credential.username != context.username()
            || record.credential.display_name != context.display_name()
        {
            return Err(Error::Security(
                "registration transaction is bound to a different request or identity".into(),
            ));
        }
        Ok(())
    }

    /// Called only after a verified native operation and final session/cancel
    /// check. Deliverable means locally usable; it does not claim RP acceptance.
    /// Keep the original binding/key so retry after uncertain delivery requires a
    /// fresh fingerprint for the same identity, never a stored authorization grant.
    pub(crate) fn registration_deliverable(
        &self,
        owner: u32,
        transaction: Uuid,
        context: &CreationContext,
        expected_key: &crate::security::KeyRef,
    ) -> Result<()> {
        let _lock = self.update_lock()?;
        let mut record = self.load(&transaction.to_string(), owner)?;
        Self::check_registration(&record, context)?;
        if record.credential.signing_key != *expected_key {
            return Err(Error::Security(
                "registration key changed before commit".into(),
            ));
        }
        if !record.registered {
            record.registered = true;
            let plain = zeroize::Zeroizing::new(serde_json::to_vec(&record)?);
            atomic_write_private(
                &self.filename(&record.credential.id)?,
                &self.backend.seal(Purpose::Vault, &plain)?,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    fn key() -> StoredSepKey {
        let secret = p256::SecretKey::from_slice(&[7u8; 32]).unwrap_or_else(|e| panic!("key: {e}"));
        serde_json::from_value(serde_json::json!({
            "version":1,"reference":crate::security::KeyRef {
                backend_id:"sep-native-v1".into(), key_id:Uuid::new_v4().to_string(),
                usage:crate::security::KeyUsage::WebAuthnSigning, algorithm:crate::security::KeyAlgorithm::P256 },
            "policy":"biometry-any","wrapped_blob":STANDARD.encode(b"synthetic wrapped blob"),
            "public_sec1":STANDARD.encode(secret.public_key().to_encoded_point(false).as_bytes()),
            "allow_decrypt":false,
        }))
        .unwrap_or_else(|e| panic!("key fixture: {e}"))
    }

    fn details() -> serde_json::Value {
        serde_json::json!({"rp":{"id":"example.com","name":"Example"},
            "user":{"id":"AQ","name":"user","displayName":"User"},
            "challenge":URL_SAFE_NO_PAD.encode([0u8;32]),
            "pubKeyCredParams":[{"type":"public-key","alg":-7}],
            "extensions":{"remoteDesktopClientOverride":{"origin":"https://example.com","sameOriginWithAncestors":true}}})
    }

    #[test]
    #[ignore = "requires root; synthetic temporary registration registry only, no SEP or network"]
    fn root_registration_reopens_prepared_and_ambiguous_delivery_without_replacing_identity() {
        assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .unwrap_or_else(|e| panic!("mode: {e}"));
        let registry = Registry::open(dir.path()).unwrap_or_else(|e| panic!("open: {e}"));
        let context = CreationContext::parse(&details().to_string())
            .unwrap_or_else(|e| panic!("context: {e}"));
        let transaction = Uuid::new_v4();
        let record = registry
            .prepare_registration(1001, transaction, &context, || Ok(key()))
            .unwrap_or_else(|e| panic!("prepare: {e}"));
        let original = serde_json::to_value(&record).unwrap_or_else(|e| panic!("serialize: {e}"));
        assert!(!record.registered);
        assert!(
            registry
                .browser_credentials(1001)
                .unwrap_or_else(|e| panic!("inventory: {e}"))
                .is_empty()
        );
        drop(registry);
        let registry = Registry::open(dir.path()).unwrap_or_else(|e| panic!("reopen: {e}"));
        let resumed = registry
            .prepare_registration(1001, transaction, &context, || {
                panic!("regenerated prepared key")
            })
            .unwrap_or_else(|e| panic!("resume: {e}"));
        assert_eq!(
            serde_json::to_value(resumed).unwrap_or_else(|e| panic!("serialize: {e}")),
            original
        );
        let mut changed = details();
        changed["challenge"] = serde_json::json!(URL_SAFE_NO_PAD.encode([1u8; 32]));
        let changed =
            CreationContext::parse(&changed.to_string()).unwrap_or_else(|e| panic!("changed: {e}"));
        assert!(
            registry
                .prepare_registration(1001, transaction, &changed, || panic!(
                    "replaced mismatched key"
                ))
                .is_err()
        );
        assert!(
            registry
                .prepare_registration(1002, transaction, &context, || panic!(
                    "replaced wrong-owner key"
                ))
                .is_err()
        );
        assert!(
            registry
                .prepare_registration(1001, Uuid::nil(), &context, || panic!(
                    "created with nil transaction"
                ))
                .is_err()
        );
        let mut wrong_key = record.credential.signing_key.clone();
        wrong_key.key_id = Uuid::new_v4().to_string();
        assert!(
            registry
                .registration_deliverable(1001, transaction, &context, &wrong_key)
                .is_err()
        );
        registry
            .registration_deliverable(1001, transaction, &context, &record.credential.signing_key)
            .unwrap_or_else(|e| panic!("deliverable: {e}"));
        drop(registry); // Simulate loss of the response after durable commit.
        let registry = Registry::open(dir.path()).unwrap_or_else(|e| panic!("reopen commit: {e}"));
        let resumed = registry
            .prepare_registration(1001, transaction, &context, || {
                panic!("replaced committed key")
            })
            .unwrap_or_else(|e| panic!("resume delivery: {e}"));
        assert!(resumed.registered);
        assert_eq!(resumed.credential, record.credential);
        assert_eq!(
            resumed
                .native_key
                .public_sec1()
                .unwrap_or_else(|e| panic!("public: {e}")),
            record
                .native_key
                .public_sec1()
                .unwrap_or_else(|e| panic!("public: {e}"))
        );
        registry
            .set_synced_inventory(1001, vec![])
            .unwrap_or_else(|e| panic!("empty sync: {e}"));
        assert_eq!(
            registry
                .browser_credentials(1001)
                .unwrap_or_else(|e| panic!("inventory: {e}")),
            vec![record.credential.clone()]
        );
        let mut excluded = details();
        excluded["excludeCredentials"] =
            serde_json::json!([{"type":"public-key","id":record.credential.credential_id}]);
        let excluded = CreationContext::parse(&excluded.to_string())
            .unwrap_or_else(|e| panic!("excluded: {e}"));
        assert!(
            registry
                .prepare_registration(1001, Uuid::new_v4(), &excluded, || panic!(
                    "excluded key created"
                ))
                .is_err()
        );
        let uncertain = Uuid::new_v4();
        assert!(
            registry
                .prepare_registration(1001, uncertain, &context, || {
                    Err(crate::security::sep::ProviderError::AmbiguousCompletion.into())
                })
                .is_err()
        );
        drop(registry);
        let registry = Registry::open(dir.path()).unwrap_or_else(|e| panic!("reopen intent: {e}"));
        assert!(
            registry
                .prepare_registration(1001, uncertain, &context, || panic!(
                    "retried ambiguous CREATE"
                ))
                .is_err()
        );
        let path = registry
            .filename(&transaction.to_string())
            .unwrap_or_else(|e| panic!("path: {e}"));
        atomic_write_private(&path, b"incomplete encrypted record")
            .unwrap_or_else(|e| panic!("mutate: {e}"));
        assert!(
            registry
                .prepare_registration(1001, transaction, &context, || panic!(
                    "replaced corrupt record"
                ))
                .is_err()
        );
    }
}
