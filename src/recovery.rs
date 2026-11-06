//! Explicit Octagon trust repair. Old peer keys remain recoverable until the
//! replacement has independently decrypted a complete snapshot. No Apple network
//! request or escrow attempt is initiated by loading/resuming this journal.
use serde::{Deserialize, Serialize};

use crate::apple::octagon;
use crate::model::{AccountState, DeviceIdentity, OctagonState, OctagonTrustState};
use crate::security::SecurityBackend;
use crate::store::StateStore;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RepairPhase {
    Prepared,
    SnapshotVerified,
    Committed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{MobileMeState, VaultState};
    use crate::paths::{AppPaths, atomic_write_private, read_bounded};
    use crate::security::{KeyUsage, Purpose, SoftwareFileBackend};
    use std::collections::BTreeMap;

    struct Fixture {
        _dir: tempfile::TempDir,
        paths: AppPaths,
        backend: SoftwareFileBackend,
        account: AccountState,
        device: DeviceIdentity,
        original: OctagonState,
    }
    impl Fixture {
        fn new() -> Result<Self> {
            let dir = tempfile::tempdir().map_err(|e| Error::io("fixture", e))?;
            let paths = AppPaths::for_test(dir.path())?;
            let backend = SoftwareFileBackend::new(paths.clone());
            let account = AccountState {
                schema_version: 1,
                username: "test@example.com".into(),
                adsid: "synthetic-account".into(),
                logged_in_at: 1,
                mobileme: MobileMeState::default(),
                webservices: BTreeMap::new(),
            };
            let device = DeviceIdentity {
                schema_version: 1,
                device_id: "synthetic-device".into(),
                serial: "test".into(),
                local_user_uuid: "test".into(),
            };
            let (mut original, _) =
                octagon::ensure_peer_identity(None, &account, &device, &backend)?;
            original.trust_state = OctagonTrustState::Joined;
            StateStore::new(&paths, &backend).save_octagon(&original)?;
            Ok(Self {
                _dir: dir,
                paths,
                backend,
                account,
                device,
                original,
            })
        }
        fn store(&self) -> StateStore<'_> {
            StateStore::new(&self.paths, &self.backend)
        }
        fn prepare(&self) -> Result<TrustRepair> {
            TrustRepair::prepare(&self.store(), &self.account, &self.device, &self.backend)
        }
        fn ready(&self) -> Result<TrustRepair> {
            let mut journal = self.prepare()?;
            journal.candidate.trust_state = OctagonTrustState::JoinedSponsorRetirementVerified {
                sponsor_peer_id: "sponsor".into(),
                escrow_record_label: "test-bottle".into(),
                sponsor_encryption_key: self.backend.generate_p384(KeyUsage::Agreement)?,
            };
            TrustRepair::checkpoint(&self.store(), &journal.candidate)?;
            journal.snapshot_verified(&self.store())
        }
        fn retire(&self, state: &mut OctagonState) -> Result<()> {
            let OctagonTrustState::JoinedSponsorRetirementVerified {
                sponsor_encryption_key,
                ..
            } = &state.trust_state
            else {
                return Err(Error::Security("not ready".into()));
            };
            self.backend.destroy_key(sponsor_encryption_key)?;
            state.trust_state = OctagonTrustState::Joined;
            Ok(())
        }
    }

    #[test]
    fn preparation_and_checkpoint_keep_original_keys_and_cache_and_resume_without_new_identity()
    -> Result<()> {
        let f = Fixture::new()?;
        let store = f.store();
        let vault = VaultState {
            schema_version: 1,
            synced_at: 1,
            credentials: vec![],
            passkeys: vec![],
        };
        store.save_vault(&vault)?;
        let cached = read_bounded(&f.paths.vault_file())?;
        let mut journal = f.prepare()?;
        assert_ne!(journal.candidate.peer_id, f.original.peer_id);
        assert_eq!(f.prepare()?.candidate, journal.candidate);
        assert!(
            journal
                .clone()
                .commit(&store, |_| panic!("unverified retirement"))
                .is_err()
        );
        assert!(journal.clone().snapshot_verified(&store).is_err());
        journal.candidate.trust_state = OctagonTrustState::SponsorRecovered {
            peer_id: "sponsor".into(),
            escrow_record_label: "test-bottle".into(),
            signing_key: f.backend.generate_p384(KeyUsage::Signing)?,
            encryption_key: f.backend.generate_p384(KeyUsage::Agreement)?,
        };
        TrustRepair::checkpoint(&store, &journal.candidate)?;
        assert_eq!(f.prepare()?.candidate, journal.candidate);
        assert_eq!(store.load_octagon()?, Some(f.original.clone()));
        assert_eq!(read_bounded(&f.paths.vault_file())?, cached);
        assert!(
            f.backend
                .sign_p384_sha256(&f.original.signing_key, b"still usable")
                .is_ok()
        );
        let encrypted = read_bounded(&f.paths.trust_repair_file())?;
        assert!(f.backend.open(Purpose::Octagon, &encrypted).is_err());
        assert!(
            !encrypted
                .windows(b"test-bottle".len())
                .any(|v| v == b"test-bottle")
        );
        Ok(())
    }

    #[test]
    fn commit_resumes_after_promotion_before_sponsor_retirement() -> Result<()> {
        let f = Fixture::new()?;
        let journal = f.ready()?;
        let replacement = journal.candidate.clone();
        assert!(
            journal
                .commit(&f.store(), |_| Err(Error::Security("interrupted".into())))
                .is_err()
        );
        assert_eq!(f.store().load_octagon()?, Some(replacement));
        let resumed = f.prepare()?;
        assert_eq!(resumed.phase, RepairPhase::SnapshotVerified);
        let committed = resumed.commit(&f.store(), |s| f.retire(s))?;
        assert_eq!(committed.phase, RepairPhase::Committed);
        assert_eq!(f.store().load_octagon()?, Some(committed.candidate));
        assert!(f.backend.public_spki(&f.original.signing_key).is_ok());
        assert!(f.backend.public_x963(&f.original.encryption_key).is_ok());
        Ok(())
    }

    #[test]
    fn commit_resumes_when_retirement_succeeded_before_the_active_state_rename() -> Result<()> {
        let f = Fixture::new()?;
        let journal = f.ready()?;
        let pending = f
            .backend
            .seal(Purpose::Octagon, &serde_json::to_vec(&journal.candidate)?)?;
        let path = f.paths.octagon_file();
        assert!(
            journal
                .commit(&f.store(), |s| {
                    f.retire(s)?;
                    std::fs::remove_file(&path).map_err(|e| Error::io(&path, e))?;
                    std::fs::create_dir(&path).map_err(|e| Error::io(&path, e))?;
                    Ok(())
                })
                .is_err()
        );
        std::fs::remove_dir(&path).map_err(|e| Error::io(&path, e))?;
        atomic_write_private(&path, &pending)?;
        let resumed = f.prepare()?.commit(&f.store(), |s| f.retire(s))?;
        assert_eq!(resumed.phase, RepairPhase::Committed);
        assert!(f.backend.public_spki(&f.original.signing_key).is_ok());
        Ok(())
    }

    #[test]
    fn commit_resumes_after_active_commit_before_final_journal_rename_and_repeated_repairs_retain_history()
    -> Result<()> {
        let f = Fixture::new()?;
        let journal = f.ready()?;
        let old_journal = read_bounded(&f.paths.trust_repair_file())?;
        let path = f.paths.trust_repair_file();
        assert!(
            journal
                .commit(&f.store(), |s| {
                    f.retire(s)?;
                    std::fs::remove_file(&path).map_err(|e| Error::io(&path, e))?;
                    std::fs::create_dir(&path).map_err(|e| Error::io(&path, e))?;
                    Ok(())
                })
                .is_err()
        );
        std::fs::remove_dir(&path).map_err(|e| Error::io(&path, e))?;
        atomic_write_private(&path, &old_journal)?;
        let resumed = f
            .prepare()?
            .commit(&f.store(), |_| panic!("already retired"))?;
        assert_eq!(resumed.phase, RepairPhase::Committed);
        let next = f.prepare()?;
        assert_eq!(next.retained.len(), 2);
        assert_eq!(next.retained[0], f.original);
        assert_eq!(next.retained[1], resumed.candidate);
        Ok(())
    }

    #[test]
    fn changed_account_or_active_identity_refuses_resume_and_missing_root_is_not_replaced()
    -> Result<()> {
        let mut f = Fixture::new()?;
        let journal = f.prepare()?;
        f.account.adsid = "different-account".into();
        assert!(f.prepare().is_err());
        let mut changed = f.original.clone();
        changed.permanent.signature_b64.push('A');
        f.store().save_octagon(&changed)?;
        assert!(TrustRepair::checkpoint(&f.store(), &journal.candidate).is_err());
        // Even a journal without the normal state files must prevent a new root.
        for path in [
            f.paths.octagon_file(),
            f.paths.keys_file(),
            f.paths.software_key_file(),
        ] {
            std::fs::remove_file(&path).map_err(|e| Error::io(path, e))?;
        }
        use crate::security::RootKeySource;
        assert!(
            crate::security::FileRootKeySource::new(f.paths.clone())
                .root_key()
                .is_err()
        );
        assert!(!f.paths.software_key_file().exists());
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRepair {
    version: u32,
    /// Retain references across repeated repairs; never discard old peer keys
    /// as a side effect of repairing trust. These are references, not scalars.
    retained: Vec<OctagonState>,
    candidate: OctagonState,
    phase: RepairPhase,
}

fn same_peer(a: &OctagonState, b: &OctagonState) -> bool {
    a.schema_version == b.schema_version
        && a.account_fingerprint == b.account_fingerprint
        && a.peer_id == b.peer_id
        && a.signing_key == b.signing_key
        && a.encryption_key == b.encryption_key
        && a.permanent == b.permanent
        && a.created_at == b.created_at
}

impl TrustRepair {
    pub fn phase(&self) -> RepairPhase {
        self.phase
    }
    pub fn candidate(&self) -> &OctagonState {
        &self.candidate
    }
    pub fn retained(&self) -> &[OctagonState] {
        &self.retained
    }
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.retained.is_empty()
            || self.candidate.schema_version != 1
            || self.retained.iter().any(|old| {
                old.schema_version != 1
                    || old.account_fingerprint != self.candidate.account_fingerprint
                    || old.peer_id == self.candidate.peer_id
                    || old.signing_key == self.candidate.signing_key
                    || old.encryption_key == self.candidate.encryption_key
            })
            || (self.phase == RepairPhase::SnapshotVerified
                && !matches!(
                    self.candidate.trust_state,
                    OctagonTrustState::JoinedSponsorRetirementVerified { .. }
                ))
            || (self.phase == RepairPhase::Committed
                && self.candidate.trust_state != OctagonTrustState::Joined)
        {
            return Err(Error::Security(
                "invalid Octagon trust-repair journal".into(),
            ));
        }
        Ok(())
    }

    fn validate_active(&self, store: &StateStore<'_>) -> Result<OctagonState> {
        self.validate()?;
        let active = store.load_octagon()?.ok_or_else(|| {
            Error::Security("active Octagon identity is missing during trust repair".into())
        })?;
        let original = self
            .retained
            .last()
            .ok_or_else(|| Error::Security("trust repair has no retained identity".into()))?;
        let valid = match self.phase {
            RepairPhase::Prepared => &active == original,
            RepairPhase::SnapshotVerified => {
                &active == original
                    || (same_peer(&active, &self.candidate)
                        && (active.trust_state == self.candidate.trust_state
                            || active.trust_state == OctagonTrustState::Joined))
            }
            RepairPhase::Committed => active == self.candidate,
        };
        if !valid {
            return Err(Error::Security(
                "active Octagon identity changed outside the pending trust repair".into(),
            ));
        }
        Ok(active)
    }

    /// Start explicitly, or resume the already authorized durable transaction.
    /// Caller holds StateLock. Generating a replacement never overwrites the
    /// active identity, and failures never destroy any previous peer keys.
    pub fn prepare(
        store: &StateStore<'_>,
        account: &AccountState,
        device: &DeviceIdentity,
        backend: &dyn SecurityBackend,
    ) -> Result<Self> {
        let existing = store.load_trust_repair()?;
        if let Some(journal) = &existing {
            journal.validate_active(store)?;
            if journal.candidate.account_fingerprint != octagon::account_fingerprint(account) {
                return Err(Error::Security(
                    "trust repair belongs to a different account".into(),
                ));
            }
            if journal.phase != RepairPhase::Committed {
                return Ok(journal.clone());
            }
        }
        let active = store.load_octagon()?.ok_or_else(|| {
            Error::Config("no Octagon identity to repair; run `keychain setup`".into())
        })?;
        if active.account_fingerprint != octagon::account_fingerprint(account)
            || active.trust_state != OctagonTrustState::Joined
        {
            return Err(Error::Refused(
                "finish the current join before starting trust repair".into(),
            ));
        }
        let (candidate, _) = octagon::ensure_peer_identity(None, account, device, backend)?;
        let mut retained = existing.map(|journal| journal.retained).unwrap_or_default();
        retained.push(active);
        let journal = Self {
            version: 1,
            retained,
            candidate,
            phase: RepairPhase::Prepared,
        };
        journal.validate()?;
        store.save_trust_repair(&journal)?;
        Ok(journal)
    }

    pub fn checkpoint(store: &StateStore<'_>, candidate: &OctagonState) -> Result<()> {
        let mut journal = store
            .load_trust_repair()?
            .ok_or_else(|| Error::Security("trust-repair journal is missing".into()))?;
        journal.validate_active(store)?;
        if journal.phase != RepairPhase::Prepared || !same_peer(candidate, &journal.candidate) {
            return Err(Error::Security(
                "trust-repair checkpoint changed identity or phase".into(),
            ));
        }
        journal.candidate = candidate.clone();
        store.save_trust_repair(&journal)
    }

    /// The caller has just saved a full snapshot decrypted using only the new
    /// peer, without sponsor fallback. Persist that proof before promotion.
    pub fn snapshot_verified(mut self, store: &StateStore<'_>) -> Result<Self> {
        self.validate_active(store)?;
        if self.phase != RepairPhase::Prepared
            || !matches!(
                self.candidate.trust_state,
                OctagonTrustState::JoinedSponsorRetirementVerified { .. }
            )
        {
            return Err(Error::Security(
                "replacement self-shares are not verified".into(),
            ));
        }
        self.phase = RepairPhase::SnapshotVerified;
        store.save_trust_repair(&self)?;
        Ok(self)
    }

    /// All file transitions are resumable. Retirement concerns only the escrow
    /// sponsor; retained old peer keys are never retired by this operation.
    pub fn commit(
        mut self,
        store: &StateStore<'_>,
        retire_sponsor: impl FnOnce(&mut OctagonState) -> Result<()>,
    ) -> Result<Self> {
        let active = self.validate_active(store)?;
        if self.phase == RepairPhase::Committed {
            return Ok(self);
        }
        if self.phase != RepairPhase::SnapshotVerified {
            return Err(Error::Refused(
                "complete replacement snapshot verification before promotion".into(),
            ));
        }
        if same_peer(&active, &self.candidate) && active.trust_state == OctagonTrustState::Joined {
            // Active state was committed before the final journal rename.
            self.candidate = active;
        } else {
            store.save_octagon(&self.candidate)?;
            let expected = self.candidate.clone();
            retire_sponsor(&mut self.candidate)?;
            if !same_peer(&expected, &self.candidate)
                || self.candidate.trust_state != OctagonTrustState::Joined
            {
                return Err(Error::Security(
                    "sponsor retirement did not finish the replacement join".into(),
                ));
            }
            store.save_octagon(&self.candidate)?;
        }
        self.phase = RepairPhase::Committed;
        store.save_trust_repair(&self)?;
        Ok(self)
    }
}
