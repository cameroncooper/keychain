//! Synthetic complete-operation integration; no driver, UI or Apple requests.
use super::*;
use crate::apple::ckks::upload::tests::synthetic_io;
use crate::apple::ckks::{Record, ZoneIdentity};
use crate::broker::registry::test_support::{binding, context, open_scalar, registry};
use std::cell::Cell;

struct Observed<I> {
    inner: I,
    writes: Vec<Record>,
    canceled: Arc<AtomicBool>,
    cancel_after_send: bool,
    cancel_fetch: Option<usize>,
    fetches: usize,
    lose_reply: bool,
    reject: bool,
    fail_before_commit: bool,
}
impl<I: UploadIo> Observed<I> {
    fn new(inner: I) -> Self {
        Self {
            inner,
            writes: vec![],
            canceled: Arc::new(AtomicBool::new(false)),
            cancel_after_send: false,
            cancel_fetch: None,
            fetches: 0,
            lose_reply: false,
            reject: false,
            fail_before_commit: false,
        }
    }
}
impl<I: UploadIo> UploadIo for Observed<I> {
    fn fetch_zone(&mut self, zone: &ZoneIdentity) -> Result<Snapshot> {
        self.fetches += 1;
        let result = self.inner.fetch_zone(zone);
        if self.cancel_fetch == Some(self.fetches) {
            self.canceled.store(true, Ordering::Release);
        }
        result
    }
    fn create_atomic(
        &mut self,
        attempt: Uuid,
        zone: &ZoneIdentity,
        record: &Record,
        pointer: &Record,
    ) -> Result<SaveOutcome> {
        self.writes.push(record.clone());
        if self.reject {
            return Ok(SaveOutcome::PreconditionFailed);
        }
        if self.fail_before_commit {
            return Err(Error::Apple("synthetic uncertain absent write".into()));
        }
        let result = self.inner.create_atomic(attempt, zone, record, pointer);
        if self.cancel_after_send {
            self.canceled.store(true, Ordering::Release);
        }
        if self.lose_reply {
            return Err(Error::Apple("synthetic lost reply".into()));
        }
        result
    }
}
fn check(canceled: &AtomicBool) -> Result<()> {
    if canceled.load(Ordering::Acquire) {
        Err(ProviderError::Canceled.into())
    } else {
        Ok(())
    }
}

#[test]
#[ignore = "requires root; synthetic selected-secret/upload operation only, no capture or network"]
fn selected_creation_uploads_registers_and_retries_delivery_without_regenerating_ciphertext()
-> Result<()> {
    let dir = tempfile::tempdir().map_err(|e| Error::io("test registry", e))?;
    let registry = registry(dir.path())?;
    let context = context()?;
    let binding = binding(&context);
    let draft = registry.prepare_synced_registration(&binding, &context)?;
    let scalar = open_scalar(draft.record())?;
    let mut io = Observed::new(synthetic_io(binding.zone.clone())?);
    let snapshot = io.fetch_zone(&binding.zone)?;
    let selected = SelectedScalar::from_biometric(draft.record(), &scalar)?; // Explicit fake UV fixture.
    let response = PendingCreation {
        registry: &registry,
        draft: &draft,
        context: &context,
        snapshot,
    }
    .finish(&selected, &mut io, &|| Ok(()), UploadRecovery::Reconcile)?;
    assert_eq!(response.id, draft.record().credential.credential_id);
    assert_eq!(
        registry.browser_credentials(binding.owner)?,
        vec![draft.record().credential.clone()]
    );
    assert_eq!(io.writes.len(), 1);
    let ciphertext = io.writes[0].clone();
    assert!(
        !ciphertext
            .bytes("data")
            .ok_or_else(|| Error::InvalidData("test ciphertext".into()))?
            .windows(32)
            .any(|bytes| bytes == scalar.as_slice())
    );
    drop(registry);
    let registry = Registry::open(dir.path())?;
    let resumed = registry.prepare_synced_registration(&binding, &context)?;
    let snapshot = io.fetch_zone(&binding.zone)?; // Contains this item, so new preparation would fail.
    let fresh = SelectedScalar::from_biometric(resumed.record(), &scalar)?;
    let response = PendingCreation {
        registry: &registry,
        draft: &resumed,
        context: &context,
        snapshot,
    }
    .finish(&fresh, &mut io, &|| Ok(()), UploadRecovery::Reconcile)?;
    assert_eq!(response.id, draft.record().credential.credential_id);
    assert_eq!(io.writes.len(), 1);
    assert_eq!(io.writes[0], ciphertext);
    Ok(())
}

#[test]
#[ignore = "requires root; synthetic uncertain upload only, no capture or network"]
fn lost_upload_reply_keeps_registration_hidden_then_reconciles_without_another_send() -> Result<()>
{
    let dir = tempfile::tempdir().map_err(|e| Error::io("test registry", e))?;
    let registry = registry(dir.path())?;
    let context = context()?;
    let binding = binding(&context);
    let draft = registry.prepare_synced_registration(&binding, &context)?;
    let scalar = open_scalar(draft.record())?;
    let mut io = Observed::new(synthetic_io(binding.zone.clone())?);
    io.lose_reply = true;
    let snapshot = io.fetch_zone(&binding.zone)?;
    let selected = SelectedScalar::from_biometric(draft.record(), &scalar)?;
    assert!(
        PendingCreation {
            registry: &registry,
            draft: &draft,
            context: &context,
            snapshot
        }
        .finish(&selected, &mut io, &|| Ok(()), UploadRecovery::Reconcile)
        .is_err()
    );
    assert!(registry.browser_credentials(binding.owner)?.is_empty());
    let upload = registry.uploads()?.resume(&binding)?;
    assert!(matches!(upload.phase()?, Phase::Attempted { .. }));
    drop(upload);
    io.lose_reply = false;
    let snapshot = io.fetch_zone(&binding.zone)?;
    let fresh = SelectedScalar::from_biometric(draft.record(), &scalar)?;
    PendingCreation {
        registry: &registry,
        draft: &draft,
        context: &context,
        snapshot,
    }
    .finish(&fresh, &mut io, &|| Ok(()), UploadRecovery::Reconcile)?;
    assert_eq!(io.writes.len(), 1);
    assert_eq!(
        registry.browser_credentials(binding.owner)?,
        vec![draft.record().credential.clone()]
    );
    Ok(())
}

#[test]
#[ignore = "requires root; synthetic cancellation boundaries only, no capture or network"]
fn canceled_network_results_never_activate_a_registration_and_new_operation_can_reconcile()
-> Result<()> {
    for after_ack in [false, true] {
        let dir = tempfile::tempdir().map_err(|e| Error::io("test registry", e))?;
        let registry = registry(dir.path())?;
        let context = context()?;
        let binding = binding(&context);
        let draft = registry.prepare_synced_registration(&binding, &context)?;
        let scalar = open_scalar(draft.record())?;
        let mut io = Observed::new(synthetic_io(binding.zone.clone())?);
        let snapshot = io.fetch_zone(&binding.zone)?;
        io.fetches = 0;
        if after_ack {
            io.cancel_fetch = Some(2);
        } else {
            io.cancel_after_send = true;
        }
        let canceled = io.canceled.clone();
        let selected = SelectedScalar::from_biometric(draft.record(), &scalar)?;
        let result = PendingCreation {
            registry: &registry,
            draft: &draft,
            context: &context,
            snapshot,
        }
        .finish(
            &selected,
            &mut io,
            &|| check(&canceled),
            UploadRecovery::Reconcile,
        );
        assert!(matches!(result, Err(Error::Sep(ProviderError::Canceled))));
        assert!(registry.browser_credentials(binding.owner)?.is_empty());
        let upload = registry.uploads()?.resume(&binding)?;
        assert!(if after_ack {
            matches!(upload.phase()?, Phase::Accepted { .. })
        } else {
            matches!(upload.phase()?, Phase::Attempted { .. })
        });
        drop(upload);
        io.cancel_fetch = None;
        io.cancel_after_send = false;
        canceled.store(false, Ordering::Release);
        let snapshot = io.fetch_zone(&binding.zone)?;
        let fresh = SelectedScalar::from_biometric(draft.record(), &scalar)?; // New logical UV operation.
        PendingCreation {
            registry: &registry,
            draft: &draft,
            context: &context,
            snapshot,
        }
        .finish(
            &fresh,
            &mut io,
            &|| check(&canceled),
            UploadRecovery::Reconcile,
        )?;
        assert_eq!(io.writes.len(), 1);
        assert_eq!(
            registry.browser_credentials(binding.owner)?,
            vec![draft.record().credential.clone()]
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires root; synthetic explicit recovery choices only, no capture or network"]
fn explicit_recovery_choices_preserve_the_key_and_do_not_hide_an_uncertain_retry() -> Result<()> {
    for rejected in [false, true] {
        let dir = tempfile::tempdir().map_err(|e| Error::io("test registry", e))?;
        let registry = registry(dir.path())?;
        let context = context()?;
        let binding = binding(&context);
        let draft = registry.prepare_synced_registration(&binding, &context)?;
        let scalar = open_scalar(draft.record())?;
        let mut io = Observed::new(synthetic_io(binding.zone.clone())?);
        io.reject = rejected;
        io.fail_before_commit = !rejected;
        let snapshot = io.fetch_zone(&binding.zone)?;
        let selected = SelectedScalar::from_biometric(draft.record(), &scalar)?;
        assert!(
            PendingCreation {
                registry: &registry,
                draft: &draft,
                context: &context,
                snapshot
            }
            .finish(&selected, &mut io, &|| Ok(()), UploadRecovery::Reconcile)
            .is_err()
        );
        let original = io.writes[0].clone();
        io.reject = false;
        io.fail_before_commit = false;
        let snapshot = io.fetch_zone(&binding.zone)?;
        let fresh = SelectedScalar::from_biometric(draft.record(), &scalar)?;
        assert!(
            PendingCreation {
                registry: &registry,
                draft: &draft,
                context: &context,
                snapshot
            }
            .finish(&fresh, &mut io, &|| Ok(()), UploadRecovery::Reconcile)
            .is_err()
        );
        assert_eq!(io.writes.len(), 1);
        let snapshot = io.fetch_zone(&binding.zone)?;
        let fresh = SelectedScalar::from_biometric(draft.record(), &scalar)?;
        let policy = if rejected {
            UploadRecovery::ReencryptRejected
        } else {
            UploadRecovery::RetryConfirmedAbsent
        };
        let response = PendingCreation {
            registry: &registry,
            draft: &draft,
            context: &context,
            snapshot,
        }
        .finish(&fresh, &mut io, &|| Ok(()), policy)?;
        assert_eq!(response.id, draft.record().credential.credential_id);
        assert_eq!(io.writes.len(), 2);
        if rejected {
            assert_ne!(io.writes[1].bytes("data"), original.bytes("data"));
        } else {
            assert_eq!(io.writes[1], original);
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires root; synthetic selected-key/context refusal only, no capture or network"]
fn changed_selected_record_and_expired_operation_do_not_prepare_or_send_an_upload() -> Result<()> {
    let dir = tempfile::tempdir().map_err(|e| Error::io("test registry", e))?;
    let registry = registry(dir.path())?;
    let context = context()?;
    let binding = binding(&context);
    let draft = registry.prepare_synced_registration(&binding, &context)?;
    let scalar = open_scalar(draft.record())?;
    assert!(SelectedScalar::from_biometric(draft.record(), &[9u8; 32]).is_err());
    let mut altered = draft.record().clone();
    altered.credential.username = "another selected account".into();
    let selected = SelectedScalar::from_biometric(&altered, &scalar)?;
    let mut io = Observed::new(synthetic_io(binding.zone.clone())?);
    let snapshot = io.fetch_zone(&binding.zone)?;
    assert!(
        PendingCreation {
            registry: &registry,
            draft: &draft,
            context: &context,
            snapshot
        }
        .finish(&selected, &mut io, &|| Ok(()), UploadRecovery::Reconcile)
        .is_err()
    );
    let snapshot = io.fetch_zone(&binding.zone)?;
    let selected = SelectedScalar::from_biometric(draft.record(), &scalar)?;
    let guards = Cell::new(0);
    assert!(
        PendingCreation {
            registry: &registry,
            draft: &draft,
            context: &context,
            snapshot
        }
        .finish(
            &selected,
            &mut io,
            &|| {
                guards.set(guards.get() + 1);
                Err(ProviderError::Expired.into())
            },
            UploadRecovery::Reconcile
        )
        .is_err()
    );
    assert_eq!(guards.get(), 1);
    assert!(io.writes.is_empty());
    assert!(
        !dir.path()
            .join(format!("upload-{}.enc", binding.transaction))
            .exists()
    );
    assert!(registry.browser_credentials(binding.owner)?.is_empty());
    Ok(())
}
