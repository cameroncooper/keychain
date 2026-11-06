//! One selected-secret lifetime for upload and registration. Production IPC must
//! supply an authenticated, cancellable network-worker UploadIo implementation;
//! ordinary browser/owner JSON cannot manufacture snapshots or backup receipts.

use super::protected::SelectedScalar;
use super::registry::SyncedCreation;
use super::*;
use crate::apple::ckks::upload::{Binding, Phase, SaveOutcome, Snapshot, UploadIo};
use crate::model::PasskeyCredential;
use crate::passkey::registration::{CreationContext, Registration};
use crate::security::sep::ProviderError;

#[derive(Clone, Copy, Debug, Default)]
pub enum UploadRecovery {
    #[default]
    Reconcile,
    RetryConfirmedAbsent,
    ReencryptRejected,
}
pub struct SyncedCreationRequest {
    pub binding: Binding,
    pub request_details_json: String,
    pub recovery: UploadRecovery,
}

impl Broker {
    /// Trusted in-process integration seam, not an enabled browser IPC action.
    /// The caller must supply network IO from the isolated trusted worker, with
    /// cooperative cancellation/deadlines. Never run Apple networking inside
    /// this privileged process or accept an owner's claimed upload-success bit.
    pub fn create_synced_registration(
        &self,
        request: SyncedCreationRequest,
        io: &mut dyn UploadIo,
        canceled: Arc<AtomicBool>,
    ) -> Result<Registration> {
        if !self.allow_item_decrypt {
            return Err(ProviderError::UnsupportedPolicy.into());
        }
        request.binding.validate()?;
        let context = CreationContext::parse(&request.request_details_json)?;
        if request.binding.owner != self.owner
            || request.binding.request_sha256 != context.binding()
        {
            return Err(Error::Security(
                "synced creation does not match this owner/request".into(),
            ));
        }
        let _active = self
            .active
            .try_lock()
            .map_err(|_| Error::Refused("another key operation is active".into()))?;
        let session = ActiveSession::for_owner(self.owner)?;
        if canceled.load(Ordering::Acquire) {
            return Err(ProviderError::Canceled.into());
        }
        // Fetch the initial complete hierarchy before opening the desktop
        // prompt or holding any private scalar. Preparation validates the zone.
        let snapshot = io.fetch_zone(&request.binding.zone)?;
        if canceled.load(Ordering::Acquire) || !session.valid() {
            return Err(ProviderError::Canceled.into());
        }
        let excluded = self
            .registry
            .browser_credentials(self.owner)?
            .into_iter()
            .find(|credential| context.excludes(credential));
        let authorization = self.native_authorization(
            Presentation {
                id: Uuid::new_v4(),
                application: "Keychain".into(),
                action: format!("Create a passkey for {} in iCloud", context.rp_id()),
                account: context.username().into(),
            },
            canceled,
            session,
            false,
        )?;
        if let Some(excluded) = excluded {
            self.reject_registration_exclusion(&excluded, &context, &authorization)?;
        }
        let draft = self
            .registry
            .prepare_synced_registration(&request.binding, &context)?;
        authorization.check()?;
        self.with_protected_scalar(draft.record(), &authorization, |selected| {
            authorization.status("Saving passkey to iCloud…")?;
            PendingCreation {
                registry: &self.registry,
                draft: &draft,
                context: &context,
                snapshot,
            }
            .finish(selected, io, &|| authorization.check(), request.recovery)
        })
    }

    pub(super) fn reject_registration_exclusion(
        &self,
        excluded: &PasskeyCredential,
        context: &CreationContext,
        authorization: &Arc<super::native::NativeAuthorization>,
    ) -> Result<()> {
        let message = format!(
            "cameroncooper.keychain/registration-exclusion/v1/{}",
            context.binding()
        );
        let outcome = if excluded.signing_key.backend_id == "sep-native-v1" {
            let record = self.registry.load(&excluded.id, self.owner)?;
            let provider = authorization.provider(record.native_key, self.device.clone())?;
            sign_native(
                &provider,
                &excluded.signing_key,
                &provider.public_sec1()?,
                message.as_bytes(),
                authorization.remaining()?,
            )?
        } else {
            let record = self.registry.load_protected(&excluded.id, self.owner)?;
            self.sign_protected_record(&record, message.as_bytes(), authorization)?
        };
        outcome.into_signature(
            &excluded.signing_key,
            message.as_bytes(),
            AuthorizationRequirement::UserVerification,
        )?;
        authorization.check()?;
        Err(Error::CredentialExcluded)
    }
}

struct PendingCreation<'a> {
    registry: &'a Registry,
    draft: &'a SyncedCreation,
    context: &'a CreationContext,
    snapshot: Snapshot,
}
impl PendingCreation<'_> {
    fn finish(
        self,
        selected: &SelectedScalar<'_>,
        io: &mut dyn UploadIo,
        check: &dyn Fn() -> Result<()>,
        recovery: UploadRecovery,
    ) -> Result<Registration> {
        check()?;
        selected.verify_record(self.draft.record())?;
        let binding = self.draft.binding();
        let record = self.draft.record();
        let mut io = GuardedIo { inner: io, check };
        let mut upload = self.registry.uploads()?.resume_or_prepare(binding, || {
            check()?;
            let prepared = selected.prepare_upload(binding, &self.snapshot)?;
            check()?;
            Ok(prepared)
        })?;
        upload.verify_identity(
            binding,
            &record.credential,
            &registry::decode_public(&record.public_sec1)?,
        )?;
        check()?;
        match (recovery, upload.phase()?) {
            (UploadRecovery::RetryConfirmedAbsent, Phase::Attempted { .. }) => {
                upload.retry_after_absence(&mut io)?
            }
            (UploadRecovery::ReencryptRejected, Phase::Rejected) => upload
                .reprepare_after_rejection(&mut io, |binding, _, snapshot| {
                    check()?;
                    selected.prepare_upload(binding, snapshot)
                })?,
            _ => (),
        }
        upload.advance(&mut io)?;
        check()?;
        let verified = upload.verified_upload()?;
        self.registry.finish_synced_registration(
            binding,
            self.context,
            &verified,
            |record, message| {
                check()?;
                selected.sign(record, message)
            },
            check,
        )
    }
}

/// Worker calls must themselves be bounded/cancellable. These guards prevent
/// result delivery or subsequent side effects after cancellation, session loss
/// or expiry, including a response received just after an uncertain write.
struct GuardedIo<'a> {
    inner: &'a mut dyn UploadIo,
    check: &'a dyn Fn() -> Result<()>,
}
impl UploadIo for GuardedIo<'_> {
    fn fetch_zone(&mut self, zone: &crate::apple::ckks::ZoneIdentity) -> Result<Snapshot> {
        (self.check)()?;
        let result = self.inner.fetch_zone(zone);
        (self.check)()?;
        result
    }
    fn create_atomic(
        &mut self,
        attempt: Uuid,
        zone: &crate::apple::ckks::ZoneIdentity,
        record: &crate::apple::ckks::Record,
        pointer: &crate::apple::ckks::Record,
    ) -> Result<SaveOutcome> {
        (self.check)()?;
        let result = self.inner.create_atomic(attempt, zone, record, pointer);
        (self.check)()?;
        result
    }
}

#[cfg(test)]
mod tests;
