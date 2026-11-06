use super::*;
use crate::security::sep::{ProviderError, StoredSepKey};

impl Broker {
    pub(super) fn native_authorization(
        &self,
        presentation: Presentation,
        canceled: Arc<AtomicBool>,
        session: ActiveSession,
        cancellation_test: bool,
    ) -> Result<Arc<NativeAuthorization>> {
        if canceled.load(Ordering::Acquire) || !session.valid() {
            return Err(ProviderError::Canceled.into());
        }
        let path = PathBuf::from(format!("/run/user/{}/keychain-auth.sock", self.owner));
        let prompt = PromptSession::connect(&path, self.owner, presentation)
            .map_err(|e| Error::io(&path, e))?;
        Ok(Arc::new(NativeAuthorization {
            prompt: Mutex::new(prompt),
            canceled,
            session,
            cancellation_test,
            deadline: Instant::now() + Duration::from_secs(60),
        }))
    }
}

/// Shared presentation/cancellation lifetime for native registration and use.
/// The UI supplies no success signal; the verified SEP operation supplies UV.
pub(super) struct NativeAuthorization {
    prompt: Mutex<PromptSession>,
    canceled: Arc<AtomicBool>,
    session: ActiveSession,
    pub(super) deadline: Instant,
    cancellation_test: bool,
}
impl NativeAuthorization {
    pub(super) fn check(&self) -> Result<()> {
        if self.canceled.load(Ordering::Acquire)
            || !self.session.valid()
            || self
                .prompt
                .lock()
                .map_err(|_| Error::Refused("prompt failed".into()))?
                .canceled()
        {
            return Err(ProviderError::Canceled.into());
        }
        self.remaining()?;
        Ok(())
    }
    pub(super) fn remaining(&self) -> Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| *remaining >= Duration::from_millis(1))
            .ok_or_else(|| ProviderError::Expired.into())
    }
    pub(super) fn status(&self, message: &str) -> Result<()> {
        self.check()?;
        self.prompt
            .lock()
            .map_err(|_| Error::Refused("prompt failed".into()))?
            .status(message)
            .map_err(|e| Error::io("desktop prompt status", e))
    }
    pub(super) fn progress(&self, guidance: keychain_sep_driver::Guidance) -> bool {
        if self.check().is_err() {
            return false;
        }
        let Ok(mut prompt) = self.prompt.lock() else {
            return false;
        };
        prompt
            .status(if self.cancellation_test {
                "Click Cancel or press Escape — do not touch the reader"
            } else {
                use keychain_sep_driver::Guidance;
                match guidance {
                    Guidance::WaitingForDevice => "Waiting for the fingerprint reader…",
                    Guidance::Preparing => "Preparing fingerprint reader…",
                    Guidance::PlaceFinger => "Touch the fingerprint reader",
                    Guidance::LiftAndMove => "Lift and reposition your finger",
                    Guidance::HoldStill => "Hold your finger still",
                }
            })
            .is_ok()
    }
    pub(super) fn provider(
        self: &Arc<Self>,
        key: StoredSepKey,
        device: PathBuf,
    ) -> Result<NativeSepProvider> {
        self.check()?;
        let authorization = self.clone();
        NativeSepProvider::new(key, device, move |guidance| {
            authorization.progress(guidance)
        })
    }
}
