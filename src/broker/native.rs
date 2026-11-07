use super::*;
use crate::security::sep::{ProviderError, StoredSepKey};

impl Broker {
    pub(super) fn native_creation_authorization(
        &self,
        id: Uuid,
        context: &crate::passkey::registration::CreationContext,
        canceled: Arc<AtomicBool>,
        session: ActiveSession,
    ) -> Result<(crate::model::PasskeyProvenance, Arc<NativeAuthorization>)> {
        use crate::model::PasskeyProvenance as P;
        use crate::prompt::PromptStorage as S;
        let allowed = self.creation_storage_choices()?;
        let default = if allowed.contains(&P::Synced) {
            P::Synced
        } else {
            P::DeviceBound
        };
        let choices = allowed
            .iter()
            .map(|choice| match choice {
                P::Synced => S::ICloudSynced,
                P::DeviceBound => S::DeviceOnly,
            })
            .collect();
        let request = Presentation::passkey(
            id,
            PromptOperation::CreatePasskey,
            context.rp_id(),
            Some(context.origin()),
            context.username(),
            default,
        );
        let path = PathBuf::from(format!("/run/user/{}/keychain-auth.sock", self.owner));
        let check = || {
            if canceled.load(Ordering::Acquire) || !session.valid() {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "creation request canceled or desktop session invalid",
                ))
            } else {
                Ok(())
            }
        };
        let (storage, prompt) = PromptSession::choose_creation(
            &path, self.owner, request, choices, &check,
        )
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe => ProviderError::Canceled.into(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                ProviderError::Expired.into()
            }
            _ => Error::io(&path, e),
        })?;
        let storage = match storage {
            S::ICloudSynced => P::Synced,
            S::DeviceOnly => P::DeviceBound,
            _ => return Err(ProviderError::UnsupportedPolicy.into()),
        };
        Ok((
            storage,
            Arc::new(NativeAuthorization {
                prompt: Mutex::new(prompt),
                canceled,
                session,
                cancellation_test: false,
                deadline: Instant::now() + Duration::from_secs(60),
            }),
        ))
    }

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
        self.remaining()?;
        let reason = if self.canceled.load(Ordering::Acquire) {
            Some("request disconnected")
        } else if !self.session.valid() {
            Some("desktop session invalid")
        } else if self
            .prompt
            .lock()
            .map_err(|_| Error::Refused("prompt failed".into()))?
            .canceled()
        {
            Some("desktop prompt canceled or disconnected")
        } else {
            None
        };
        if let Some(reason) = reason {
            eprintln!("keychain-broker: biometric authorization canceled: {reason}");
            return Err(ProviderError::Canceled.into());
        }
        // Cancellation can arrive during the bounded login1 query above.
        if self.canceled.load(Ordering::Acquire) {
            eprintln!("keychain-broker: biometric authorization canceled: request disconnected");
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
