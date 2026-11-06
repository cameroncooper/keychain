use super::*;
use crate::model::PasskeyProvenance;
use crate::passkey::registration::CreationContext;
use crate::security::sep::{ProviderError, StoredSepKey};

impl Broker {
    pub(super) fn execute_registration(
        &self,
        id: Uuid,
        operation: Operation,
        canceled: Arc<AtomicBool>,
        session: ActiveSession,
    ) -> Result<serde_json::Value> {
        match operation {
            Operation::InspectCreation {
                request_details_json,
            } => {
                let context = CreationContext::parse(&request_details_json)?;
                if !self.native_ui_available()?
                    || !matches!(self.device_status(), "available" | "busy")
                {
                    return Err(Error::Refused(
                        "native registration needs an available SEP and desktop agent".into(),
                    ));
                }
                Ok(serde_json::json!({
                    "kind":"creationInspection", "rpId":context.rp_id(),
                    "rpName":context.rp_name(), "origin":context.origin(),
                    "username":context.username(), "displayName":context.display_name(),
                    "storageChoices":["device-bound"],
                }))
            }
            Operation::Create {
                transaction,
                storage,
                request_details_json,
            } => {
                // A storage choice is required. There is never an implicit
                // cloud-to-local fallback or an Apple write on this path.
                if storage != PasskeyProvenance::DeviceBound {
                    return Err(ProviderError::UnsupportedPolicy.into());
                }
                let context = CreationContext::parse(&request_details_json)?;
                let excluded = self
                    .registry
                    .browser_credentials(self.owner)?
                    .into_iter()
                    .find(|credential| context.excludes(credential));
                let authorization = self.native_authorization(
                    Presentation {
                        id,
                        application: "Keychain".into(),
                        action: format!("Create a passkey for {} on this device", context.rp_id()),
                        account: context.username().into(),
                    },
                    canceled,
                    session,
                    false,
                )?;
                authorization.check()?;
                if let Some(excluded) = excluded {
                    // WebAuthn permits the distinguishable InvalidStateError
                    // only AFTER a presence gesture. Sign a private, domain-
                    // separated consent message; never disclose its signature.
                    let message = format!(
                        "cameroncooper.keychain/registration-exclusion/v1/{}",
                        context.binding()
                    );
                    let outcome = if excluded.signing_key.backend_id == "sep-native-v1" {
                        let record = self.registry.load(&excluded.id, self.owner)?;
                        let provider =
                            authorization.provider(record.native_key, self.device.clone())?;
                        sign_native(
                            &provider,
                            &excluded.signing_key,
                            &provider.public_sec1()?,
                            message.as_bytes(),
                            authorization.remaining()?,
                        )?
                    } else {
                        let record = self.registry.load_protected(&excluded.id, self.owner)?;
                        self.sign_protected_record(&record, message.as_bytes(), &authorization)?
                    };
                    outcome.into_signature(
                        &excluded.signing_key,
                        message.as_bytes(),
                        AuthorizationRequirement::UserVerification,
                    )?;
                    authorization.check()?;
                    return Err(Error::CredentialExcluded);
                }
                let record = self.registry.prepare_registration(
                    self.owner,
                    transaction,
                    &context,
                    || {
                        StoredSepKey::create_selected(
                            &self.device,
                            authorization.deadline,
                            |guidance| authorization.progress(guidance),
                        )
                    },
                )?;
                authorization.check()?;
                let provider = authorization.provider(record.native_key, self.device.clone())?;
                let public = provider.public_sec1()?;
                let registration = context.finish_device_registration(
                    &record.credential,
                    &public,
                    |key, message, _| {
                        sign_native(&provider, key, &public, message, authorization.remaining()?)
                            .map_err(Error::Sep)
                    },
                )?;
                authorization.check()?;
                self.registry.registration_deliverable(
                    self.owner,
                    transaction,
                    &context,
                    &record.credential.signing_key,
                )?;
                authorization.check()?;
                Ok(
                    serde_json::json!({"responseJson":serde_json::to_string(&registration)?,
                    "recordId":record.credential.id}),
                )
            }
            _ => Err(Error::InvalidData("not a registration operation".into())),
        }
    }
}
