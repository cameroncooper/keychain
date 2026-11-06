use super::*;
use crate::model::PasskeyProvenance;
use crate::passkey::registration::CreationContext;
use crate::security::sep::StoredSepKey;

impl Broker {
    pub(super) fn creation_storage_choices(&self) -> Result<Vec<PasskeyProvenance>> {
        let mut choices = vec![PasskeyProvenance::DeviceBound];
        if self.allow_synced_creation
            && self.allow_item_decrypt
            && self.registry.optional_account(self.owner)?.is_some()
        {
            choices.push(PasskeyProvenance::Synced);
        }
        Ok(choices)
    }
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
                    "storageChoices":self.creation_storage_choices()?,
                }))
            }
            Operation::Create {
                transaction,
                storage,
                request_details_json,
            } => {
                // The application selection is explicit. No cloud-to-local
                // fallback, user-provided account snapshot or upload receipt.
                if storage == PasskeyProvenance::Synced {
                    let registration = self.create_synced_with_worker(
                        transaction,
                        request_details_json,
                        canceled,
                        session,
                    )?;
                    return Ok(
                        serde_json::json!({"responseJson":serde_json::to_string(&registration)?, "recordId":transaction.to_string()}),
                    );
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
                    // Disclose exclusion only after verified presence; share the
                    // same policy with the syncable creation integration path.
                    self.reject_registration_exclusion(&excluded, &context, &authorization)?;
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
