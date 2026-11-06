use super::*;
use crate::broker::registry::test_support::{binding, context, open_scalar, registry};
use base64::engine::general_purpose::STANDARD;

fn receipt(record: &ProtectedRecord, binding: &Binding) -> Result<VerifiedUpload> {
    let mut private = zeroize::Zeroizing::new(decode_public(&record.public_sec1)?);
    private.extend_from_slice(&open_scalar(record)?);
    crate::apple::ckks::upload::tests::verified_for(
        binding.clone(),
        record.credential.clone(),
        &private,
    )
}

fn sign(
    record: &ProtectedRecord,
    message: &[u8],
    scalar: &[u8],
    uv: bool,
    protection: crate::security::authorization::SigningProtection,
) -> Result<AuthorizedSignature> {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    let key =
        SigningKey::from_slice(scalar).map_err(|_| Error::Security("test signing key".into()))?;
    let signature: Signature = key.sign(message);
    Ok(AuthorizedSignature::new(
        signature.to_der().as_bytes().to_vec(),
        &record.credential.signing_key,
        message,
        uv,
        protection,
    ))
}

#[test]
#[ignore = "requires root; synthetic upload/signature only, no hardware or network"]
fn synced_promotion_requires_verified_backup_and_uv_and_resumes_uncertain_delivery() -> Result<()> {
    use crate::security::authorization::SigningProtection;
    use std::cell::Cell;
    assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
    let dir = tempfile::tempdir().map_err(|e| Error::io("temporary registry", e))?;
    let registry = registry(dir.path())?;
    let context = context()?;
    let binding = binding(&context);
    registry.set_synced_inventory(binding.owner, vec![])?;
    let draft = registry.prepare_synced_registration(&binding, &context)?;
    let record = draft.record();
    let scalar = open_scalar(record)?;
    let verified = receipt(record, &binding)?;
    let id = &record.credential.id;

    for (uv, protection) in [
        (false, SigningProtection::SepProtectedSoftware),
        (true, SigningProtection::Software),
        (true, SigningProtection::SepNative),
    ] {
        assert!(
            registry
                .finish_synced_registration(
                    &binding,
                    &context,
                    &verified,
                    |record, message| sign(record, message, &scalar, uv, protection),
                    || Ok(())
                )
                .is_err()
        );
        assert!(registry.browser_credentials(binding.owner)?.is_empty());
        assert_eq!(
            registry.read_synced_creation(id, binding.owner)?.phase,
            CreationPhase::Prepared
        );
    }
    let other = Binding {
        owner: 1002,
        ..binding.clone()
    };
    let wrong_receipt = receipt(record, &other)?;
    assert!(
        registry
            .finish_synced_registration(
                &binding,
                &context,
                &wrong_receipt,
                |_, _| panic!("wrong upload reached signer"),
                || Ok(())
            )
            .is_err()
    );
    assert!(
        registry
            .finish_synced_registration(
                &binding,
                &context,
                &verified,
                |record, message| sign(
                    record,
                    message,
                    &[8u8; 32],
                    true,
                    SigningProtection::SepProtectedSoftware
                ),
                || Ok(())
            )
            .is_err()
    );
    for cancel_at in 1..=3 {
        let checks = Cell::new(0);
        assert!(
            registry
                .finish_synced_registration(
                    &binding,
                    &context,
                    &verified,
                    |record, message| sign(
                        record,
                        message,
                        &scalar,
                        true,
                        SigningProtection::SepProtectedSoftware
                    ),
                    || {
                        checks.set(checks.get() + 1);
                        if checks.get() == cancel_at {
                            Err(Error::Refused("synthetic cancellation".into()))
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
        );
        assert_eq!(
            registry.read_synced_creation(id, binding.owner)?.phase,
            CreationPhase::Prepared
        );
        assert!(registry.browser_credentials(binding.owner)?.is_empty());
    }
    // Cancellation after durable commit must suppress the response. The
    // saved credential remains usable only through a new authorized use.
    let checks = Cell::new(0);
    let signatures = Cell::new(0);
    assert!(
        registry
            .finish_synced_registration(
                &binding,
                &context,
                &verified,
                |record, message| {
                    signatures.set(signatures.get() + 1);
                    sign(
                        record,
                        message,
                        &scalar,
                        true,
                        SigningProtection::SepProtectedSoftware,
                    )
                },
                || {
                    checks.set(checks.get() + 1);
                    if checks.get() == 4 {
                        Err(Error::Refused("synthetic late cancellation".into()))
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
    );
    assert_eq!(signatures.get(), 1);
    assert_eq!(
        registry.read_synced_creation(id, binding.owner)?.phase,
        CreationPhase::Committed
    );
    assert_eq!(
        registry.browser_credentials(binding.owner)?,
        vec![record.credential.clone()]
    );
    let state = registry.protection_state(id, binding.owner)?;
    assert!(state.staged.is_none());
    assert!(state.active.is_some_and(|active| active.verified));

    // Normal sync metadata refresh and verified same-key rewraps continue
    // working after creation. A delivery retry cannot overwrite either.
    let mut updated = record.credential.clone();
    updated.username = "Renamed after creation".into();
    updated.modified_at += 1.0;
    registry.refresh_protected_metadata(binding.owner, updated.clone(), &record.public_sec1, 1)?;
    let import = ProtectedImport::seal_scalar(
        binding.owner,
        &registry.item_recipient()?,
        1,
        updated.clone(),
        &scalar,
        false,
    )?;
    registry.import_protected(binding.owner, import)?;
    let staged = registry.verification_record(id, binding.owner)?;
    registry.commit_verified(&staged)?; // Synthetic verified-UV fixture only.
    assert_eq!(registry.load_protected(id, binding.owner)?.revision, 2);
    drop(registry);
    let reopened = Registry::open(dir.path())?;
    let resumed = reopened.prepare_synced_registration(&binding, &context)?;
    assert_eq!(resumed.record().sealed, record.sealed);
    let response = reopened.finish_synced_registration(
        &binding,
        &context,
        &verified,
        |record, message| {
            signatures.set(signatures.get() + 1);
            sign(
                record,
                message,
                &scalar,
                true,
                SigningProtection::SepProtectedSoftware,
            )
        },
        || Ok(()),
    )?;
    assert_eq!(signatures.get(), 2);
    assert_eq!(response.id, record.credential.credential_id);
    let active = reopened.load_protected(id, binding.owner)?;
    assert_eq!(active.revision, 2);
    assert_eq!(active.credential, updated);
    let auth = URL_SAFE_NO_PAD
        .decode(response.response.authenticator_data)
        .map_err(|_| Error::Security("test response".into()))?;
    assert_eq!(auth[32], 0x5d);
    // Losing a committed active file must never cause resurrection from an
    // old draft, even though that draft still holds a valid sealed copy.
    let active_path = reopened.protected_filename(id)?;
    std::fs::remove_file(&active_path).map_err(|e| Error::io(&active_path, e))?;
    assert!(
        reopened
            .finish_synced_registration(
                &binding,
                &context,
                &verified,
                |_, _| panic!("missing committed record reached signer"),
                || Ok(())
            )
            .is_err()
    );
    assert!(!active_path.exists());
    Ok(())
}

#[test]
#[ignore = "requires root; synthetic interrupted promotions only, no hardware or network"]
fn interrupted_synced_promotion_remains_hidden_and_reopens_with_the_same_key() -> Result<()> {
    use crate::security::authorization::SigningProtection;
    assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
    for transition in 0..3 {
        let dir = tempfile::tempdir().map_err(|e| Error::io("temporary registry", e))?;
        let registry = registry(dir.path())?;
        let context = context()?;
        let binding = binding(&context);
        registry.set_synced_inventory(binding.owner, vec![])?;
        let draft = registry.prepare_synced_registration(&binding, &context)?;
        let record = draft.record();
        let id = &record.credential.id;
        let scalar = open_scalar(record)?;
        let verified = receipt(record, &binding)?;
        // Stop after each actual durable transition, before the commit
        // marker: Activating, active write, then inventory inclusion.
        let mut interrupted = registry.read_synced_creation(id, binding.owner)?;
        interrupted.phase = CreationPhase::Activating;
        registry.write_synced_creation(&interrupted)?;
        if transition >= 1 {
            let mut active = record.clone();
            active.verified = true;
            registry.write_protected(&active, true)?;
        }
        if transition >= 2 {
            registry.include_synced_record(id, binding.owner)?;
        }
        drop(registry);
        let reopened = Registry::open(dir.path())?;
        assert!(reopened.browser_credentials(binding.owner)?.is_empty());
        let state = reopened.protection_state(id, binding.owner)?;
        assert!(state.active.is_none());
        assert!(state.staged.is_some());
        assert!(reopened.load_protected(id, binding.owner).is_err());
        assert!(reopened.verification_record(id, binding.owner).is_err());
        assert!(reopened.commit_verified(record).is_err());
        let import = ProtectedImport::seal_scalar(
            binding.owner,
            &reopened.item_recipient()?,
            0,
            record.credential.clone(),
            &scalar,
            false,
        )?;
        assert!(reopened.import_protected(binding.owner, import).is_err());
        let resumed = reopened.prepare_synced_registration(&binding, &context)?;
        assert_eq!(resumed.record().sealed, record.sealed);
        let response = reopened.finish_synced_registration(
            &binding,
            &context,
            &verified,
            |selected, message| {
                sign(
                    selected,
                    message,
                    &scalar,
                    true,
                    SigningProtection::SepProtectedSoftware,
                )
            },
            || Ok(()),
        )?;
        assert_eq!(response.id, record.credential.credential_id);
        assert_eq!(
            reopened.browser_credentials(binding.owner)?,
            vec![record.credential.clone()]
        );
        assert_eq!(
            reopened.load_protected(id, binding.owner)?.sealed,
            record.sealed
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires root; synthetic concurrent update only, no hardware or network"]
fn synced_promotion_refuses_a_draft_changed_during_authorization() -> Result<()> {
    use crate::security::authorization::SigningProtection;
    assert_eq!(keychain_sep_driver::peer::effective_uid(), 0);
    let dir = tempfile::tempdir().map_err(|e| Error::io("temporary registry", e))?;
    let registry = registry(dir.path())?;
    let context = context()?;
    let binding = binding(&context);
    let draft = registry.prepare_synced_registration(&binding, &context)?;
    let record = draft.record();
    let scalar = open_scalar(record)?;
    let verified = receipt(record, &binding)?;
    assert!(
        registry
            .finish_synced_registration(
                &binding,
                &context,
                &verified,
                |record, message| {
                    let mut concurrent =
                        registry.read_synced_creation(&record.credential.id, binding.owner)?;
                    concurrent.phase = CreationPhase::Activating;
                    registry.write_synced_creation(&concurrent)?;
                    sign(
                        record,
                        message,
                        &scalar,
                        true,
                        SigningProtection::SepProtectedSoftware,
                    )
                },
                || Ok(())
            )
            .is_err()
    );
    assert!(registry.browser_credentials(binding.owner)?.is_empty());
    assert!(
        registry
            .load_protected(&record.credential.id, binding.owner)
            .is_err()
    );
    registry.finish_synced_registration(
        &binding,
        &context,
        &verified,
        |record, message| {
            sign(
                record,
                message,
                &scalar,
                true,
                SigningProtection::SepProtectedSoftware,
            )
        },
        || Ok(()),
    )?;
    assert_eq!(
        registry.browser_credentials(binding.owner)?,
        vec![record.credential.clone()]
    );
    Ok(())
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

    let scalar = open_scalar(record)?;
    let disk = registry.backend.open(
        Purpose::Vault,
        &read_bounded(&registry.synced_creation_filename(&record.credential.id, false)?)?,
    )?;
    assert!(!disk.windows(32).any(|bytes| bytes == scalar.as_slice()));
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
        &scalar,
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
fn synced_creation_refuses_interrupted_intents_collisions_and_missing_recipient() -> Result<()> {
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
