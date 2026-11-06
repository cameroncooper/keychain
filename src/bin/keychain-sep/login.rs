//! Opt-in hardware check using published synthetic values only. No Apple IO.
use keychain::broker::{
    Operation,
    login::{LoginImport, LoginSelection, RevealField, RevealedLogin, reveal},
    registry::{LoginState, LoginSummary, Recipient},
};
use keychain::model::Credential;
use keychain::paths::{create_private_exclusive, read_bounded};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};
use std::time::{SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const URI: &str =
    "otpauth://totp/diagnostic?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    owner: u32,
    socket: PathBuf,
    initial: LoginImport,
    updated: LoginImport,
}
fn fixture(id: String, updated: bool) -> Credential {
    Credential {
        protected: false,
        id,
        domain: "diagnostic.invalid".into(),
        username: "Synthetic login hardware check".into(),
        title: "Synthetic login hardware check".into(),
        password: if updated {
            "published-password-2"
        } else {
            "published-password-1"
        }
        .into(),
        notes: "Published synthetic notes; no real account".into(),
        totp_uri: URI.into(),
        modified_at: if updated { 2.0 } else { 1.0 },
        last_used: 0.0,
    }
}
fn matches(summary: &LoginSummary, import: &LoginImport, verified: bool) -> bool {
    summary.verified == verified
        && summary.metadata == import.metadata
        && summary.recipient_id == import.recipient_id
        && summary.content_binding == import.content_binding
        && import.expected_revision.checked_add(1) == Some(summary.revision)
}
fn selection(import: &LoginImport) -> LoginSelection {
    LoginSelection {
        id: import.metadata.id.clone(),
        revision: import.expected_revision + 1,
        content_binding: import.content_binding.clone(),
    }
}
fn load_state(socket: &Path, id: &str) -> Result<LoginState> {
    Ok(serde_json::from_value(keychain::broker::call(
        socket,
        Operation::LoginProtectionState { record: id.into() },
    )?)?)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn check_reply(reply: &RevealedLogin, updated: bool, before: u64, after: u64) -> Result<()> {
    let expected = fixture(reply.id.clone(), updated);
    if reply.password.as_deref().map(|s| s.as_str()) != Some(expected.password.as_str())
        || reply.notes.as_deref().map(|s| s.as_str()) != Some(expected.notes.as_str())
    {
        return Err("synthetic reveal changed password/notes".into());
    }
    let code = reply.totp.as_ref().ok_or("synthetic reveal omitted TOTP")?;
    let earliest = before / 30 * 30 + 30;
    let latest = after / 30 * 30 + 30;
    if code.period != 30 || !(earliest..=latest).contains(&code.expires) {
        return Err("synthetic reveal returned a stale/invalid TOTP window".into());
    }
    let expected = keychain::totp::generate(URI, code.expires - 1)
        .ok_or("cannot locally generate synthetic TOTP")?;
    if code.code != expected.code {
        return Err("synthetic reveal returned the wrong TOTP".into());
    }
    Ok(())
}
fn reveal_and_check(socket: &Path, import: &LoginImport, updated: bool) -> Result<()> {
    let before = now()?;
    let reply = reveal(
        socket,
        &selection(import),
        RevealField::All,
        Arc::new(AtomicBool::new(false)),
    )?;
    check_reply(&reply, updated, before, now()?)?;
    // No password, notes, code, URI, plaintext frame or header values are logged.
    println!(
        "verified synthetic password, notes and current TOTP at revision {}",
        reply.revision
    );
    Ok(())
}

fn expect_canceled(reply: keychain::Result<RevealedLogin>) -> Result<()> {
    match reply {
        Err(keychain::Error::Sep(keychain::security::sep::ProviderError::Canceled)) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => {
            Err("cancellation check unexpectedly revealed fields; no values were logged".into())
        }
    }
}

pub(super) fn check(socket: &Path, state_path: &Path, cancel_check: bool) -> Result<()> {
    keychain_sep_driver::memory::make_process_nondumpable()?;
    let owner = keychain_sep_driver::peer::effective_uid();
    if owner == 0 || !socket.is_absolute() {
        return Err("run as the paired desktop user with an absolute broker socket".into());
    }
    let recipient: Recipient =
        serde_json::from_value(keychain::broker::call(socket, Operation::ItemRecipient)?)?;
    let fresh = !state_path.try_exists()?;
    if fresh && cancel_check {
        return Err("cancellation check requires the existing verified synthetic state".into());
    }
    let state: State = if fresh {
        let id = uuid::Uuid::new_v4().to_string();
        let initial = LoginImport::seal(owner, &recipient, 0, &fixture(id.clone(), false))?;
        let updated = LoginImport::seal(owner, &recipient, 1, &fixture(id, true))?;
        let state = State {
            version: 1,
            owner,
            socket: socket.into(),
            initial,
            updated,
        };
        create_private_exclusive(state_path, &serde_json::to_vec(&state)?)?;
        state
    } else {
        let bytes = read_bounded(state_path)?;
        if bytes.len() > 32768 {
            return Err("synthetic state exceeds limit".into());
        }
        serde_json::from_slice(&bytes)?
    };
    if state.version != 1
        || state.owner != owner
        || state.socket != socket
        || state.initial.expected_revision != 0
        || state.updated.expected_revision != 1
        || state.initial.metadata != (&fixture(state.initial.metadata.id.clone(), false)).into()
        || state.updated.metadata != (&fixture(state.initial.metadata.id.clone(), true)).into()
        || state.initial.recipient_id != recipient.id
        || state.updated.recipient_id != recipient.id
    {
        return Err("synthetic state owner/socket/recipient/content mismatch".into());
    }
    let id = &state.initial.metadata.id;
    println!("synthetic login record: {id}");
    let mut current = load_state(socket, id)?;
    if cancel_check {
        if !current
            .active
            .as_ref()
            .is_some_and(|s| matches(s, &state.updated, true))
            || current.staged.is_some()
        {
            return Err(
                "cancellation check requires the unchanged committed synthetic revision 2".into(),
            );
        }
        println!("Cancellation check: DO NOT TOUCH the reader; click Cancel or press Escape.");
        expect_canceled(reveal(
            socket,
            &selection(&state.updated),
            RevealField::All,
            Arc::new(AtomicBool::new(false)),
        ))?;
        let after = load_state(socket, id)?;
        if !after
            .active
            .as_ref()
            .is_some_and(|s| matches(s, &state.updated, true))
            || after.staged.is_some()
        {
            return Err("synthetic state changed during cancellation".into());
        }
        println!(
            "verified desktop cancellation: no successful field response; revision 2 unchanged"
        );
        return Ok(());
    }
    if fresh {
        if current.active.is_some() || current.staged.is_some() {
            return Err("synthetic record unexpectedly exists".into());
        }
        keychain::broker::call(
            socket,
            Operation::ImportLogin {
                import: Box::new(state.initial.clone()),
            },
        )?;
        current = load_state(socket, id)?;
    }
    if current.active.is_none() {
        if !current
            .staged
            .as_ref()
            .is_some_and(|s| matches(s, &state.initial, false))
        {
            return Err(
                "initial synthetic staging is missing or changed; refusing recreation".into(),
            );
        }
        println!("Initial verification: touch only when the desktop prompt requests it.");
        keychain::broker::call(
            socket,
            Operation::VerifyLogin {
                selection: selection(&state.initial),
            },
        )?;
        current = load_state(socket, id)?;
    }
    if current
        .active
        .as_ref()
        .is_some_and(|s| matches(s, &state.updated, true))
    {
        if current
            .staged
            .as_ref()
            .is_some_and(|s| !matches(s, &state.updated, false))
        {
            return Err("unexpected staged version after synthetic update".into());
        }
        println!(
            "Persistence check: a fresh desktop fingerprint operation will reveal the updated item."
        );
        return reveal_and_check(socket, &state.updated, true);
    }
    if !current
        .active
        .as_ref()
        .is_some_and(|s| matches(s, &state.initial, true))
    {
        return Err("verified synthetic predecessor is missing or changed".into());
    }
    if current.staged.is_none() {
        println!(
            "Initial reveal: a fresh desktop fingerprint operation will check the published synthetic fields."
        );
        reveal_and_check(socket, &state.initial, false)?;
        keychain::broker::call(
            socket,
            Operation::ImportLogin {
                import: Box::new(state.updated.clone()),
            },
        )?;
        current = load_state(socket, id)?;
    }
    if !current
        .staged
        .as_ref()
        .is_some_and(|s| matches(s, &state.updated, false))
    {
        return Err("synthetic successor is missing or changed".into());
    }
    println!(
        "Update and reveal: one desktop fingerprint operation should commit and reveal revision 2."
    );
    reveal_and_check(socket, &state.updated, true)?;
    let current = load_state(socket, id)?;
    if !current
        .active
        .as_ref()
        .is_some_and(|s| matches(s, &state.updated, true))
        || current.staged.is_some()
    {
        return Err("synthetic update was not durably committed and cleaned up".into());
    }
    println!(
        "verified synthetic update commit; rerun the same command for fresh-process/reboot validation"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reply(at: u64) -> RevealedLogin {
        let item = fixture(uuid::Uuid::new_v4().to_string(), true);
        RevealedLogin {
            id: item.id.clone(),
            revision: 2,
            password: Some(zeroize::Zeroizing::new(item.password.clone())),
            notes: Some(zeroize::Zeroizing::new(item.notes.clone())),
            totp: keychain::totp::generate(URI, at),
        }
    }
    #[test]
    fn accepts_both_sides_of_clock_rollover_but_rejects_stale_or_wrong_output() {
        let first = reply(59);
        assert_eq!(
            first.totp.as_ref().map(|code| code.code.as_str()),
            Some("94287082")
        );
        let mut second = reply(60);
        assert!(check_reply(&first, true, 59, 60).is_ok());
        assert!(check_reply(&second, true, 59, 60).is_ok());
        assert!(check_reply(&first, true, 60, 61).is_err());
        assert!(check_reply(&second, false, 59, 60).is_err());
        second
            .totp
            .as_mut()
            .unwrap_or_else(|| panic!("missing fixture code"))
            .code = "00000000".into();
        assert!(check_reply(&second, true, 59, 60).is_err());
    }
    #[test]
    fn cancellation_check_requires_cancel_and_refuses_success_or_timeout() {
        use keychain::security::sep::ProviderError;
        assert!(expect_canceled(Err(ProviderError::Canceled.into())).is_ok());
        assert!(expect_canceled(Err(ProviderError::Expired.into())).is_err());
        assert!(expect_canceled(Ok(reply(59))).is_err());
    }
    #[test]
    fn rejects_missing_fields_and_changed_notes() {
        let mut value = reply(59);
        value.password = None;
        assert!(check_reply(&value, true, 59, 59).is_err());
        let mut value = reply(59);
        value.notes = Some(zeroize::Zeroizing::new("changed".into()));
        assert!(check_reply(&value, true, 59, 59).is_err());
        let mut value = reply(59);
        value.totp = None;
        assert!(check_reply(&value, true, 59, 59).is_err());
    }
}
