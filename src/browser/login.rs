//! Browser-scoped intentional login reveal. Destination policy is repeated in
//! the root broker; extension-side matching is never an authorization grant.
use crate::broker::{
    Operation,
    login::{LoginMetadata, LoginSelection, RevealField},
};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FillContext {
    pub origin: String,
    pub document: Uuid,
    pub target: Uuid,
    pub nonce: Uuid,
}
impl FillContext {
    pub fn validate(&self) -> Result<()> {
        let url = url::Url::parse(&self.origin)?;
        if self.origin.len() > 1024
            || url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.origin().ascii_serialization() != self.origin
            || [self.document, self.target, self.nonce]
                .iter()
                .any(|id| id.get_version_num() != 4)
        {
            return Err(Error::Security(
                "invalid browser autofill destination".into(),
            ));
        }
        Ok(())
    }
    /// HTTPS sites match by registrable domain, including PSL private suffixes.
    /// Bare website names mean HTTPS on its default port. IPs, local names and
    /// unknown suffixes stay host-exact; ports must always match.
    pub fn matches(&self, metadata: &LoginMetadata) -> Result<bool> {
        self.validate()?;
        if metadata.domain.trim() != metadata.domain {
            return Ok(false);
        }
        let text = if metadata.domain.contains("://") {
            metadata.domain.clone()
        } else {
            format!("https://{}", metadata.domain)
        };
        let Ok(url) = url::Url::parse(&text) else {
            return Ok(false);
        };
        let destination = url::Url::parse(&self.origin)?;
        Ok(url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.port_or_known_default() == destination.port_or_known_default()
            && matching_login_hosts(&url, &destination))
    }
    pub(crate) fn matches_passkey(&self, rp_id: &str) -> Result<bool> {
        self.validate()?;
        if rp_id.is_empty()
            || psl::suffix(rp_id.as_bytes())
                .is_some_and(|suffix| suffix.is_known() && suffix.as_bytes() == rp_id.as_bytes())
        {
            return Ok(false);
        }
        Ok(crate::passkey::validate_origin_for_rp(&self.origin, rp_id).is_ok())
    }
    pub(crate) fn authorize(&self, metadata: &LoginMetadata, field: RevealField) -> Result<()> {
        if !matches!(field, RevealField::Password | RevealField::Totp) || !self.matches(metadata)? {
            return Err(Error::Security(
                "selected login is not eligible for this browser destination".into(),
            ));
        }
        if (field == RevealField::Password && !metadata.has_password)
            || (field == RevealField::Totp && !metadata.has_totp)
        {
            return Err(Error::Refused(
                "selected login has no requested field".into(),
            ));
        }
        Ok(())
    }
}

// URL parsing canonicalizes case and IDNA before this check. Do not use a
// string suffix or last-two-label comparison: co.uk and private hosting suffixes
// (for example github.io) contain unrelated credential destinations.
fn matching_login_hosts(saved: &url::Url, destination: &url::Url) -> bool {
    match (saved.host(), destination.host()) {
        (Some(url::Host::Domain(saved)), Some(url::Host::Domain(destination))) => {
            let saved = saved.strip_suffix('.').unwrap_or(saved);
            let destination = destination.strip_suffix('.').unwrap_or(destination);
            if saved == destination {
                return true;
            }
            fn registrable(host: &str) -> Option<&[u8]> {
                if host.len() > 253
                    || host.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    })
                {
                    return None;
                }
                psl::domain(host.as_bytes())
                    .filter(|domain| domain.suffix().is_known())
                    .map(|domain| domain.as_bytes())
            }
            match (registrable(saved), registrable(destination)) {
                (Some(saved), Some(destination)) => saved == destination,
                _ => false,
            }
        }
        (Some(saved), Some(destination)) => saved == destination,
        _ => false,
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum LoginCandidate {
    Login {
        selection: LoginSelection,
        username: String,
        title: String,
        #[serde(rename = "hasPassword")]
        has_password: bool,
        #[serde(rename = "hasTotp")]
        has_totp: bool,
    },
    Passkey {
        id: String,
        username: String,
        title: String,
    },
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
enum Request {
    InspectLogins {
        version: u32,
        context: FillContext,
    },
    FillLogin {
        version: u32,
        context: FillContext,
        selection: LoginSelection,
        field: RevealField,
    },
}

/// Handles the separate login protocol directly into a protected output frame.
/// No password/code is ever converted into a serde_json::Value or logged.
pub fn dispatch(
    message: &[u8],
    socket: &Path,
    canceled: Arc<AtomicBool>,
    writer: &mut dyn Write,
) -> Option<Result<()>> {
    #[derive(Deserialize)]
    struct Header {
        action: String,
    }
    let kind: Header = serde_json::from_slice(message).ok()?;
    if !matches!(
        Some(kind.action.as_str()),
        Some("inspectLogins" | "fillLogin")
    ) {
        return None;
    }
    let result = (|| -> Result<()> {
        let request: Request = serde_json::from_slice(message)?;
        let (version, context) = match &request {
            Request::InspectLogins { version, context }
            | Request::FillLogin {
                version, context, ..
            } => (*version, context),
        };
        if version != 1 {
            return Err(Error::InvalidData(
                "unsupported browser login version".into(),
            ));
        }
        context.validate()?;
        match request {
            Request::InspectLogins { context, .. } => {
                let candidates = crate::broker::call_cancelable(
                    socket,
                    Operation::InspectBrowserLogins { context },
                    canceled.clone(),
                )?;
                write_public_reply(
                    writer,
                    &serde_json::json!({"ok":true,"result":{"kind":"logins","candidates":candidates,"managerAvailable":super::manager_available()}}),
                    &canceled,
                )
            }
            Request::FillLogin {
                context,
                selection,
                field,
                ..
            } => {
                if !matches!(field, RevealField::Password | RevealField::Totp) {
                    return Err(Error::Security(
                        "browser may request only a password or current code".into(),
                    ));
                }
                let revealed = crate::broker::login::fill(
                    socket,
                    &context,
                    &selection,
                    field,
                    canceled.clone(),
                )?;
                #[derive(Serialize)]
                struct Result<'a> {
                    kind: &'static str,
                    id: &'a str,
                    revision: u64,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    password: Option<&'a str>,
                    #[serde(skip_serializing_if = "Option::is_none")]
                    totp: Option<&'a crate::totp::GeneratedCode>,
                }
                #[derive(Serialize)]
                struct Reply<'a> {
                    ok: bool,
                    result: Result<'a>,
                }
                write_reply(
                    writer,
                    &Reply {
                        ok: true,
                        result: Result {
                            kind: "login",
                            id: &revealed.id,
                            revision: revealed.revision,
                            password: revealed.password.as_deref().map(|s| s.as_str()),
                            totp: revealed.totp.as_ref(),
                        },
                    },
                    &canceled,
                )
            }
        }
    })();
    Some(result.or_else(|error| {
        // A write failure may have emitted part of a secret frame. Never append
        // another frame to it, and do not reflect a private deserialization error.
        if matches!(&error, Error::Io { .. }) || canceled.load(Ordering::Acquire) {
            return Err(error);
        }
        let error = if matches!(error, Error::Json(_)) {
            Error::Security("invalid browser login response".into())
        } else {
            error
        };
        write_reply(writer, &super::error_reply(&error), &canceled)
    }))
}

fn write_public_reply(
    writer: &mut dyn Write,
    reply: &impl Serialize,
    canceled: &AtomicBool,
) -> Result<()> {
    let data = serde_json::to_vec(reply)?;
    if data.len() > super::MAX_NATIVE_MESSAGE_BYTES {
        return Err(Error::Refused("login inventory reply is too large".into()));
    }
    if canceled.load(Ordering::Acquire) {
        return Err(crate::security::sep::ProviderError::Canceled.into());
    }
    writer
        .write_all(&(data.len() as u32).to_le_bytes())
        .map_err(|e| Error::io("native inventory reply", e))?;
    writer
        .write_all(&data)
        .map_err(|e| Error::io("native inventory reply", e))?;
    writer
        .flush()
        .map_err(|e| Error::io("native inventory reply", e))
}

fn write_reply(
    writer: &mut dyn Write,
    reply: &(impl Serialize + Sync),
    canceled: &AtomicBool,
) -> Result<()> {
    let mut memory = keychain_sep_driver::memory::LockedBuffer::<32768>::new()
        .map_err(|e| Error::io("browser login output", e))?;
    let destination = &mut memory.as_mut_array()[..];
    let length = crate::security::secret_compute(|| {
        let mut cursor = io::Cursor::new(destination);
        serde_json::to_writer(&mut cursor, reply)?;
        Ok(cursor.position() as usize)
    })?;
    if canceled.load(Ordering::Acquire) {
        return Err(crate::security::sep::ProviderError::Canceled.into());
    }
    writer
        .write_all(&(length as u32).to_le_bytes())
        .map_err(|e| Error::io("native login reply", e))?;
    writer
        .write_all(&memory.as_array()[..length])
        .map_err(|e| Error::io("native login reply", e))?;
    writer
        .flush()
        .map_err(|e| Error::io("native login reply", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context() -> FillContext {
        FillContext {
            origin: "https://example.com".into(),
            document: Uuid::new_v4(),
            target: Uuid::new_v4(),
            nonce: Uuid::new_v4(),
        }
    }
    fn metadata(domain: &str) -> LoginMetadata {
        LoginMetadata {
            id: Uuid::new_v4().to_string(),
            domain: domain.into(),
            username: "alice".into(),
            title: "Test".into(),
            modified_at: 1.,
            last_used: 0.,
            has_password: true,
            has_notes: true,
            has_totp: true,
        }
    }
    #[test]
    fn destination_policy_groups_sites_and_disallows_other_reveal_purposes() {
        let scope = context();
        assert!(scope.matches(&metadata("example.com")).unwrap_or(false));
        assert!(
            scope
                .matches(&metadata("https://EXAMPLE.com/login"))
                .unwrap_or(false)
        );
        for other in [
            "other.com",
            "example.com:8443",
            "http://example.com",
            "https://user@example.com",
            "*.example.com",
            "",
        ] {
            assert!(!scope.matches(&metadata(other)).unwrap_or(false), "{other}");
        }
        assert!(
            scope
                .authorize(&metadata("example.com"), RevealField::Notes)
                .is_err()
        );
        assert!(
            scope
                .authorize(&metadata("example.com"), RevealField::All)
                .is_err()
        );
        let mut bad = scope.clone();
        bad.origin = "https://example.com/path".into();
        assert!(bad.validate().is_err());
        bad = context();
        bad.document = Uuid::nil();
        assert!(bad.validate().is_err());
    }
    #[test]
    fn site_matching_uses_public_and_private_suffix_boundaries() {
        let cases = [
            ("apple.com", "https://account.apple.com", true),
            (
                "https://account.apple.com/login",
                "https://developer.apple.com",
                true,
            ),
            ("https://account.apple.com", "https://apple.com", true),
            ("apple.com", "https://apple.com.attacker.com", false),
            ("apple.com", "https://notapple.com", false),
            ("apple.com", "https://icloud.com", false),
            ("login.example.co.uk", "https://account.example.co.uk", true),
            ("example.co.uk", "https://other.co.uk", false),
            ("co.uk", "https://example.co.uk", false),
            ("alice.github.io", "https://login.alice.github.io", true),
            ("alice.github.io", "https://bob.github.io", false),
            ("github.io", "https://alice.github.io", false),
            ("alice.blogspot.com", "https://bob.blogspot.com", false),
            ("a.b.ck", "https://c.b.ck", false), // PSL wildcard
            ("www.ck", "https://login.www.ck", true), // PSL exception
            ("bücher.de", "https://login.xn--bcher-kva.de", true),
            ("APPLE.COM", "https://account.apple.com", true),
            ("apple.com.", "https://account.apple.com", true),
            ("*.apple.com", "https://account.apple.com", false),
            ("apple..com", "https://account.apple.com", false),
            ("apple.com", "https://account.apple.com:8443", false),
            (
                "https://apple.com:8443",
                "https://account.apple.com:8443",
                true,
            ),
            ("http://apple.com", "https://account.apple.com", false),
            ("https://user@apple.com", "https://account.apple.com", false),
            ("127.0.0.1", "https://127.0.0.1", true),
            ("127.0.0.1", "https://127.0.0.2", false),
            ("[::1]", "https://[::1]", true),
            ("[::1]", "https://[::2]", false),
            ("localhost", "https://localhost", true),
            ("localhost", "https://login.localhost", false),
            ("vault.corp", "https://vault.corp", true),
            ("vault.corp", "https://other.vault.corp", false),
        ];
        for (saved, origin, expected) in cases {
            let scope = FillContext {
                origin: origin.into(),
                ..context()
            };
            assert_eq!(
                scope.matches(&metadata(saved)).unwrap_or(false),
                expected,
                "{saved} -> {origin}"
            );
            assert_eq!(
                scope
                    .authorize(&metadata(saved), RevealField::Password)
                    .is_ok(),
                expected,
                "private check: {saved} -> {origin}"
            );
            assert_eq!(
                scope.authorize(&metadata(saved), RevealField::Totp).is_ok(),
                expected,
                "code check: {saved} -> {origin}"
            );
        }
    }

    #[test]
    fn passkey_username_suggestions_follow_rp_scope_not_password_site_grouping() {
        for (origin, rp, expected) in [
            ("https://webauthn.io", "webauthn.io", true),
            ("https://login.webauthn.io", "webauthn.io", true),
            ("https://webauthn.io", "login.webauthn.io", false),
            ("https://other.webauthn.io", "login.webauthn.io", false),
            ("https://webauthn.io.attacker.com", "webauthn.io", false),
            ("https://webauthn.io", "io", false),
            ("https://alice.github.io", "github.io", false),
            ("https://localhost", "localhost", true),
        ] {
            let scope = FillContext {
                origin: origin.into(),
                ..context()
            };
            assert_eq!(
                scope.matches_passkey(rp).unwrap_or(false),
                expected,
                "{origin} -> {rp}"
            );
        }
    }

    #[test]
    fn browser_cannot_request_notes_or_all_fields_even_before_connection() {
        for field in ["notes", "all"] {
            let request = serde_json::json!({"version":1,"action":"fillLogin","context":context(),
                "selection":{"id":Uuid::new_v4().to_string(),"revision":1,"content_binding":"a".repeat(64)},"field":field});
            let mut output = Vec::new();
            dispatch(
                request.to_string().as_bytes(),
                Path::new("/nonexistent-keychain-test-socket"),
                Arc::new(AtomicBool::new(false)),
                &mut output,
            )
            .unwrap_or_else(|| panic!("not dispatched"))
            .unwrap_or_else(|e| panic!("reply: {e}"));
            let reply: serde_json::Value =
                serde_json::from_slice(&output[4..]).unwrap_or_else(|e| panic!("json: {e}"));
            assert_eq!(reply["ok"], false);
            assert_eq!(reply["error"]["name"], "SecurityError");
        }
    }
}
