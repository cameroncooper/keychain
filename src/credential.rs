use std::collections::BTreeMap;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use plist::{Dictionary, Value};

use crate::apple::pipeline::DecryptedItem;
use crate::model::Credential;
use crate::secret::zeroize_plist_dictionary;

const APPLE_EPOCH: f64 = 978_307_200.0;
const SIDECAR_PREFIX: &str = "com.apple.password-manager";
const SIDECAR_LABEL_PREFIX: &str = "password manager metadata:";
const PASSKEY_ACCESS_GROUP: &str = "com.apple.webkit.webauthn";

pub struct Projection {
    pub credentials: Vec<Credential>,
    pub ignored_passkeys: usize,
}

pub fn normalize_host(value: &str) -> String {
    let trimmed = value.trim().to_ascii_lowercase();
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(&trimmed);
    let authority = without_scheme.split(['/', '?']).next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    let host = host.split(':').next().unwrap_or_default();
    host.strip_prefix("www.").unwrap_or(host).to_owned()
}

pub fn domains_match(page: &str, stored: &str) -> bool {
    let page = normalize_host(page);
    let stored = normalize_host(stored);
    if page.is_empty() || stored.is_empty() {
        return false;
    }
    page == stored || page.ends_with(&format!(".{stored}")) || stored.ends_with(&format!(".{page}"))
}

pub fn search<'a>(credentials: &'a [Credential], query: &str) -> Vec<&'a Credential> {
    let query = query.trim().to_ascii_lowercase();
    let mut found: Vec<_> = credentials
        .iter()
        .filter(|c| {
            query.is_empty()
                || c.id.to_ascii_lowercase().starts_with(&query)
                || c.domain.to_ascii_lowercase().contains(&query)
                || c.username.to_ascii_lowercase().contains(&query)
                || c.title.to_ascii_lowercase().contains(&query)
        })
        .collect();
    found.sort_by(|a, b| {
        b.recency()
            .total_cmp(&a.recency())
            .then_with(|| a.domain.cmp(&b.domain))
            .then_with(|| a.username.cmp(&b.username))
    });
    found
}

pub fn printable(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { '.' } else { ch })
        .collect()
}

enum Payload {
    Password(String),
    Sidecar(Dictionary),
    Drop,
}

fn text(fields: &Dictionary, names: &[&str]) -> String {
    names
        .iter()
        .find_map(|name| fields.get(name))
        .and_then(|value| match value {
            Value::String(value) => Some(value.clone()),
            Value::Data(value) => Some(String::from_utf8_lossy(value).into_owned()),
            _ => None,
        })
        .unwrap_or_default()
}

fn payload(fields: &Dictionary, access_group: &str) -> Payload {
    let forced_sidecar = access_group.starts_with(SIDECAR_PREFIX);
    if access_group == PASSKEY_ACCESS_GROUP
        || access_group == "com.apple.safari.credit-cards"
        || (access_group.starts_with("com.apple.")
            && !access_group.starts_with(SIDECAR_PREFIX)
            && access_group != "com.apple.cfnetwork")
    {
        return Payload::Drop;
    }
    let Some(value) = fields.get("v_Data").or_else(|| fields.get("password")) else {
        return if forced_sidecar {
            Payload::Sidecar(Dictionary::new())
        } else {
            Payload::Password(String::new())
        };
    };
    let parsed = match value {
        Value::String(value) => {
            return if forced_sidecar {
                Payload::Sidecar(Dictionary::new())
            } else {
                Payload::Password(value.clone())
            };
        }
        Value::Data(value) if value.starts_with(b"bplist00") => {
            match Value::from_reader(Cursor::new(value)) {
                Ok(value) => Some(value),
                Err(_) if forced_sidecar => return Payload::Sidecar(Dictionary::new()),
                Err(_) => return Payload::Drop,
            }
        }
        Value::Data(value)
            if value
                .iter()
                .skip_while(|byte| byte.is_ascii_whitespace())
                .take(5)
                .copied()
                .eq(b"<?xml".iter().copied()) =>
        {
            return if forced_sidecar {
                Payload::Sidecar(Dictionary::new())
            } else {
                Payload::Drop
            };
        }
        Value::Data(value) => {
            let Ok(value) = std::str::from_utf8(value) else {
                return if forced_sidecar {
                    Payload::Sidecar(Dictionary::new())
                } else {
                    Payload::Drop
                };
            };
            if value
                .chars()
                .any(|ch| (ch.is_control() && !matches!(ch, '\t' | '\n' | '\r')) || ch == '\u{7f}')
            {
                return if forced_sidecar {
                    Payload::Sidecar(Dictionary::new())
                } else {
                    Payload::Drop
                };
            }
            return if forced_sidecar {
                Payload::Sidecar(Dictionary::new())
            } else {
                Payload::Password(value.to_owned())
            };
        }
        _ => {
            return if forced_sidecar {
                Payload::Sidecar(Dictionary::new())
            } else {
                Payload::Drop
            };
        }
    };
    let Some(Value::Dictionary(mut dictionary)) = parsed else {
        return if forced_sidecar {
            Payload::Sidecar(Dictionary::new())
        } else {
            Payload::Drop
        };
    };
    let keys: std::collections::BTreeSet<_> = dictionary.keys().map(String::as_str).collect();
    let should_drop = (["tlkUUID", "srcIdentity"]
        .iter()
        .all(|key| keys.contains(key)))
        || (["viewName", "encryptedData"]
            .iter()
            .all(|key| keys.contains(key)))
        || [
            "CardNumber",
            "FPANHash",
            "PrimaryAccountIdentifier",
            "CardSecurityCode",
        ]
        .iter()
        .any(|key| keys.contains(key));
    if should_drop {
        zeroize_plist_dictionary(&mut dictionary);
        Payload::Drop
    } else {
        Payload::Sidecar(dictionary)
    }
}

fn is_credential(domain: &str, title: &str) -> bool {
    [domain, title].into_iter().all(|value| {
        let value = value.trim().to_ascii_lowercase();
        !value.starts_with("pcs ")
            && !value.starts_with("pcs-")
            && !value.starts_with("website metadata")
            && !value.contains("com.apple.")
    })
}

fn number(value: &Value) -> Option<f64> {
    match value {
        Value::Real(value) => Some(*value),
        Value::Integer(value) => value
            .as_signed()
            .map(|value| value as f64)
            .or_else(|| value.as_unsigned().map(|value| value as f64)),
        _ => None,
    }
}

fn to_unix(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::Date(date)) => {
            let time: SystemTime = (*date).into();
            time.duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs_f64())
                .unwrap_or_default()
        }
        Some(value) => number(value)
            .filter(|value| *value > 0.0)
            .map(|value| {
                if value < 1e9 {
                    value + APPLE_EPOCH
                } else {
                    value
                }
            })
            .unwrap_or_default(),
        None => 0.0,
    }
}

fn sidecar_last_used(value: Option<&Value>) -> f64 {
    let Some(Value::Dictionary(profiles)) = value else {
        return 0.0;
    };
    profiles
        .values()
        .filter_map(Value::as_dictionary)
        .map(|profile| to_unix(profile.get("lUsed").or_else(|| profile.get("slUsed"))))
        .fold(0.0, f64::max)
}

fn sidecar_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Data(value)) => String::from_utf8_lossy(value).into_owned(),
        _ => String::new(),
    }
}

fn sidecar_primary_site(value: Option<&Value>) -> String {
    let Some(Value::Array(sites)) = value else {
        return String::new();
    };
    sites
        .iter()
        .filter_map(Value::as_dictionary)
        .find_map(|site| {
            let value = sidecar_text(site.get("s"));
            if value.is_empty() {
                None
            } else {
                let normalized = normalize_host(&value);
                Some(if normalized.is_empty() {
                    value
                } else {
                    normalized
                })
            }
        })
        .unwrap_or_default()
}

pub fn totp_uri_from_sidecar(value: Option<&Value>) -> String {
    let Some(Value::Dictionary(block)) = value else {
        return String::new();
    };
    let Some(Value::Data(secret)) = block.get("secret") else {
        return String::new();
    };
    if secret.is_empty() {
        return String::new();
    }
    let issuer = sidecar_text(block.get("issuer"));
    let account = sidecar_text(block.get("accountName"));
    let label = match (issuer.is_empty(), account.is_empty()) {
        (false, false) => format!("{issuer}:{account}"),
        (false, true) => issuer.clone(),
        (true, false) => account,
        (true, true) => "icloud".into(),
    };
    let algorithm = block
        .get("algorithm")
        .and_then(|value| match value {
            Value::Integer(value) => value.as_unsigned(),
            _ => None,
        })
        .and_then(|value| match value {
            0 => Some("SHA1"),
            1 => Some("SHA256"),
            2 => Some("SHA512"),
            _ => None,
        })
        .unwrap_or("SHA1");
    let integer = |name: &str, default: u64| {
        block
            .get(name)
            .and_then(|value| match value {
                Value::Integer(value) => value.as_unsigned(),
                _ => None,
            })
            .unwrap_or(default)
    };
    let mut uri = match url::Url::parse("otpauth://totp/") {
        Ok(uri) => uri,
        Err(_) => return String::new(),
    };
    uri.set_path(&label);
    {
        let mut pairs = uri.query_pairs_mut();
        pairs.append_pair("secret", &BASE32_NOPAD.encode(secret));
        pairs.append_pair("algorithm", algorithm);
        pairs.append_pair("digits", &integer("digits", 6).to_string());
        pairs.append_pair("period", &integer("period", 30).to_string());
        if !issuer.is_empty() {
            pairs.append_pair("issuer", &issuer);
        }
    }
    uri.to_string()
}

pub fn from_items(items: &[DecryptedItem]) -> Projection {
    struct Login {
        id: String,
        key: (String, String),
        domain: String,
        username: String,
        password: String,
        title: String,
        modified_at: f64,
    }

    let mut logins = Vec::new();
    let mut sidecars: BTreeMap<(String, String), Dictionary> = BTreeMap::new();
    for item in items {
        let domain = text(&item.fields, &["srvr", "server", "domain", "url", "svce"]);
        let username = text(&item.fields, &["acct", "username", "user"]);
        let label = text(&item.fields, &["labl"]);
        let access_group = text(&item.fields, &["agrp"]);
        let key = (domain.to_ascii_lowercase(), username.to_ascii_lowercase());
        let mut kind = payload(&item.fields, &access_group);
        if label.to_ascii_lowercase().starts_with(SIDECAR_LABEL_PREFIX)
            && !matches!(kind, Payload::Sidecar(_))
        {
            kind = Payload::Sidecar(Dictionary::new());
        }
        match kind {
            Payload::Sidecar(mut values) => {
                if !domain.is_empty() || !username.is_empty() {
                    let sidecar = sidecars.entry(key).or_default();
                    for name in ["notes", "title", "ctxt", "totp", "s_as"] {
                        if let Some(value) = values.get(name) {
                            sidecar.insert(name.into(), value.clone());
                        }
                    }
                }
                zeroize_plist_dictionary(&mut values);
            }
            Payload::Password(password) => {
                let title = if label.is_empty() {
                    domain.clone()
                } else {
                    label
                };
                if (!domain.is_empty() || !username.is_empty())
                    && (!username.is_empty() || !password.is_empty())
                    && is_credential(&domain, &title)
                {
                    logins.push(Login {
                        id: item.record_id.clone(),
                        key,
                        domain,
                        username,
                        password,
                        title,
                        modified_at: to_unix(
                            item.fields.get("mdat").or_else(|| item.fields.get("cdat")),
                        ),
                    });
                }
            }
            _ => {}
        }
    }
    let credentials = logins
        .into_iter()
        .map(|login| {
            let sidecar = sidecars.get(&login.key);
            let sidecar_title = sidecar_text(sidecar.and_then(|value| value.get("title")));
            let sidecar_site = sidecar_primary_site(sidecar.and_then(|value| value.get("s_as")));
            Credential {
                id: login.id,
                domain: if sidecar_site.is_empty() {
                    login.domain
                } else {
                    sidecar_site
                },
                username: login.username,
                password: login.password,
                title: if sidecar_title.is_empty() {
                    login.title
                } else {
                    sidecar_title
                },
                modified_at: login.modified_at,
                notes: sidecar_text(sidecar.and_then(|value| value.get("notes"))),
                last_used: sidecar_last_used(sidecar.and_then(|value| value.get("ctxt"))),
                totp_uri: totp_uri_from_sidecar(sidecar.and_then(|value| value.get("totp"))),
            }
        })
        .collect();
    for sidecar in sidecars.values_mut() {
        zeroize_plist_dictionary(sidecar);
    }
    Projection {
        credentials,
        ignored_passkeys: items
            .iter()
            .filter(|item| text(&item.fields, &["agrp"]) == PASSKEY_ACCESS_GROUP)
            .count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, fields: Dictionary) -> DecryptedItem {
        DecryptedItem {
            record_id: id.into(),
            fields,
        }
    }

    fn bplist(value: Value) -> Vec<u8> {
        let mut data = Vec::new();
        value
            .to_writer_binary(&mut data)
            .unwrap_or_else(|error| panic!("plist: {error}"));
        data
    }

    #[test]
    fn matches_domains_on_label_boundaries() {
        assert!(domains_match("login.example.com", "example.com"));
        assert!(domains_match("https://www.example.com/path", "example.com"));
        assert!(!domains_match("notexample.com", "example.com"));
    }

    #[test]
    fn builds_totp_uri_from_structured_sidecar() {
        let mut block = Dictionary::new();
        block.insert(
            "secret".into(),
            Value::Data(b"12345678901234567890".to_vec()),
        );
        block.insert("issuer".into(), Value::String("Example".into()));
        block.insert("accountName".into(), Value::String("alice".into()));
        let uri = totp_uri_from_sidecar(Some(&Value::Dictionary(block)));
        assert!(uri.starts_with("otpauth://totp/Example:alice?"));
        assert!(uri.contains("algorithm=SHA1"));
    }

    #[test]
    fn sidecar_folds_into_login_and_drops_unapproved_fields() {
        let mut login = Dictionary::new();
        login.insert("agrp".into(), Value::String("com.apple.cfnetwork".into()));
        login.insert("srvr".into(), Value::String("ex.com".into()));
        login.insert("acct".into(), Value::String("a@b.c".into()));
        login.insert("v_Data".into(), Value::Data(b"hunter2".to_vec()));
        login.insert("labl".into(), Value::String("ex.com (a@b.c)".into()));
        login.insert("mdat".into(), Value::Real(1_600_000_000.0));

        let mut profile_one = Dictionary::new();
        profile_one.insert("lUsed".into(), Value::Real(700_000_000.0));
        let mut profile_two = Dictionary::new();
        profile_two.insert("lUsed".into(), Value::Real(750_000_000.0));
        let mut contexts = Dictionary::new();
        contexts.insert(String::new(), Value::Dictionary(profile_one));
        contexts.insert("Profile2".into(), Value::Dictionary(profile_two));
        let mut sidecar_payload = Dictionary::new();
        sidecar_payload.insert("notes".into(), Value::Data(b"my note".to_vec()));
        sidecar_payload.insert("title".into(), Value::Data(b"My Bank".to_vec()));
        sidecar_payload.insert("ctxt".into(), Value::Dictionary(contexts));
        sidecar_payload.insert(
            "s_as".into(),
            Value::Array(vec![Value::Dictionary(Dictionary::from_iter([(
                "s".to_owned(),
                Value::Data(b"https://www.example.com/login".to_vec()),
            )]))]),
        );
        sidecar_payload.insert("s_hi".into(), Value::String("old-password".into()));
        sidecar_payload.insert("supportsPasskey".into(), Value::Boolean(true));
        let mut sidecar = Dictionary::new();
        sidecar.insert(
            "agrp".into(),
            Value::String("com.apple.password-manager".into()),
        );
        sidecar.insert("srvr".into(), Value::String("ex.com".into()));
        sidecar.insert("acct".into(), Value::String("a@b.c".into()));
        sidecar.insert(
            "v_Data".into(),
            Value::Data(bplist(Value::Dictionary(sidecar_payload))),
        );

        let projection = from_items(&[item("login-id", login), item("sidecar-id", sidecar)]);
        let credentials = projection.credentials;
        assert_eq!(credentials.len(), 1);
        let credential = &credentials[0];
        assert_eq!(credential.password, "hunter2");
        assert_eq!(credential.domain, "example.com");
        assert_eq!(credential.notes, "my note");
        assert_eq!(credential.title, "My Bank");
        assert_eq!(credential.last_used, 750_000_000.0 + APPLE_EPOCH);
        let serialized =
            serde_json::to_string(credential).unwrap_or_else(|error| panic!("serialize: {error}"));
        assert!(!serialized.contains("old-password"));
        assert!(!serialized.contains("supportsPasskey"));
        assert!(!format!("{credential:?}").contains("hunter2"));
        assert!(!format!("{credential:?}").contains("my note"));
    }

    #[test]
    fn only_login_records_reach_the_vault() {
        let mut login = Dictionary::new();
        login.insert("agrp".into(), Value::String("com.apple.cfnetwork".into()));
        login.insert("srvr".into(), Value::String("ex.com".into()));
        login.insert("acct".into(), Value::String("alice".into()));
        login.insert("v_Data".into(), Value::Data(b"real".to_vec()));

        let mut passkey = Dictionary::new();
        passkey.insert(
            "agrp".into(),
            Value::String("com.apple.webkit.webauthn".into()),
        );
        passkey.insert("srvr".into(), Value::String("ex.com".into()));
        passkey.insert("acct".into(), Value::String("credential-id".into()));
        passkey.insert("v_Data".into(), Value::Data(vec![4, 0, 1]));

        let mut card_payload = Dictionary::new();
        card_payload.insert(
            "CardNumber".into(),
            Value::String("4111111111111111".into()),
        );
        let mut card = Dictionary::new();
        card.insert(
            "agrp".into(),
            Value::String("com.apple.safari.credit-cards".into()),
        );
        card.insert("srvr".into(), Value::String("cards".into()));
        card.insert("acct".into(), Value::String("alice".into()));
        card.insert(
            "v_Data".into(),
            Value::Data(bplist(Value::Dictionary(card_payload))),
        );

        let mut malformed_sidecar = Dictionary::new();
        malformed_sidecar.insert(
            "agrp".into(),
            Value::String("com.apple.password-manager".into()),
        );
        malformed_sidecar.insert("srvr".into(), Value::String("sidecar.test".into()));
        malformed_sidecar.insert("acct".into(), Value::String("not-a-login".into()));
        malformed_sidecar.insert("v_Data".into(), Value::Data(b"plain text".to_vec()));

        let projection = from_items(&[
            item("login", login),
            item("passkey", passkey),
            item("card", card),
            item("malformed-sidecar", malformed_sidecar),
        ]);
        let credentials = projection.credentials;
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].password, "real");
        assert_eq!(projection.ignored_passkeys, 1);
    }
}
