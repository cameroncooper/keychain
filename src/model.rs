use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::security::KeyRef;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub schema_version: u32,
    pub device_id: String,
    pub serial: String,
    pub local_user_uuid: String,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MobileMeState {
    pub dsid: String,
    pub auth_token: String,
    pub cloudkit_user_id: Option<String>,
    pub tokens: BTreeMap<String, String>,
    pub minted_at: i64,
}

impl fmt::Debug for MobileMeState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MobileMeState")
            .field("dsid", &self.dsid)
            .field("auth_token", &"[REDACTED]")
            .field("cloudkit_user_id", &self.cloudkit_user_id)
            .field("token_names", &self.tokens.keys().collect::<Vec<_>>())
            .field("minted_at", &self.minted_at)
            .finish()
    }
}

impl Drop for MobileMeState {
    fn drop(&mut self) {
        self.auth_token.zeroize();
        for token in self.tokens.values_mut() {
            token.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountState {
    pub schema_version: u32,
    pub username: String,
    pub adsid: String,
    pub logged_in_at: i64,
    pub mobileme: MobileMeState,
    pub webservices: BTreeMap<String, String>,
}

impl fmt::Debug for AccountState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountState")
            .field("schema_version", &self.schema_version)
            .field("username", &self.username)
            .field("adsid", &self.adsid)
            .field("logged_in_at", &self.logged_in_at)
            .field("mobileme", &self.mobileme)
            .field(
                "webservice_names",
                &self.webservices.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedInfoState {
    pub data_b64: String,
    pub signature_b64: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "phase", rename_all = "kebab-case")]
pub enum OctagonTrustState {
    IdentityReady,
    SponsorRecovered {
        peer_id: String,
        escrow_record_label: String,
        signing_key: KeyRef,
        encryption_key: KeyRef,
    },
    JoinedAwaitingTlkVerification {
        sponsor_peer_id: String,
        escrow_record_label: String,
        sponsor_encryption_key: KeyRef,
    },
    JoinedSponsorRetirementVerified {
        sponsor_peer_id: String,
        escrow_record_label: String,
        sponsor_encryption_key: KeyRef,
    },
    Joined,
}

impl OctagonTrustState {
    pub fn is_joined(&self) -> bool {
        matches!(
            self,
            Self::JoinedAwaitingTlkVerification { .. }
                | Self::JoinedSponsorRetirementVerified { .. }
                | Self::Joined
        )
    }

    pub fn escrow_record_label(&self) -> Option<&str> {
        match self {
            Self::SponsorRecovered {
                escrow_record_label,
                ..
            }
            | Self::JoinedAwaitingTlkVerification {
                escrow_record_label,
                ..
            }
            | Self::JoinedSponsorRetirementVerified {
                escrow_record_label,
                ..
            } => Some(escrow_record_label),
            Self::IdentityReady | Self::Joined => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OctagonState {
    pub schema_version: u32,
    pub account_fingerprint: String,
    pub peer_id: String,
    pub signing_key: KeyRef,
    pub encryption_key: KeyRef,
    pub permanent: SignedInfoState,
    pub trust_state: OctagonTrustState,
    pub created_at: i64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct Credential {
    pub id: String,
    pub domain: String,
    pub username: String,
    pub password: String,
    pub title: String,
    pub modified_at: f64,
    pub notes: String,
    pub last_used: f64,
    pub totp_uri: String,
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Credential")
            .field("id", &self.id)
            .field("domain", &self.domain)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("title", &self.title)
            .field("modified_at", &self.modified_at)
            .field("notes", &"[REDACTED]")
            .field("last_used", &self.last_used)
            .field("totp", &(!self.totp_uri.is_empty()))
            .finish()
    }
}

impl Credential {
    pub fn recency(&self) -> f64 {
        if self.last_used > 0.0 {
            self.last_used
        } else {
            self.modified_at
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct VaultState {
    pub schema_version: u32,
    pub synced_at: i64,
    pub credentials: Vec<Credential>,
}

impl fmt::Debug for VaultState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultState")
            .field("schema_version", &self.schema_version)
            .field("synced_at", &self.synced_at)
            .field("credential_count", &self.credentials.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octagon_trust_state_has_one_explicit_phase() {
        let state = OctagonTrustState::JoinedAwaitingTlkVerification {
            sponsor_peer_id: "sponsor".into(),
            escrow_record_label: "com.apple.icdp.record.sponsor".into(),
            sponsor_encryption_key: KeyRef {
                backend_id: "software-file-v1".into(),
                key_id: "key".into(),
                usage: crate::security::KeyUsage::Agreement,
            },
        };
        let encoded = serde_json::to_value(&state)
            .unwrap_or_else(|error| panic!("encode trust state: {error}"));
        assert_eq!(
            encoded.get("phase").and_then(serde_json::Value::as_str),
            Some("joined-awaiting-tlk-verification")
        );
        assert!(state.is_joined());
        assert_eq!(
            state.escrow_record_label(),
            Some("com.apple.icdp.record.sponsor")
        );
    }

    #[test]
    fn pre_cleanup_octagon_shape_is_rejected() {
        let old = r#"{"joined":true,"sponsor":null}"#;
        assert!(serde_json::from_str::<OctagonTrustState>(old).is_err());
    }
}
