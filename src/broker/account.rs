//! Explicit root-administrator enrollment of an existing account identity.
//! Never deserialize this package through an owner/browser broker operation.
//! Account roots remain software protected here; SEP root unsealing is separate.
use base64::{Engine, engine::general_purpose::STANDARD};
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::{
    SecretKey,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::{DecodePublicKey, EncodePublicKey},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

use crate::apple::cloudkit::DeviceConfig;
use crate::apple::octagon_keys::{PERMANENT_INFO_SIG_TYPE, prefixed_data, tphash_sha256};
use crate::apple::worker::AccountScope;
use crate::model::{
    AccountState, DeviceIdentity, OctagonState, OctagonTrustState, SignedInfoState,
};
use crate::proto::{Value, decode_fields};
use crate::security::{KeyAlgorithm, KeyRef, KeyUsage, Purpose, SecurityBackend};
use crate::{Error, Result};

pub const MAX_BOOTSTRAP: usize = 64 * 1024;

/// Read-only diagnostic result; contains no item values or authorization grant.
#[derive(Serialize)]
pub struct AccountCheck {
    pub owner: u32,
    pub account_fingerprint: String,
    pub zone: String,
    pub records: usize,
    pub authenticated_roots: usize,
    pub current_class_a_resolved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_record: Option<crate::apple::ckks::upload::NewRecordReview>,
}

fn invalid(message: &str) -> Error {
    Error::Security(format!("broker account: {message}"))
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSettings {
    pub uid: u32,
    pub socket: PathBuf,
}
impl WorkerSettings {
    fn validate(&self, owner: u32) -> Result<()> {
        if self.uid == 0
            || self.uid == owner
            || !self.socket.is_absolute()
            || self.socket.as_os_str().len() > 107
            || self.socket.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(invalid(
                "worker must use a dedicated UID and absolute trusted socket",
            ));
        }
        Ok(())
    }
}

/// Private agreement scalar only: no signing private key, token, ADI or vault.
/// Plaintext can travel only through an explicitly invoked administrator pipe.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    version: u32,
    scope: AccountScope,
    device: DeviceIdentity,
    permanent: SignedInfoState,
    agreement_x963: String,
}
impl Drop for Bootstrap {
    fn drop(&mut self) {
        self.agreement_x963.zeroize();
    }
}

struct PermanentKeys {
    signing_spki: Vec<u8>,
    agreement_spki: Vec<u8>,
}
fn permanent_keys(peer_id: &str, permanent: &SignedInfoState) -> Result<PermanentKeys> {
    if permanent.data_b64.len() > 24 * 1024 || permanent.signature_b64.len() > 256 {
        return Err(invalid("permanent peer info exceeds limit"));
    }
    let data = STANDARD
        .decode(&permanent.data_b64)
        .map_err(|_| invalid("invalid permanent peer encoding"))?;
    let signature = STANDARD
        .decode(&permanent.signature_b64)
        .map_err(|_| invalid("invalid peer signature encoding"))?;
    let mut hash_input = data.clone();
    hash_input.extend_from_slice(&signature);
    if tphash_sha256(&hash_input) != peer_id {
        return Err(invalid("peer ID does not match signed permanent info"));
    }
    let fields = decode_fields(&data)?;
    let key = |field| -> Result<Vec<u8>> {
        match fields.get(&field).map(Vec::as_slice) {
            Some([Value::Bytes(bytes)]) if !bytes.is_empty() && bytes.len() <= 256 => {
                Ok(bytes.clone())
            }
            _ => Err(invalid("missing or ambiguous permanent public key")),
        }
    };
    let signing_spki = key(2)?;
    let agreement_spki = key(3)?;
    let verify = VerifyingKey::from_public_key_der(&signing_spki)
        .map_err(|_| invalid("invalid permanent signing public key"))?;
    p384::PublicKey::from_public_key_der(&agreement_spki)
        .map_err(|_| invalid("invalid permanent agreement public key"))?;
    let signature =
        Signature::from_der(&signature).map_err(|_| invalid("invalid permanent signature"))?;
    verify
        .verify(&prefixed_data(PERMANENT_INFO_SIG_TYPE, &data), &signature)
        .map_err(|_| invalid("permanent signature did not verify"))?;
    Ok(PermanentKeys {
        signing_spki,
        agreement_spki,
    })
}
fn validate_device(device: &DeviceIdentity) -> Result<()> {
    if device.schema_version != 1
        || uuid::Uuid::parse_str(&device.device_id).is_err()
        || uuid::Uuid::parse_str(&device.local_user_uuid).is_err()
        || device.serial.is_empty()
        || device.serial.len() > 128
        || device.serial.chars().any(char::is_control)
    {
        return Err(invalid("invalid frozen device identity"));
    }
    Ok(())
}
impl Bootstrap {
    pub(crate) fn from_private(
        owner: u32,
        account: &AccountState,
        device: &DeviceIdentity,
        peer: &OctagonState,
        signing_spki: &[u8],
        private: &[u8],
    ) -> Result<Self> {
        if private.len() != 145 || private.first() != Some(&4) {
            return Err(invalid("invalid agreement private key size"));
        }
        if account.schema_version != 1
            || peer.schema_version != 1
            || !matches!(peer.trust_state, OctagonTrustState::Joined)
            || peer.account_fingerprint != crate::apple::octagon::account_fingerprint(account)
        {
            return Err(invalid(
                "bootstrap requires the existing matching joined peer",
            ));
        }
        let scope = AccountScope {
            owner,
            account_fingerprint: peer.account_fingerprint.clone(),
            peer_id: peer.peer_id.clone(),
            zone: crate::apple::ckks::ZoneIdentity {
                name: "Passwords".into(),
                owner: account
                    .mobileme
                    .cloudkit_user_id
                    .clone()
                    .ok_or_else(|| invalid("CloudKit user is missing"))?,
            },
        };
        let value = Self {
            version: 1,
            scope,
            device: device.clone(),
            permanent: peer.permanent.clone(),
            agreement_x963: STANDARD.encode(private),
        };
        let keys = value.validate()?;
        if keys.signing_spki != signing_spki {
            return Err(invalid(
                "stored signing key differs from the signed peer identity",
            ));
        }
        Ok(value)
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        Ok(Zeroizing::new(serde_json::to_vec(self)?))
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BOOTSTRAP {
            return Err(invalid("bootstrap package exceeds limit"));
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| invalid("invalid bootstrap package"))?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<PermanentKeys> {
        if self.version != 1 || self.agreement_x963.len() != 196 {
            return Err(invalid(
                "invalid bootstrap version or agreement encoding length",
            ));
        }
        self.scope.validate()?;
        validate_device(&self.device)?;
        let keys = permanent_keys(&self.scope.peer_id, &self.permanent)?;
        let private = Zeroizing::new(
            STANDARD
                .decode(&self.agreement_x963)
                .map_err(|_| invalid("invalid agreement key encoding"))?,
        );
        if private.len() != 145 || private[0] != 4 {
            return Err(invalid("invalid agreement X9.63 shape"));
        }
        let secret = SecretKey::from_slice(&private[97..])
            .map_err(|_| invalid("invalid agreement scalar"))?;
        let public = secret.public_key();
        if public.to_encoded_point(false).as_bytes() != &private[..97]
            || public
                .to_public_key_der()
                .map_err(|_| invalid("agreement SPKI encoding"))?
                .as_bytes()
                != keys.agreement_spki
        {
            return Err(invalid(
                "agreement scalar differs from signed permanent public key",
            ));
        }
        Ok(keys)
    }
}

/// Root-controlled, encrypted account metadata. No Deserialize implementation
/// on this authority type: only Registry can construct it after validation.
pub struct Account {
    record: AccountRecord,
    signing_spki: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountRecord {
    version: u32,
    scope: AccountScope,
    device: DeviceIdentity,
    permanent: SignedInfoState,
    agreement: KeyRef,
    worker: WorkerSettings,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentIntent {
    version: u32,
    owner: u32,
    fingerprint: String,
}
fn enrollment_fingerprint(
    scope: &AccountScope,
    device: &DeviceIdentity,
    permanent: &SignedInfoState,
    worker: &WorkerSettings,
) -> Result<String> {
    Ok(tphash_sha256(&serde_json::to_vec(&(
        scope, device, permanent, worker,
    ))?))
}
impl Account {
    pub fn scope(&self) -> &AccountScope {
        &self.record.scope
    }
    pub fn device(&self) -> DeviceConfig {
        (&self.record.device).into()
    }
    pub fn worker(&self) -> &WorkerSettings {
        &self.record.worker
    }
    pub(crate) fn agreement(&self) -> &KeyRef {
        &self.record.agreement
    }
    pub(crate) fn signing_spki(&self) -> &[u8] {
        &self.signing_spki
    }
    pub(crate) fn authenticate_roots(
        &self,
        backend: &dyn SecurityBackend,
        recovered: &[crate::apple::ckks::Record],
        live: &[crate::apple::ckks::Record],
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Vec<crate::apple::pipeline::RecoveredTlk>> {
        check()?;
        if recovered.len() + live.len() > 8192 {
            return Err(invalid("share count exceeds limit"));
        }
        let recipient = backend.public_x963(self.agreement())?;
        check()?;
        let mut roots =
            std::collections::BTreeMap::<String, crate::apple::pipeline::RecoveredTlk>::new();
        for share in recovered.iter().chain(live) {
            check()?;
            if share.record_type != "tlkshare" {
                return Err(invalid("share result contains another record type"));
            }
            let materials = crate::apple::pipeline::unwrap_authenticated_tlkshares(
                std::slice::from_ref(share),
                &self.scope().peer_id,
                &self.scope().peer_id,
                self.signing_spki(),
                backend,
                self.agreement(),
                &recipient,
            )?;
            check()?;
            for material in materials {
                if material.zone_name != self.scope().zone.name {
                    continue;
                }
                if material.keyclass != "tlk" {
                    return Err(invalid("share does not contain a zone TLK"));
                }
                if let Some(existing) = roots.get(&material.uuid) {
                    if existing.key != material.key {
                        return Err(invalid("conflicting authenticated recoverable/live roots"));
                    }
                } else {
                    roots.insert(material.uuid.clone(), material);
                }
            }
        }
        if roots.is_empty() {
            return Err(invalid(
                "no authenticated self-share for the Passwords zone",
            ));
        }
        Ok(roots.into_values().collect())
    }
}

impl super::registry::Registry {
    fn intent_path(&self, owner: u32) -> PathBuf {
        self.directory.join(format!("account-{owner}-intent.enc"))
    }
    fn check_account_intent(&self, owner: u32, fingerprint: &str) -> Result<()> {
        let encrypted = crate::paths::read_bounded(&self.intent_path(owner))?;
        let plaintext = self.backend.open(Purpose::BrokerAccount, &encrypted)?;
        if plaintext.len() > MAX_BOOTSTRAP {
            return Err(invalid("account intent exceeds limit"));
        }
        let intent: EnrollmentIntent =
            serde_json::from_slice(&plaintext).map_err(|_| invalid("invalid account intent"))?;
        if intent.version != 1 || intent.owner != owner || intent.fingerprint != fingerprint {
            return Err(invalid("account enrollment differs from frozen intent"));
        }
        Ok(())
    }
    /// Trusted coordinator seam: account metadata and unwrap key are loaded from
    /// this registry, not supplied by an ordinary owner client or network worker.
    pub fn account_upload_io<'a>(
        &self,
        owner: u32,
        client: crate::apple::worker::WorkerClient<'a>,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<crate::apple::worker::WorkerUploadIo<'a>> {
        let account = self.load_account(owner)?;
        crate::apple::worker::WorkerUploadIo::for_account(client, &account, &self.backend, check)
    }
    /// Administrator-only preflight against an already running enrolled worker.
    /// Does not start services, create keys, capture biometrics or save records.
    pub fn check_account(
        &self,
        owner: u32,
        deadline: std::time::Instant,
        new_record: Option<uuid::Uuid>,
    ) -> Result<AccountCheck> {
        use crate::apple::ckks::upload::{Binding, UploadIo};
        use sha2::{Digest, Sha256};
        if keychain_sep_driver::peer::effective_uid() != 0 {
            return Err(invalid("account check requires root"));
        }
        let check = || {
            if std::time::Instant::now() >= deadline {
                return Err(crate::security::sep::ProviderError::Expired.into());
            }
            Ok(())
        };
        check()?;
        if new_record.is_some_and(|id| id.get_version_num() != 4) {
            return Err(invalid("proposed record UUID must be v4"));
        }
        let account = self.load_account(owner)?;
        let scope = account.scope();
        let binding = Binding {
            owner,
            account_fingerprint: scope.account_fingerprint.clone(),
            peer_id: scope.peer_id.clone(),
            zone: scope.zone.clone(),
            transaction: uuid::Uuid::new_v4(),
            request_sha256: hex::encode(Sha256::digest(
                [
                    b"keychain/read-only-account-check/v1\0".as_slice(),
                    &serde_json::to_vec(scope)?,
                ]
                .concat(),
            )),
        };
        let client = crate::apple::worker::WorkerClient::connect(
            &account.worker().socket,
            account.worker().uid,
            binding,
            deadline,
            &check,
            &check,
        )?;
        let mut io = self.account_upload_io(owner, client, &check)?;
        let snapshot = io.fetch_zone(&scope.zone, &check)?;
        let (records, authenticated_roots) = snapshot.readiness_counts()?;
        let proposed_record = new_record
            .map(|id| snapshot.review_new_record(id))
            .transpose()?;
        check()?;
        Ok(AccountCheck {
            owner,
            account_fingerprint: scope.account_fingerprint.clone(),
            zone: scope.zone.name.clone(),
            records,
            authenticated_roots,
            current_class_a_resolved: true,
            proposed_record,
        })
    }
    fn account_path(&self, owner: u32) -> PathBuf {
        self.directory.join(format!("account-{owner}.enc"))
    }
    pub fn load_account(&self, owner: u32) -> Result<Account> {
        if owner == 0 {
            return Err(invalid("invalid account owner"));
        }
        let bytes = crate::paths::read_bounded(&self.account_path(owner))?;
        let plaintext = self.backend.open(Purpose::BrokerAccount, &bytes)?;
        if plaintext.len() > MAX_BOOTSTRAP {
            return Err(invalid("account metadata exceeds limit"));
        }
        let record: AccountRecord =
            serde_json::from_slice(&plaintext).map_err(|_| invalid("invalid account metadata"))?;
        if record.version != 1
            || record.scope.owner != owner
            || record.agreement.backend_id != self.backend.backend_id()
            || record.agreement.algorithm != KeyAlgorithm::P384
            || record.agreement.usage != KeyUsage::Agreement
        {
            return Err(invalid("account owner or key policy mismatch"));
        }
        record.scope.validate()?;
        validate_device(&record.device)?;
        record.worker.validate(owner)?;
        let keys = permanent_keys(&record.scope.peer_id, &record.permanent)?;
        if self.backend.public_spki(&record.agreement)? != keys.agreement_spki {
            return Err(invalid(
                "stored agreement key no longer matches permanent identity",
            ));
        }
        self.check_account_intent(
            owner,
            &enrollment_fingerprint(
                &record.scope,
                &record.device,
                &record.permanent,
                &record.worker,
            )?,
        )?;
        Ok(Account {
            record,
            signing_spki: keys.signing_spki,
        })
    }
    pub(super) fn optional_account(&self, owner: u32) -> Result<Option<Account>> {
        if owner == 0 {
            return Err(invalid("invalid account owner"));
        }
        let path = self.account_path(owner);
        if !path.try_exists().map_err(|e| Error::io(&path, e))? {
            return Ok(None);
        }
        self.load_account(owner).map(Some)
    }
    /// Root administrator CLI only, never an owner socket operation. A retry
    /// cannot replace the pinned account, identity, device or worker selection.
    pub fn enroll_account(
        &self,
        owner: u32,
        input: &Bootstrap,
        worker: WorkerSettings,
    ) -> Result<Account> {
        if keychain_sep_driver::peer::effective_uid() != 0 || input.scope.owner != owner {
            return Err(invalid(
                "account enrollment requires root and the exact owner",
            ));
        }
        let _lock = self.update_lock()?;
        input.validate()?;
        worker.validate(owner)?;
        let path = self.account_path(owner);
        let fingerprint =
            enrollment_fingerprint(&input.scope, &input.device, &input.permanent, &worker)?;
        let intent_path = self.intent_path(owner);
        if intent_path
            .try_exists()
            .map_err(|e| Error::io(&intent_path, e))?
        {
            self.check_account_intent(owner, &fingerprint)?;
        } else {
            if path.try_exists().map_err(|e| Error::io(&path, e))? {
                return Err(invalid(
                    "committed account intent is missing; refusing replacement",
                ));
            }
            // Freeze account/peer/device/worker before importing private data.
            let intent = EnrollmentIntent {
                version: 1,
                owner,
                fingerprint,
            };
            let plaintext = Zeroizing::new(serde_json::to_vec(&intent)?);
            crate::paths::atomic_write_private(
                &intent_path,
                &self.backend.seal(Purpose::BrokerAccount, &plaintext)?,
            )?;
        }
        if path.try_exists().map_err(|e| Error::io(&path, e))? {
            let current = self.load_account(owner)?;
            if current.record.scope != input.scope
                || current.record.device != input.device
                || current.record.permanent != input.permanent
                || current.record.worker != worker
            {
                return Err(invalid(
                    "different account enrollment already exists; refusing replacement",
                ));
            }
            return Ok(current);
        }
        let private = Zeroizing::new(
            STANDARD
                .decode(&input.agreement_x963)
                .map_err(|_| invalid("invalid agreement encoding"))?,
        );
        let agreement = self
            .backend
            .import_p384_x963(KeyUsage::Agreement, &private)?;
        let record = AccountRecord {
            version: 1,
            scope: input.scope.clone(),
            device: input.device.clone(),
            permanent: input.permanent.clone(),
            agreement,
            worker,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&record)?);
        let encrypted = self.backend.seal(Purpose::BrokerAccount, &plaintext)?;
        crate::paths::atomic_write_private(&path, &encrypted)?;
        self.load_account(owner)
    }
}

#[cfg(test)]
mod tests;
