//! Account-scoped worker startup. Credentials are delivered by systemd from a
//! root-controlled encrypted package, never taken from an owner's browser RPC.
use super::*;
use crate::apple::{anisette::ManagedAnisette, cloudkit::CloudKitTransport};
use crate::model::{AccountState, DeviceIdentity, MobileMeState, OctagonState, OctagonTrustState};
use crate::paths::{AppPaths, StateLock, create_private_exclusive};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::os::unix::{
    fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
    net::UnixListener,
};
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_CREDENTIAL: usize = 6 * 1024 * 1024;
const COREADI_SHA256: &str = "2eafc3c79c7f41a8afbfbeaaf23ee5dab5ad5bda55ec8e54dbc0ddf1d20ce630";

/// Contains only the CloudKit token and local ADI seed, with public scope.
/// Intentionally no Debug, password/PET, Octagon key reference, TLK or vault.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    version: u32,
    owner: u32,
    adsid: String,
    peer_id: String,
    device: DeviceIdentity,
    cloudkit_user_id: String,
    cloudkit_token: String,
    anisette_seed: String,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.cloudkit_token.zeroize();
        self.anisette_seed.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdiSeed {
    version: u32,
    phase: String,
    machine_json: String,
}
impl Drop for AdiSeed {
    fn drop(&mut self) {
        self.machine_json.zeroize();
    }
}

#[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct MachineIdentity {
    version: u32,
    host_uuid: String,
    identity: MachineIdentifiers,
}
#[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct MachineIdentifiers {
    device_id: String,
    local_user_uuid: String,
}

// Interoperability fields from the pinned helper's JSON format. The mutable
// store is deliberately excluded: OTP/resync must not turn token rotation into
// identity replacement. No GPL emulator implementation is linked or copied.
fn seed_identity(seed: &[u8]) -> Result<String> {
    if seed.len() > 4 * 1024 * 1024 {
        return Err(invalid("ADI seed exceeds limit"));
    }
    let state: AdiSeed = serde_json::from_slice(seed).map_err(|_| invalid("invalid ADI seed"))?;
    if state.version != 1 || state.phase != "ready" {
        return Err(invalid("ADI seed is not already provisioned"));
    }
    let machine: MachineIdentity = serde_json::from_str(&state.machine_json)
        .map_err(|_| invalid("invalid ADI machine identity"))?;
    let host = Zeroizing::new(
        hex::decode(&machine.host_uuid).map_err(|_| invalid("invalid ADI host identity"))?,
    );
    let device = adi_device_identity(&machine.identity.device_id)?;
    let local = Uuid::parse_str(&machine.identity.local_user_uuid)
        .map_err(|_| invalid("invalid ADI local identity"))?;
    if machine.version != 1 || host.len() != 16 || local.is_nil() {
        return Err(invalid("invalid ADI identity"));
    }
    let mut hash = Sha256::new();
    hash.update(b"keychain/network-worker/adi-identity/v1");
    hash.update(host.as_slice());
    hash.update(device.as_slice());
    hash.update(local.as_bytes());
    Ok(hex::encode(hash.finalize()))
}

/// ADI provisioning IDs are distinct from the app's CloudKit UUID. The pinned
/// helper supports UUID identities and macOS UDIDs (8 hex digits, '-', 16 hex).
/// Retain the existing UUID digest input, and give UDIDs a distinct typed prefix.
fn adi_device_identity(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(uuid) = Uuid::parse_str(value) {
        if uuid.is_nil() {
            return Err(invalid("invalid ADI device identity"));
        }
        return Ok(Zeroizing::new(uuid.as_bytes().to_vec()));
    }
    if value.len() != 25 || !value.is_ascii() || value.as_bytes()[8] != b'-' {
        return Err(invalid("invalid ADI device identity"));
    }
    let mut udid = Zeroizing::new([0u8; 12]);
    hex::decode_to_slice(&value[..8], &mut udid[..4])
        .map_err(|_| invalid("invalid ADI device identity"))?;
    hex::decode_to_slice(&value[9..], &mut udid[4..])
        .map_err(|_| invalid("invalid ADI device identity"))?;
    if udid.iter().all(|byte| *byte == 0) {
        return Err(invalid("invalid ADI device identity"));
    }
    let mut tagged = Zeroizing::new(Vec::with_capacity(17));
    tagged.extend_from_slice(b"udid:");
    tagged.extend_from_slice(udid.as_slice());
    Ok(tagged)
}

impl Credentials {
    pub fn from_account(
        owner: u32,
        account: &AccountState,
        device: &DeviceIdentity,
        peer: &OctagonState,
        adi_state: &[u8],
    ) -> Result<Self> {
        if adi_state.len() > 4 * 1024 * 1024 {
            return Err(invalid("ADI seed exceeds limit"));
        }
        if account.schema_version != 1
            || peer.schema_version != 1
            || peer.account_fingerprint != crate::apple::octagon::account_fingerprint(account)
            || !matches!(peer.trust_state, OctagonTrustState::Joined)
        {
            return Err(invalid(
                "credential export requires the matching joined peer",
            ));
        }
        let value = Self {
            version: 1,
            owner,
            adsid: account.adsid.clone(),
            peer_id: peer.peer_id.clone(),
            device: device.clone(),
            cloudkit_user_id: account
                .mobileme
                .cloudkit_user_id
                .clone()
                .ok_or_else(|| invalid("missing CloudKit user"))?,
            cloudkit_token: account
                .mobileme
                .tokens
                .get("cloudKitToken")
                .cloned()
                .ok_or_else(|| invalid("missing CloudKit token"))?,
            anisette_seed: STANDARD.encode(adi_state),
        };
        value.validate()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let bytes = Zeroizing::new(serde_json::to_vec(self)?);
        if bytes.len() > MAX_CREDENTIAL {
            return Err(invalid("worker credential exceeds limit"));
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CREDENTIAL {
            return Err(invalid("worker credential exceeds limit"));
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| invalid("invalid worker credential"))?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        let text = |value: &str, max: usize| {
            !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
        };
        if self.version != 1
            || self.owner == 0
            || !text(&self.adsid, 256)
            || !text(&self.cloudkit_user_id, 512)
            || !text(&self.cloudkit_token, 65536)
            || self.device.schema_version != 1
            || !text(&self.device.serial, 128)
            || Uuid::parse_str(&self.device.device_id).is_err()
            || Uuid::parse_str(&self.device.local_user_uuid).is_err()
            || !self
                .peer_id
                .strip_prefix("SHA256:")
                .and_then(|value| STANDARD.decode(value).ok())
                .is_some_and(|value| value.len() == 32)
        {
            return Err(invalid("worker credential scope is invalid"));
        }
        let _ = self.seed()?;
        Ok(())
    }
    fn seed(&self) -> Result<Zeroizing<Vec<u8>>> {
        if self.anisette_seed.len() > 6 * 1024 * 1024 {
            return Err(invalid("ADI seed exceeds limit"));
        }
        let bytes = Zeroizing::new(
            STANDARD
                .decode(&self.anisette_seed)
                .map_err(|_| invalid("invalid ADI seed encoding"))?,
        );
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(invalid("ADI seed exceeds limit"));
        }
        seed_identity(&bytes)?;
        Ok(bytes)
    }
    fn account(&self) -> AccountState {
        AccountState {
            schema_version: 1,
            username: String::new(),
            adsid: self.adsid.clone(),
            logged_in_at: 0,
            mobileme: MobileMeState {
                dsid: String::new(),
                auth_token: String::new(),
                minted_at: 0,
                cloudkit_user_id: Some(self.cloudkit_user_id.clone()),
                tokens: BTreeMap::from([("cloudKitToken".into(), self.cloudkit_token.clone())]),
            },
            webservices: BTreeMap::new(),
        }
    }
    pub fn scope(&self) -> AccountScope {
        AccountScope {
            owner: self.owner,
            account_fingerprint: crate::apple::octagon_keys::tphash_sha256(self.adsid.as_bytes()),
            peer_id: self.peer_id.clone(),
            zone: ZoneIdentity {
                name: "Passwords".into(),
                owner: self.cloudkit_user_id.clone(),
            },
        }
    }
}

/// Check every ancestor before opening a service credential/executable. Service
/// account files and root-owned systemd credential mounts are readable here;
/// neither the paired owner nor the worker may rewrite this input hierarchy.
pub fn trusted_file(path: &Path, maximum: usize) -> Result<File> {
    if !path.is_absolute() {
        return Err(invalid("trusted service path must be absolute"));
    }
    for ancestor in path.ancestors().skip(1) {
        let meta = fs::symlink_metadata(ancestor).map_err(|e| Error::io(ancestor, e))?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(invalid("service path has an untrusted ancestor"));
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| Error::io(path, e))?;
    let meta = file.metadata().map_err(|e| Error::io(path, e))?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.len() > maximum as u64
    {
        return Err(invalid(
            "service file ownership, permissions or size is unsafe",
        ));
    }
    Ok(file)
}
pub fn load_credentials(directory: &Path) -> Result<Credentials> {
    let path = directory.join("network-account");
    let file = trusted_file(&path, MAX_CREDENTIAL)?;
    if file.metadata().map_err(|e| Error::io(&path, e))?.mode() & 0o007 != 0 {
        return Err(invalid("service credential is world accessible"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_CREDENTIAL as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(&path, e))?;
    Credentials::decode(&bytes)
}

/// Seed a NEW private profile by atomic directory rename. An existing profile
/// with a different stable identity is never reset or silently replaced.
fn seed_anisette(paths: &AppPaths, seed: &[u8]) -> Result<()> {
    let parent = paths.anisette_dir();
    fs::create_dir_all(&parent).map_err(|e| Error::io(&parent, e))?;
    let meta = fs::symlink_metadata(&parent).map_err(|e| Error::io(&parent, e))?;
    if !meta.is_dir() || meta.uid() != keychain_sep_driver::peer::effective_uid() {
        return Err(invalid("unsafe private anisette directory"));
    }
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(&parent, e))?;
    let target = parent.join("macos");
    let digest = seed_identity(seed)?;
    let existing = match fs::symlink_metadata(&target) {
        Ok(meta) => Some(meta),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(Error::io(&target, e)),
    };
    if let Some(meta) = existing {
        if !meta.is_dir()
            || meta.uid() != keychain_sep_driver::peer::effective_uid()
            || meta.mode() & 0o077 != 0
        {
            return Err(invalid("unsafe anisette profile"));
        }
        let marker = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(target.join("identity.sha256"))
            .map_err(|e| Error::io(&target, e))?;
        let meta = marker.metadata().map_err(|e| Error::io(&target, e))?;
        if !meta.is_file()
            || meta.len() != 64
            || meta.uid() != keychain_sep_driver::peer::effective_uid()
            || meta.mode() & 0o077 != 0
        {
            return Err(invalid("unsafe anisette seed marker"));
        }
        let mut bytes = Vec::new();
        marker
            .take(65)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::io(&target, e))?;
        if bytes != digest.as_bytes() {
            return Err(invalid("ADI seed changed; existing identity retained"));
        }
        let machine = fs::symlink_metadata(target.join("machine.json"))
            .map_err(|_| invalid("ADI machine is missing; refusing regeneration"))?;
        if !machine.is_file()
            || machine.uid() != keychain_sep_driver::peer::effective_uid()
            || machine.mode() & 0o077 != 0
        {
            return Err(invalid("ADI machine is unsafe; refusing replacement"));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(target.join("machine.json"))
            .map_err(|e| Error::io(&target, e))?;
        let mut current = Zeroizing::new(Vec::new());
        file.take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut current)
            .map_err(|e| Error::io(&target, e))?;
        if seed_identity(&current)? != digest {
            return Err(invalid("local ADI identity changed; refusing replacement"));
        }
        return Ok(());
    }
    let staging = parent.join(format!(".seed-{}", Uuid::new_v4()));
    fs::create_dir(&staging).map_err(|e| Error::io(&staging, e))?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(&staging, e))?;
    let result = (|| {
        create_private_exclusive(&staging.join("machine.json"), seed)?;
        create_private_exclusive(&staging.join("identity.sha256"), digest.as_bytes())?;
        fs::rename(&staging, &target).map_err(|e| Error::io(&target, e))?;
        File::open(&parent)
            .and_then(|file| file.sync_all())
            .map_err(|e| Error::io(&parent, e))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

pub struct ServiceConfig {
    pub credentials_directory: PathBuf,
    pub state_directory: PathBuf,
    pub runtime_directory: PathBuf,
    pub helper: PathBuf,
    pub coreadi: PathBuf,
    pub idle_timeout: Duration,
}
pub fn run(config: ServiceConfig) -> Result<()> {
    let uid = keychain_sep_driver::peer::effective_uid();
    if uid == 0 {
        return Err(invalid("network worker must use a dedicated nonroot UID"));
    }
    keychain_sep_driver::memory::make_process_nondumpable()
        .map_err(|e| Error::io("worker memory policy", e))?;
    let credentials = load_credentials(&config.credentials_directory)?;
    if credentials.owner == uid {
        return Err(invalid("network worker cannot run as the paired owner"));
    }
    if config.idle_timeout.is_zero() || config.idle_timeout > Duration::from_secs(86400) {
        return Err(invalid("invalid worker idle timeout"));
    }
    if trusted_file(&config.helper, 512 * 1024 * 1024)?
        .metadata()
        .map_err(|e| Error::io(&config.helper, e))?
        .mode()
        & 0o111
        == 0
    {
        return Err(invalid("helper is not executable"));
    }
    let mut image = Vec::new();
    trusted_file(&config.coreadi, 16 * 1024 * 1024)?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut image)
        .map_err(|e| Error::io(&config.coreadi, e))?;
    if hex::encode(Sha256::digest(&image)) != COREADI_SHA256 {
        return Err(invalid(
            "CoreADI image differs from the pinned local Mac provider",
        ));
    }
    let paths = AppPaths::new(
        config.state_directory.join("config"),
        config.state_directory.join("state"),
        config.runtime_directory.clone(),
    )?;
    let _lock = StateLock::acquire(&paths)?;
    seed_anisette(&paths, &credentials.seed()?)?;
    let scope = credentials.scope();
    let expected_device = credentials.device.clone();
    let expected_identity = seed_identity(&credentials.seed()?)?;
    // Wipe the primary token/seed buffers before spawning the external helper.
    // Re-read the immutable systemd credential after exec; never pass it to the
    // helper via arguments, environment, stdin or inherited credential handles.
    drop(credentials);
    let anisette =
        ManagedAnisette::start_with_image(&config.helper, &paths, Some(&config.coreadi))?;
    let credentials = load_credentials(&config.credentials_directory)?;
    if credentials.scope() != scope
        || credentials.device != expected_device
        || seed_identity(&credentials.seed()?)? != expected_identity
    {
        return Err(invalid("worker credentials changed during helper startup"));
    }
    let transport = CloudKitTransport::new(&credentials.account(), &credentials.device, &anisette)?;
    drop(credentials);
    let socket = config.runtime_directory.join("worker.sock");
    if socket.try_exists().map_err(|e| Error::io(&socket, e))? {
        let meta = fs::symlink_metadata(&socket).map_err(|e| Error::io(&socket, e))?;
        if !meta.file_type().is_socket() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
            return Err(invalid("unsafe stale worker socket"));
        }
        fs::remove_file(&socket).map_err(|e| Error::io(&socket, e))?;
    }
    let listener = UnixListener::bind(&socket).map_err(|e| Error::io(&socket, e))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::io(&socket, e))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::io(&socket, e))?;
    let mut idle = Instant::now();
    let result = loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // Never log account payloads or free-form errors. Fixed save
                // failure stages/numeric HTTP statuses contain no account data.
                // Failed/aborted attempts
                // are reconciled by the broker's durable journal, not replayed.
                let _ = serve_account(
                    stream,
                    &scope,
                    |binding| AppleUploadIo::for_worker(&transport, binding),
                    Instant::now() + Duration::from_secs(120),
                );
                idle = Instant::now();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if idle.elapsed() >= config.idle_timeout {
                    break Ok(());
                }
                std::thread::sleep(Duration::from_millis(40));
            }
            Err(e) => break Err(Error::io(&socket, e)),
        }
    };
    let _ = fs::remove_file(socket);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> Credentials {
        Credentials {
            version: 1,
            owner: 1001,
            adsid: "synthetic-adsid".into(),
            peer_id: format!("SHA256:{}", STANDARD.encode([2; 32])),
            device: DeviceIdentity {
                schema_version: 1,
                device_id: Uuid::new_v4().to_string(),
                local_user_uuid: Uuid::new_v4().to_string(),
                serial: "synthetic".into(),
            },
            cloudkit_user_id: "synthetic-owner".into(),
            cloudkit_token: "synthetic-cloudkit-token".into(),
            anisette_seed: STANDARD
                .encode(serde_json::json!({"version":1,"phase":"ready","machine_json":serde_json::json!({"version":1,"host_uuid":"01".repeat(16),"identity":{"device_id":"11111111-1111-4111-8111-111111111111","local_user_uuid":"22222222-2222-4222-8222-222222222222"},"store_export_b64":"synthetic-adi"}).to_string()}).to_string()),
        }
    }
    fn seed_with_device(device_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let mut seed: serde_json::Value = serde_json::from_slice(&credential().seed()?)?;
        let mut machine: serde_json::Value = serde_json::from_str(
            seed["machine_json"]
                .as_str()
                .ok_or_else(|| invalid("test machine"))?,
        )?;
        machine["identity"]["device_id"] = device_id.into();
        seed["machine_json"] = serde_json::to_string(&machine)?.into();
        Ok(Zeroizing::new(serde_json::to_vec(&seed)?))
    }
    #[test]
    fn existing_uuid_identity_marker_is_unchanged() -> Result<()> {
        assert_eq!(
            seed_identity(&credential().seed()?)?,
            "cc71aa6d8c35578bf1ab515d11529957fd9750417b1869730ae4a0a747de7a85"
        );
        Ok(())
    }
    #[test]
    fn adi_udid_is_not_a_cloudkit_uuid_and_preserves_credential_scope() -> Result<()> {
        let mut original = credential();
        let seed = seed_with_device("00006000-0A1B2C3D4E5F6071")?;
        original.anisette_seed = STANDARD.encode(seed.as_slice());
        let decoded = Credentials::decode(&original.encode()?)?;
        assert!(decoded.scope() == original.scope());
        assert_eq!(decoded.seed()?.as_slice(), seed.as_slice());
        assert_eq!(
            seed_identity(&seed)?,
            seed_identity(&seed_with_device("00006000-0a1b2c3d4e5f6071")?)?
        );
        // CloudKit-facing app scope still requires a UUID.
        original.device.device_id = "00006000-0A1B2C3D4E5F6071".into();
        assert!(original.validate().is_err());
        Ok(())
    }
    #[test]
    fn malformed_or_zero_adi_device_identifiers_are_refused() {
        for value in [
            "",
            "not-a-device",
            "00006000-0A1B2C3D4E5F607",
            "00006000-0A1B2C3D4E5F60712",
            "00006000_0A1B2C3D4E5F6071",
            "00006000-0A1B2C3D4E5F607Z",
            "00006000-0A1B2C3D4E5F607\n",
            "00000000-0000000000000000",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(
                adi_device_identity(value).is_err(),
                "accepted malformed synthetic identity"
            );
        }
    }
    #[test]
    fn changing_a_seeded_udid_never_replaces_the_worker_identity() -> Result<()> {
        let directory = tempfile::tempdir().map_err(|e| Error::io("test", e))?;
        let paths = AppPaths::for_test(directory.path())?;
        let original = seed_with_device("00006000-0A1B2C3D4E5F6071")?;
        let changed = seed_with_device("00006000-0A1B2C3D4E5F6072")?;
        assert_ne!(seed_identity(&original)?, seed_identity(&changed)?);
        seed_anisette(&paths, &original)?;
        assert!(seed_anisette(&paths, &changed).is_err());
        let saved = fs::read(paths.anisette_dir().join("macos/machine.json"))
            .map_err(|e| Error::io("test machine", e))?;
        assert_eq!(saved.as_slice(), original.as_slice());
        Ok(())
    }
    #[test]
    fn minimal_credential_roundtrip_rejects_unknown_fields_and_invalid_scope() -> Result<()> {
        let original = credential();
        let bytes = original.encode()?;
        let decoded = Credentials::decode(&bytes)?;
        assert!(decoded.scope() == original.scope());
        for case in 0..8 {
            let mut value = serde_json::to_value(&original)?;
            match case {
                0 => value["version"] = 2.into(),
                1 => value["owner"] = 0.into(),
                2 => value["cloudkit_token"] = "".into(),
                3 => value["peer_id"] = "wrong".into(),
                4 => value["device"]["device_id"] = "wrong".into(),
                5 => {
                    value["anisette_seed"] = STANDARD
                        .encode(br#"{"version":1,"phase":"prepared","machine_json":"data"}"#)
                        .into()
                }
                6 => value["anisette_seed"] = "not-base64".into(),
                _ => value["password"] = "must-not-be-accepted".into(),
            }
            assert!(Credentials::decode(&serde_json::to_vec(&value)?).is_err());
        }
        assert!(Credentials::decode(&vec![0; MAX_CREDENTIAL + 1]).is_err());
        Ok(())
    }
    #[test]
    fn export_selects_only_cloudkit_credentials_and_requires_matching_joined_peer() -> Result<()> {
        use crate::model::SignedInfoState;
        use crate::security::{KeyAlgorithm, KeyRef, KeyUsage};
        let original = credential();
        let mut account = original.account();
        account
            .mobileme
            .tokens
            .insert("pet".into(), "synthetic-must-not-export-pet".into());
        account.mobileme.auth_token = "synthetic-must-not-export-auth".into();
        let key = KeyRef {
            backend_id: "unused".into(),
            key_id: "unused-private-key-reference".into(),
            usage: KeyUsage::Signing,
            algorithm: KeyAlgorithm::P384,
        };
        let mut peer = OctagonState {
            schema_version: 1,
            account_fingerprint: crate::apple::octagon::account_fingerprint(&account),
            peer_id: original.peer_id.clone(),
            signing_key: key.clone(),
            encryption_key: key,
            permanent: SignedInfoState {
                data_b64: String::new(),
                signature_b64: String::new(),
            },
            trust_state: OctagonTrustState::Joined,
            created_at: 0,
        };
        let output =
            Credentials::from_account(1001, &account, &original.device, &peer, &original.seed()?)?
                .encode()?;
        let output = std::str::from_utf8(&output).map_err(|_| invalid("test encoding"))?;
        for secret in [
            "synthetic-must-not-export-pet",
            "synthetic-must-not-export-auth",
            "unused-private-key-reference",
        ] {
            assert!(!output.contains(secret));
        }
        peer.account_fingerprint = format!("SHA256:{}", STANDARD.encode([9; 32]));
        assert!(
            Credentials::from_account(1001, &account, &original.device, &peer, &original.seed()?)
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn anisette_seed_is_atomic_and_never_resets_an_existing_identity() -> Result<()> {
        let temp = tempfile::tempdir().map_err(|e| Error::io("test directory", e))?;
        let paths = AppPaths::for_test(temp.path())?;
        let credentials = credential();
        let seed = credentials.seed()?;
        seed_anisette(&paths, &seed)?;
        let machine = paths.anisette_dir().join("macos/machine.json");
        let original = std::str::from_utf8(&seed).map_err(|_| invalid("test seed"))?;
        let changed = original.replace("synthetic-adi", "updated-local-otp-state");
        crate::paths::atomic_write_private(&machine, changed.as_bytes())?;
        seed_anisette(&paths, &seed)?;
        assert_eq!(
            fs::read(&machine).map_err(|e| Error::io(&machine, e))?,
            changed.as_bytes()
        );
        let refreshed = original.replace("synthetic-adi", "refreshed-export-store");
        seed_anisette(&paths, refreshed.as_bytes())?;
        assert_eq!(
            fs::read(&machine).map_err(|e| Error::io(&machine, e))?,
            changed.as_bytes()
        );
        let other = original.replace(&"01".repeat(16), &"02".repeat(16));
        assert!(seed_anisette(&paths, other.as_bytes()).is_err());
        fs::remove_file(&machine).map_err(|e| Error::io(&machine, e))?;
        assert!(seed_anisette(&paths, &seed).is_err());
        assert!(!machine.exists());
        Ok(())
    }
    #[test]
    fn service_inputs_and_seed_refuse_symlink_paths() -> Result<()> {
        let temp = tempfile::tempdir().map_err(|e| Error::io("test directory", e))?;
        let paths = AppPaths::for_test(temp.path())?;
        fs::create_dir(paths.anisette_dir()).map_err(|e| Error::io("test anisette", e))?;
        std::os::unix::fs::symlink(
            temp.path().join("missing"),
            paths.anisette_dir().join("macos"),
        )
        .map_err(|e| Error::io("test symlink", e))?;
        assert!(seed_anisette(&paths, &credential().seed()?).is_err());
        let target = temp.path().join("credential");
        fs::write(&target, b"synthetic").map_err(|e| Error::io(&target, e))?;
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(target, &link).map_err(|e| Error::io(&link, e))?;
        assert!(trusted_file(&link, 4096).is_err());
        Ok(())
    }
}
