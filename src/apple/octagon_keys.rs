use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::{Digest, Sha256, Sha384};

use super::cuttlefish::SignedBlob;
use crate::Result;
use crate::proto::Writer;
use crate::security::{KeyRef, KeyUsage, SecurityBackend};

pub const PERMANENT_INFO_SIG_TYPE: &str = "TPPB.PeerPermanentInfo";
pub const STABLE_INFO_SIG_TYPE: &str = "TPPB.PeerStableInfo";
pub const DYNAMIC_INFO_SIG_TYPE: &str = "TPPB.PeerDynamicInfo";
pub const VOUCHER_SIG_TYPE: &str = "TPPB.Voucher";

pub const FROZEN_POLICY_VERSION: u64 = 5;
pub const FROZEN_POLICY_HASH: &str = "SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo=";
pub const FLEXIBLE_POLICY_VERSION: u64 = 20;
pub const FLEXIBLE_POLICY_HASH: &str = "SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY=";
pub const PEER_MODEL_ID: &str = "MacBookPro18,3";
pub const PEER_OS_VERSION: &str = "macOS 13.4.1 (22F8)";

#[derive(Clone, Debug)]
pub struct PeerKeySet {
    pub signing: KeyRef,
    pub encryption: KeyRef,
}

impl PeerKeySet {
    pub fn generate(backend: &dyn SecurityBackend) -> Result<Self> {
        let signing = backend.generate_p384(KeyUsage::Signing)?;
        match backend.generate_p384(KeyUsage::Agreement) {
            Ok(encryption) => Ok(Self {
                signing,
                encryption,
            }),
            Err(error) => {
                let _ = backend.destroy_key(&signing);
                Err(error)
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct PermanentInfo {
    pub peer_id: String,
    pub signed: SignedBlob,
}

pub fn prefixed_data(kind: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(kind.len() + data.len());
    out.extend_from_slice(kind.as_bytes());
    out.extend_from_slice(data);
    out
}

pub fn tphash_sha256(data: &[u8]) -> String {
    format!("SHA256:{}", B64.encode(Sha256::digest(data)))
}

pub fn tphash_sha384(data: &[u8]) -> String {
    format!("SHA384:{}", B64.encode(Sha384::digest(data)))
}

pub fn build_permanent_info(
    backend: &dyn SecurityBackend,
    keys: &PeerKeySet,
    machine_id: &str,
    model_id: &str,
    epoch: u64,
    creation_time: u64,
) -> Result<PermanentInfo> {
    let data = Writer::new()
        .uint64(1, epoch)
        .bytes(2, &backend.public_spki(&keys.signing)?)
        .bytes(3, &backend.public_spki(&keys.encryption)?)
        .string(4, machine_id)
        .string(5, model_id)
        .uint64(6, creation_time)
        .finish();
    let signature = backend.sign_p384_sha384(
        &keys.signing,
        &prefixed_data(PERMANENT_INFO_SIG_TYPE, &data),
    )?;
    let mut peer_input = Vec::with_capacity(data.len() + signature.len());
    peer_input.extend_from_slice(&data);
    peer_input.extend_from_slice(&signature);
    Ok(PermanentInfo {
        peer_id: tphash_sha256(&peer_input),
        signed: SignedBlob {
            info: data,
            signature,
        },
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_stable_info(
    backend: &dyn SecurityBackend,
    signing_key: &KeyRef,
    clock: u64,
    device_name: &str,
    serial_number: &str,
    os_version: &str,
    supports_repudiation: bool,
) -> Result<SignedBlob> {
    let mut writer = Writer::new()
        .uint64(1, clock)
        .uint64(2, FROZEN_POLICY_VERSION)
        .string(3, FROZEN_POLICY_HASH)
        .string(5, os_version)
        .string(6, device_name)
        .string(9, serial_number)
        .uint64(10, FLEXIBLE_POLICY_VERSION)
        .string(11, FLEXIBLE_POLICY_HASH)
        .uint64(12, 1);
    if supports_repudiation {
        writer = writer.bool(19, true);
    }
    sign_blob(backend, signing_key, STABLE_INFO_SIG_TYPE, writer.finish())
}

pub fn build_dynamic_info(
    backend: &dyn SecurityBackend,
    signing_key: &KeyRef,
    clock: u64,
    included_peer_ids: &[String],
    excluded_peer_ids: &[String],
    preapprovals: &[String],
) -> Result<SignedBlob> {
    let mut writer = Writer::new().uint64(1, clock);
    for peer in included_peer_ids {
        writer = writer.string(2, peer);
    }
    for peer in excluded_peer_ids {
        writer = writer.string(3, peer);
    }
    for hash in preapprovals {
        writer = writer.string(5, hash);
    }
    sign_blob(backend, signing_key, DYNAMIC_INFO_SIG_TYPE, writer.finish())
}

pub fn sign_blob(
    backend: &dyn SecurityBackend,
    signing_key: &KeyRef,
    kind: &str,
    info: Vec<u8>,
) -> Result<SignedBlob> {
    let signature = backend.sign_p384_sha384(signing_key, &prefixed_data(kind, &info))?;
    Ok(SignedBlob { info, signature })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::AppPaths;
    use crate::security::SoftwareFileBackend;

    #[test]
    fn peer_id_is_a_tphash_of_permanent_blob_and_signature() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths =
            AppPaths::for_test(temp.path()).unwrap_or_else(|error| panic!("paths: {error}"));
        let backend = SoftwareFileBackend::new(paths);
        let keys = PeerKeySet::generate(&backend).unwrap_or_else(|error| panic!("keys: {error}"));
        let permanent = build_permanent_info(&backend, &keys, "machine", PEER_MODEL_ID, 1, 123)
            .unwrap_or_else(|error| panic!("permanent: {error}"));
        let mut input = permanent.signed.info.clone();
        input.extend_from_slice(&permanent.signed.signature);
        assert_eq!(permanent.peer_id, tphash_sha256(&input));
    }

    #[test]
    fn tphash_matches_apples_policy_vector() {
        let policy = B64
            .decode(concat!(
                "CAESDgoGaVBob25lEgRmdWxsEgwKBGlQYWQSBGZ1bGwSCwoDTWFjEgRmdWxsEgwKBGlNYWMS",
                "BGZ1bGwSDQoHQXBwbGVUVhICdHYSDgoFV2F0Y2gSBXdhdGNoGhEKCVBDU0VzY3JvdxIEZnVs",
                "bBoXCgRXaUZpEgRmdWxsEgJ0dhIFd2F0Y2gaGQoRU2FmYXJpQ3JlZGl0Q2FyZHMSBGZ1bGwi",
                "DAoEZnVsbBIEZnVsbCIUCgV3YXRjaBIEZnVsbBIFd2F0Y2giDgoCdHYSBGZ1bGwSAnR2"
            ))
            .unwrap_or_else(|error| panic!("base64: {error}"));
        assert_eq!(
            tphash_sha256(&policy),
            "SHA256:TLXrcQmY4ue3oP5pCX1pwsi9BF8cKfohlJBilCroeBs="
        );
    }
}
