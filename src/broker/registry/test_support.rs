//! Disposable synthetic SEP-recipient fixtures. Never use with production keys.
use super::*;
use crate::apple::ckks::upload::Binding;
use crate::passkey::registration::CreationContext;
use crate::security::{KeyAlgorithm, KeyRef, KeyUsage};
use base64::engine::general_purpose::STANDARD;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Digest;

pub(crate) fn context() -> Result<CreationContext> {
    CreationContext::parse(&serde_json::json!({
        "rp":{"id":"example.com","name":"Example"},
        "user":{"id":URL_SAFE_NO_PAD.encode(b"user"),"name":"Test User","displayName":"Test"},
        "challenge":URL_SAFE_NO_PAD.encode([23u8;32]),
        "pubKeyCredParams":[{"type":"public-key","alg":-7}],
        "extensions":{"remoteDesktopClientOverride":{"origin":"https://example.com","sameOriginWithAncestors":true}}
    }).to_string())
}
pub(crate) fn binding(context: &CreationContext) -> Binding {
    Binding {
        owner: 1001,
        account_fingerprint: format!("SHA256:{}", STANDARD.encode([1u8; 32])),
        peer_id: format!("SHA256:{}", STANDARD.encode([2u8; 32])),
        transaction: Uuid::new_v4(),
        request_sha256: context.binding().into(),
        zone: crate::apple::ckks::ZoneIdentity {
            name: "Passwords".into(),
            owner: "test-cloud-owner".into(),
        },
    }
}
pub(crate) fn registry(dir: &Path) -> Result<Registry> {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(dir, e))?;
    let registry = Registry::open(dir)?;
    let secret =
        p256::SecretKey::from_slice(&[7u8; 32]).map_err(|_| Error::Security("test key".into()))?;
    let key: StoredSepKey = serde_json::from_value(serde_json::json!({
        "version":1,"reference":KeyRef {backend_id:"sep-native-v1".into(),key_id:Uuid::new_v4().to_string(),usage:KeyUsage::WebAuthnSigning,algorithm:KeyAlgorithm::P256},
        "policy":"biometry-any","wrapped_blob":STANDARD.encode(b"synthetic wrapped blob"),
        "public_sec1":STANDARD.encode(secret.public_key().to_encoded_point(false).as_bytes()),"allow_decrypt":true
    }))?;
    let plain = zeroize::Zeroizing::new(serde_json::to_vec(&key)?);
    create_private_exclusive(
        &dir.join("item-recipient.enc"),
        &registry.backend.seal(Purpose::KeyStore, &plain)?,
    )?;
    Ok(registry)
}

pub(crate) fn open_scalar(record: &ProtectedRecord) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    // Independently decrypt to prove the saved scalar matches its public
    // identity and exact item context. All secrets here are disposable.
    use aes_gcm::aead::{Aead, KeyInit, consts::U16};
    use p256::ecdh::diffie_hellman;
    use sha2::Sha256;
    let recipient =
        p256::SecretKey::from_slice(&[7u8; 32]).map_err(|_| Error::Security("test key".into()))?;
    let ephemeral = p256::PublicKey::from_sec1_bytes(&record.sealed[..65])
        .map_err(|_| Error::Security("test ephemeral".into()))?;
    let shared = diffie_hellman(recipient.to_nonzero_scalar(), ephemeral.as_affine());
    let mut material = zeroize::Zeroizing::new([0u8; 64]);
    for index in 1u32..=2 {
        let mut hash = Sha256::new();
        hash.update(shared.raw_secret_bytes());
        hash.update(index.to_be_bytes());
        hash.update(&record.sealed[..65]);
        let offset = (index as usize - 1) * 32;
        material[offset..offset + 32].copy_from_slice(&hash.finalize());
    }
    let cipher = aes_gcm::AesGcm::<aes::Aes256, U16>::new_from_slice(&material[..32])
        .map_err(|_| Error::Security("test cipher".into()))?;
    let plain = zeroize::Zeroizing::new(
        cipher
            .decrypt(
                aes_gcm::Nonce::<U16>::from_slice(&material[32..48]),
                &record.sealed[65..],
            )
            .map_err(|_| Error::Security("test decrypt".into()))?,
    );
    let expected = item_binding(
        record.owner,
        record.revision,
        &record.recipient_id,
        &record.credential,
        &record.public_sec1,
    )?;
    let scalar = crate::security::sep::envelope::item_view(&plain, plain.len(), &expected)?;
    let recovered =
        p256::SecretKey::from_slice(scalar).map_err(|_| Error::Security("test scalar".into()))?;
    assert_eq!(
        recovered.public_key().to_encoded_point(false).as_bytes(),
        decode_public(&record.public_sec1)?
    );
    Ok(zeroize::Zeroizing::new(scalar.to_vec()))
}
