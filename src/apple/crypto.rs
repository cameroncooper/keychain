use aes::Aes256;
use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{AesGcm, Nonce};
use aes_siv::siv::Aes256Siv;
use p384::ecdh::diffie_hellman;
use p384::elliptic_curve::rand_core::OsRng;
use p384::elliptic_curve::sec1::ToEncodedPoint;
use p384::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::security::{KeyRef, SecurityBackend};
use crate::{Error, Result};

type Aes256Gcm16 = AesGcm<Aes256, U16>;

pub struct EciesCiphertext {
    pub ephemeral_sender_public: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub authentication_code: Vec<u8>,
}

pub fn x963_kdf(secret: &[u8], shared_info: &[u8], length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(length);
    let mut counter = 1_u32;
    while output.len() < length {
        let mut hash = Sha256::new();
        hash.update(secret);
        hash.update(counter.to_be_bytes());
        hash.update(shared_info);
        output.extend_from_slice(&hash.finalize());
        counter = counter.saturating_add(1);
    }
    output.truncate(length);
    output
}

pub fn ecies_decrypt(
    backend: &dyn SecurityBackend,
    private_key: &KeyRef,
    ephemeral_sender_public: &[u8],
    ciphertext: &[u8],
    authentication_code: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let shared = backend.ecdh_p384(private_key, ephemeral_sender_public)?;
    let derived = Zeroizing::new(x963_kdf(&shared, ephemeral_sender_public, 48));
    let cipher = Aes256Gcm16::new_from_slice(&derived[..32])
        .map_err(|_| Error::InvalidData("invalid ECIES AES key".into()))?;
    let mut combined = Vec::with_capacity(ciphertext.len() + authentication_code.len());
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(authentication_code);
    cipher
        .decrypt(
            Nonce::<U16>::from_slice(&derived[32..48]),
            combined.as_ref(),
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidData("ECIES authentication failed".into()))
}

pub fn ecies_encrypt(recipient_public_x963: &[u8], plaintext: &[u8]) -> Result<EciesCiphertext> {
    let recipient = PublicKey::from_sec1_bytes(recipient_public_x963)
        .map_err(|_| Error::InvalidData("P-384 recipient point is not on the curve".into()))?;
    let ephemeral = SecretKey::random(&mut OsRng);
    let ephemeral_sender_public = ephemeral
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let derived = Zeroizing::new(x963_kdf(
        shared.raw_secret_bytes(),
        &ephemeral_sender_public,
        48,
    ));
    let cipher = Aes256Gcm16::new_from_slice(&derived[..32])
        .map_err(|_| Error::InvalidData("invalid ECIES AES key".into()))?;
    let encrypted = cipher
        .encrypt(Nonce::<U16>::from_slice(&derived[32..48]), plaintext)
        .map_err(|_| Error::Security("ECIES encryption failed".into()))?;
    let tag_offset = encrypted
        .len()
        .checked_sub(16)
        .ok_or_else(|| Error::Security("ECIES encryption returned no authentication tag".into()))?;
    Ok(EciesCiphertext {
        ephemeral_sender_public,
        ciphertext: encrypted[..tag_offset].to_vec(),
        authentication_code: encrypted[tag_offset..].to_vec(),
    })
}

pub fn aes_siv_unwrap(
    key: &[u8],
    wrapped: &[u8],
    associated_data: &[Vec<u8>],
) -> Result<Zeroizing<Vec<u8>>> {
    use aes_siv::KeyInit as _;
    if key.len() != 64 {
        return Err(Error::InvalidData(
            "AES-256-SIV key must be 64 bytes".into(),
        ));
    }
    let mut cipher = Aes256Siv::new_from_slice(key)
        .map_err(|_| Error::InvalidData("invalid AES-SIV key".into()))?;
    cipher
        .decrypt(associated_data.iter(), wrapped)
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidData("AES-SIV authentication failed".into()))
}

pub fn decrypt_item(
    item_key: &[u8],
    data: &[u8],
    aad_values: &[Vec<u8>],
) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < 32 {
        return Err(Error::InvalidData(
            "encrypted CKKS item is too short".into(),
        ));
    }
    let mut headers = Vec::with_capacity(aad_values.len() + 1);
    headers.push(data[..16].to_vec());
    headers.extend_from_slice(aad_values);
    let mut plaintext = aes_siv_unwrap(item_key, &data[16..], &headers)?;
    strip_iso7816_padding(&mut plaintext)?;
    Ok(plaintext)
}

fn strip_iso7816_padding(data: &mut Vec<u8>) -> Result<()> {
    let marker = data
        .iter()
        .rposition(|byte| *byte != 0)
        .ok_or_else(|| Error::InvalidData("missing ISO-7816 padding marker".into()))?;
    if data[marker] != 0x80 {
        return Err(Error::InvalidData("invalid ISO-7816 padding".into()));
    }
    data.truncate(marker);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::AppPaths;
    use crate::security::{KeyUsage, SoftwareFileBackend};
    use aes_gcm::aead::OsRng;
    use p384::SecretKey;
    use p384::ecdh::diffie_hellman;
    use p384::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use p384::{EncodedPoint, PublicKey};

    #[test]
    fn x963_known_vector() {
        assert_eq!(
            hex::encode(x963_kdf(
                &hex::decode("96c05619d56c328ab95fe84b18264b08725b85e33fd34f08")
                    .unwrap_or_else(|error| panic!("hex: {error}")),
                b"",
                16,
            )),
            "443024c3dae66b95e6f5670601558f71"
        );
    }

    #[test]
    fn x963_output_is_prefix_stable() {
        let long = x963_kdf(b"secret", b"info", 48);
        assert_eq!(long.len(), 48);
        assert_eq!(x963_kdf(b"secret", b"info", 32), long[..32]);
    }

    #[test]
    fn decrypts_siv_item_and_checks_iso7816_padding() {
        use aes_siv::KeyInit as _;

        let key = [0x42_u8; 64];
        let iv = [0x11_u8; 16];
        let metadata = vec![b"UUID".to_vec(), b"class-key".to_vec()];
        let mut headers = vec![iv.to_vec()];
        headers.extend_from_slice(&metadata);
        let mut padded = b"plist payload".to_vec();
        padded.push(0x80);
        padded.extend_from_slice(&[0; 7]);
        let mut cipher =
            Aes256Siv::new_from_slice(&key).unwrap_or_else(|error| panic!("cipher: {error}"));
        let encrypted = cipher
            .encrypt(headers.iter(), padded.as_slice())
            .unwrap_or_else(|error| panic!("encrypt: {error}"));
        let mut data = iv.to_vec();
        data.extend_from_slice(&encrypted);
        assert_eq!(
            decrypt_item(&key, &data, &metadata)
                .unwrap_or_else(|error| panic!("decrypt: {error}"))
                .as_slice(),
            b"plist payload"
        );

        let mut bad = b"not padded".to_vec();
        let encrypted = cipher
            .encrypt(headers.iter(), bad.as_slice())
            .unwrap_or_else(|error| panic!("encrypt: {error}"));
        bad.clear();
        let mut data = iv.to_vec();
        data.extend_from_slice(&encrypted);
        assert!(decrypt_item(&key, &data, &metadata).is_err());
    }

    #[test]
    fn ecies_uses_apples_16_byte_gcm_iv() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths =
            AppPaths::for_test(temp.path()).unwrap_or_else(|error| panic!("paths: {error}"));
        let backend = SoftwareFileBackend::new(paths);
        let recipient = backend
            .generate_p384(KeyUsage::Agreement)
            .unwrap_or_else(|error| panic!("recipient: {error}"));
        let recipient_point = EncodedPoint::from_bytes(
            backend
                .public_x963(&recipient)
                .unwrap_or_else(|error| panic!("public: {error}")),
        )
        .unwrap_or_else(|error| panic!("point: {error}"));
        let recipient_public =
            Option::<PublicKey>::from(PublicKey::from_encoded_point(&recipient_point))
                .unwrap_or_else(|| panic!("valid public key"));
        let ephemeral = SecretKey::random(&mut OsRng);
        let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient_public.as_affine());
        let ephemeral_public = ephemeral.public_key().to_encoded_point(false);
        let derived = x963_kdf(shared.raw_secret_bytes(), ephemeral_public.as_bytes(), 48);
        let cipher = Aes256Gcm16::new_from_slice(&derived[..32])
            .unwrap_or_else(|error| panic!("cipher: {error}"));
        let encrypted = cipher
            .encrypt(
                Nonce::<U16>::from_slice(&derived[32..]),
                b"plaintext".as_slice(),
            )
            .unwrap_or_else(|error| panic!("encrypt: {error}"));
        let (ciphertext, tag) = encrypted.split_at(encrypted.len() - 16);
        let plain = ecies_decrypt(
            &backend,
            &recipient,
            ephemeral_public.as_bytes(),
            ciphertext,
            tag,
        )
        .unwrap_or_else(|error| panic!("decrypt: {error}"));
        assert_eq!(plain.as_slice(), b"plaintext");
    }

    #[test]
    fn ecies_encrypt_round_trips_through_backend_decrypt() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths =
            AppPaths::for_test(temp.path()).unwrap_or_else(|error| panic!("paths: {error}"));
        let backend = SoftwareFileBackend::new(paths);
        let recipient = backend
            .generate_p384(KeyUsage::Agreement)
            .unwrap_or_else(|error| panic!("recipient: {error}"));
        let public = backend
            .public_x963(&recipient)
            .unwrap_or_else(|error| panic!("public: {error}"));
        let encrypted = ecies_encrypt(&public, b"secret TLK")
            .unwrap_or_else(|error| panic!("encrypt: {error}"));
        let plaintext = ecies_decrypt(
            &backend,
            &recipient,
            &encrypted.ephemeral_sender_public,
            &encrypted.ciphertext,
            &encrypted.authentication_code,
        )
        .unwrap_or_else(|error| panic!("decrypt: {error}"));
        assert_eq!(plaintext.as_slice(), b"secret TLK");
    }
}
