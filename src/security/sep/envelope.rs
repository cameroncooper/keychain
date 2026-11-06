//! Host-side item encryption compatible with the local SEP ECIES decrypt API.
//! Public-key encryption does not authenticate the sender; protect the registry
//! and derive the expected binding from trusted selected-record state.

use aes_gcm::aead::{AeadInPlace, KeyInit, consts::U16};
use aes_gcm::{AesGcm, Nonce};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};

const MAGIC: &[u8; 8] = b"SEPITEM\x01";
const MAX_CONTEXT: usize = 1024;
const MAX_SEALED: usize = 4096;
type Cipher = AesGcm<aes::Aes256, U16>;

pub fn seal_item(public_sec1: &[u8], context: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    crate::security::secret_compute(|| {
        seal_with_ephemeral(
            public_sec1,
            context,
            plaintext,
            &SecretKey::random(&mut OsRng),
        )
    })
}

fn seal_with_ephemeral(
    public_sec1: &[u8],
    context: &[u8],
    plaintext: &[u8],
    ephemeral: &SecretKey,
) -> Result<Vec<u8>> {
    if context.is_empty()
        || context.len() > MAX_CONTEXT
        || plaintext.len() > MAX_SEALED
        || 12 + context.len() + plaintext.len() + 81 > MAX_SEALED
    {
        return Err(Error::InvalidData(
            "SEP item envelope exceeds its bounds".into(),
        ));
    }
    if public_sec1.len() != 65 || public_sec1.first() != Some(&4) {
        return Err(Error::InvalidData(
            "SEP recipient must be an uncompressed P-256 point".into(),
        ));
    }
    let recipient = PublicKey::from_sec1_bytes(public_sec1)
        .map_err(|_| Error::InvalidData("invalid SEP recipient public point".into()))?;
    let point = ephemeral.public_key().to_encoded_point(false);
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let material = derive_material(shared.raw_secret_bytes(), point.as_bytes());
    let cipher = Cipher::new_from_slice(&material[..32])
        .map_err(|_| Error::Security("SEP envelope cipher initialization failed".into()))?;
    // Install the complete memory policy BEFORE copying any plaintext. In-place
    // GCM overwrites this protected allocation; only ciphertext leaves it.
    let mut memory = keychain_sep_driver::memory::SecretBuffer::new()
        .map_err(|e| Error::io("SEP sealing plaintext memory", e))?;
    let length = 12 + context.len() + plaintext.len();
    let envelope = &mut memory.as_mut_array()[..length];
    envelope[..8].copy_from_slice(MAGIC);
    envelope[8..12].copy_from_slice(&(context.len() as u32).to_be_bytes());
    envelope[12..12 + context.len()].copy_from_slice(context);
    envelope[12 + context.len()..].copy_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::<U16>::from_slice(&material[32..48]), b"", envelope)
        .map_err(|_| Error::Security("SEP item encryption failed".into()))?;
    let mut sealed = Vec::with_capacity(65 + envelope.len() + tag.len());
    sealed.extend_from_slice(point.as_bytes());
    sealed.extend_from_slice(envelope);
    sealed.extend_from_slice(&tag);
    Ok(sealed)
}

fn derive_material(shared: &[u8], ephemeral: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut material = Zeroizing::new([0; 64]);
    for i in 1_u32..=2 {
        let mut hash = Sha256::new();
        hash.update(shared);
        hash.update(i.to_be_bytes());
        hash.update(ephemeral);
        let block = Zeroizing::new(<[u8; 32]>::from(hash.finalize()));
        let offset = (i as usize - 1) * 32;
        material[offset..offset + 32].copy_from_slice(&block[..]);
    }
    material
}

/// Borrow the selected plaintext after checking its exact expected binding.
/// The caller retains ownership and must erase the full successful output too.
pub fn item_view<'a>(output: &'a [u8], length: usize, expected_context: &[u8]) -> Result<&'a [u8]> {
    if length > output.len()
        || length > MAX_SEALED
        || expected_context.is_empty()
        || expected_context.len() > MAX_CONTEXT
        || length < 12
    {
        return Err(Error::InvalidData(
            "invalid SEP plaintext envelope bounds".into(),
        ));
    }
    let view = &output[..length];
    if &view[..8] != MAGIC {
        return Err(Error::InvalidData("unsupported SEP item envelope".into()));
    }
    let size = u32::from_be_bytes([view[8], view[9], view[10], view[11]]) as usize;
    if size != expected_context.len()
        || 12 + size > length
        || &view[12..12 + size] != expected_context
    {
        return Err(Error::Security("SEP item binding mismatch".into()));
    }
    Ok(&view[12 + size..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_rejects_binding_and_tag_substitution() {
        let recipient = SecretKey::from_slice(&[9; 32]).unwrap_or_else(|e| panic!("key: {e}"));
        let ephemeral = SecretKey::from_slice(&[7; 32]).unwrap_or_else(|e| panic!("key: {e}"));
        let public = recipient.public_key().to_encoded_point(false);
        let sealed = seal_with_ephemeral(
            public.as_bytes(),
            b"owner=1;item=2",
            b"synthetic secret",
            &ephemeral,
        )
        .unwrap_or_else(|e| panic!("seal: {e}"));
        let peer =
            PublicKey::from_sec1_bytes(&sealed[..65]).unwrap_or_else(|e| panic!("point: {e}"));
        let shared = diffie_hellman(recipient.to_nonzero_scalar(), peer.as_affine());
        let material = derive_material(shared.raw_secret_bytes(), &sealed[..65]);
        let cipher =
            Cipher::new_from_slice(&material[..32]).unwrap_or_else(|e| panic!("cipher: {e}"));
        use aes_gcm::aead::Aead;
        let plain = Zeroizing::new(
            cipher
                .decrypt(Nonce::<U16>::from_slice(&material[32..48]), &sealed[65..])
                .unwrap_or_else(|e| panic!("decrypt: {e}")),
        );
        assert_eq!(
            item_view(&plain, plain.len(), b"owner=1;item=2")
                .unwrap_or_else(|e| panic!("view: {e}")),
            b"synthetic secret"
        );
        assert!(item_view(&plain, plain.len(), b"owner=2;item=2").is_err());
        let mut changed = sealed;
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(
            cipher
                .decrypt(Nonce::<U16>::from_slice(&material[32..48]), &changed[65..])
                .is_err()
        );
    }

    #[test]
    fn maximum_size_and_truncated_envelopes_are_rejected() {
        let key = SecretKey::random(&mut OsRng);
        let public = key.public_key().to_encoded_point(false);
        assert!(seal_item(public.as_bytes(), b"context", &[0; 4096]).is_err());
        assert!(seal_item(public.as_bytes(), b"", b"item").is_err());
        assert!(item_view(b"SEPITEM\x01", 8, b"context").is_err());
        assert!(item_view(&[0; 20], usize::MAX, b"context").is_err());
    }
}
