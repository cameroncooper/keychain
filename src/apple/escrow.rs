use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::time::Duration;

use aes::{Aes128, Aes256};
use aes_gcm::aead::consts::{U16, U32};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, AesGcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use num_bigint::BigUint;
use num_traits::One;
use p384::SecretKey;
use p384::elliptic_curve::sec1::ToEncodedPoint;
use plist::{Dictionary, Value};
use rand::RngCore;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{HeaderName, HeaderValue};
use sha2::{Digest, Sha256, Sha384};
use zeroize::{Zeroize, Zeroizing};

use super::anisette::AnisetteProvider;
use super::cuttlefish::{SignedBlob, encode_voucher};
use super::http::apple_client;
use super::octagon_keys::{VOUCHER_SIG_TYPE, prefixed_data};
use crate::proto::{Writer, decode_fields, first_bytes, first_string};
use crate::security::{KeyRef, KeyUsage, SecurityBackend};
use crate::{Error, Result};

const HKDF_INFO_SYMMETRIC: &[u8] = b"Escrow Symmetric Key";
pub const HKDF_INFO_SIGNING: &[u8] = b"Escrow Signing Private Key";
pub const HKDF_INFO_ENCRYPTION: &[u8] = b"Escrow Encryption Private Key";
const P384_ORDER_HEX: &str = concat!(
    "ffffffffffffffffffffffffffffffffffffffffffffffff",
    "c7634d81f4372ddf581a0db248b0a77aecec196accc52973"
);
const SRP_N_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4",
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60",
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF",
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907",
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861",
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB",
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
);
const MAX_RESPONSE: u64 = 64 * 1024 * 1024;
const USER_ACTION: &str = "com.apple.sbd: escrow recovery";
const ESCROW_USER_AGENT: &str = "com.apple.sbd/638.100.48 com.apple.iCloudHelper/282";
const ESCROW_CLIENT_INFO: &str = concat!(
    "<MacBookPro18,3> <macOS;13.4.1;22F8> ",
    "<com.apple.AuthKit/1 (com.apple.sbd/638.100.48)>"
);

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256Gcm16 = AesGcm<Aes256, U16>;
type Aes256Gcm32 = AesGcm<Aes256, U32>;
type PrivateKeyPair = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bottle {
    pub peer_id: String,
    pub bottle_id: String,
    pub escrowed_signing_spki: Vec<u8>,
    pub escrowed_encryption_spki: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub authentication_code: Vec<u8>,
    pub iv: Vec<u8>,
}

impl Bottle {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let fields = decode_fields(raw)?;
        let cipher = first_bytes(&fields, 12)
            .ok_or_else(|| Error::InvalidData("bottle has no ciphertext".into()))?;
        let cipher = decode_fields(cipher)?;
        Ok(Self {
            peer_id: first_string(&fields, 1)?.unwrap_or_default(),
            bottle_id: first_string(&fields, 2)?.unwrap_or_default(),
            escrowed_signing_spki: first_bytes(&fields, 8).unwrap_or_default().to_vec(),
            escrowed_encryption_spki: first_bytes(&fields, 9).unwrap_or_default().to_vec(),
            ciphertext: first_bytes(&cipher, 1).unwrap_or_default().to_vec(),
            authentication_code: first_bytes(&cipher, 2).unwrap_or_default().to_vec(),
            iv: first_bytes(&cipher, 3).unwrap_or_default().to_vec(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let cipher = Writer::new()
            .bytes(1, &self.ciphertext)
            .bytes(2, &self.authentication_code)
            .bytes(3, &self.iv)
            .finish();
        Writer::new()
            .string(1, &self.peer_id)
            .string(2, &self.bottle_id)
            .bytes(8, &self.escrowed_signing_spki)
            .bytes(9, &self.escrowed_encryption_spki)
            .message(12, &cipher)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct RecoveredIdentity {
    pub peer_id: String,
    pub signing_key: KeyRef,
    pub encryption_key: KeyRef,
}

impl RecoveredIdentity {
    pub fn make_voucher(
        &self,
        backend: &dyn SecurityBackend,
        beneficiary_peer_id: &str,
    ) -> Result<SignedBlob> {
        let info = encode_voucher(1, beneficiary_peer_id, &self.peer_id);
        let signature =
            backend.sign_p384_sha384(&self.signing_key, &prefixed_data(VOUCHER_SIG_TYPE, &info))?;
        Ok(SignedBlob { info, signature })
    }
}

fn hkdf(entropy: &[u8], adsid: &str, info: &[u8], output: &mut [u8]) -> Result<()> {
    Hkdf::<Sha384>::new(Some(adsid.as_bytes()), entropy)
        .expand(info, output)
        .map_err(|_| Error::Security("escrow HKDF expansion failed".into()))
}

pub fn derive_symmetric_key(entropy: &[u8], adsid: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0_u8; 32]);
    hkdf(entropy, adsid, HKDF_INFO_SYMMETRIC, &mut *key)?;
    Ok(key)
}

pub fn derive_private_x963(entropy: &[u8], adsid: &str, info: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut raw = Zeroizing::new([0_u8; 56]);
    hkdf(entropy, adsid, info, &mut *raw)?;
    let order = BigUint::parse_bytes(P384_ORDER_HEX.as_bytes(), 16)
        .ok_or_else(|| Error::InvalidData("invalid built-in P-384 order".into()))?;
    let scalar =
        (BigUint::from_bytes_be(raw.as_slice()) % (&order - BigUint::one())) + BigUint::one();
    raw.zeroize();
    let mut scalar_bytes = Zeroizing::new(vec![0_u8; 48]);
    let encoded = scalar.to_bytes_be();
    let offset = scalar_bytes.len().saturating_sub(encoded.len());
    scalar_bytes[offset..].copy_from_slice(&encoded);
    let secret = SecretKey::from_slice(&scalar_bytes)
        .map_err(|_| Error::InvalidData("derived invalid P-384 scalar".into()))?;
    let public = secret.public_key().to_encoded_point(false);
    let mut x963 = Zeroizing::new(Vec::with_capacity(145));
    x963.extend_from_slice(public.as_bytes());
    x963.extend_from_slice(&scalar_bytes);
    scalar_bytes.zeroize();
    Ok(x963)
}

pub fn recover_identity(
    backend: &dyn SecurityBackend,
    bottle: &Bottle,
    entropy: &[u8],
    adsid: &str,
) -> Result<RecoveredIdentity> {
    validate_derived_spki(
        entropy,
        adsid,
        HKDF_INFO_SIGNING,
        &bottle.escrowed_signing_spki,
    )?;
    validate_derived_spki(
        entropy,
        adsid,
        HKDF_INFO_ENCRYPTION,
        &bottle.escrowed_encryption_spki,
    )?;
    let key = derive_symmetric_key(entropy, adsid)?;
    let mut sealed = Zeroizing::new(bottle.ciphertext.clone());
    sealed.extend_from_slice(&bottle.authentication_code);
    let plaintext = aes_gcm_decrypt(key.as_slice(), &bottle.iv, sealed.as_slice(), "bottle")?;
    let (signing, encryption) = parse_internal_bottle(&plaintext)?;
    let signing_key = backend.import_p384_x963(KeyUsage::Signing, &signing)?;
    match backend.import_p384_x963(KeyUsage::Agreement, &encryption) {
        Ok(encryption_key) => Ok(RecoveredIdentity {
            peer_id: bottle.peer_id.clone(),
            signing_key,
            encryption_key,
        }),
        Err(error) => {
            let _ = backend.destroy_key(&signing_key);
            Err(error)
        }
    }
}

fn validate_derived_spki(
    entropy: &[u8],
    adsid: &str,
    info: &[u8],
    expected_spki: &[u8],
) -> Result<()> {
    let private = derive_private_x963(entropy, adsid, info)?;
    validate_private_matches_spki(&private, expected_spki)
}

fn parse_internal_bottle(raw: &[u8]) -> Result<PrivateKeyPair> {
    let fields = decode_fields(raw)?;
    let parse_key = |field| -> Result<Zeroizing<Vec<u8>>> {
        let encoded = first_bytes(&fields, field)
            .ok_or_else(|| Error::InvalidData("internal bottle is missing a key".into()))?;
        let key = decode_fields(encoded)?;
        let data = first_bytes(&key, 2)
            .ok_or_else(|| Error::InvalidData("OTPrivateKey is missing keyData".into()))?;
        if data.len() != 145 {
            return Err(Error::InvalidData("OTPrivateKey is not P-384 X9.63".into()));
        }
        Ok(Zeroizing::new(data.to_vec()))
    };
    Ok((parse_key(3)?, parse_key(4)?))
}

fn validate_private_matches_spki(private_x963: &[u8], expected_spki: &[u8]) -> Result<()> {
    use p384::pkcs8::EncodePublicKey;
    let secret = SecretKey::from_slice(&private_x963[97..])
        .map_err(|_| Error::InvalidData("bottle contains invalid P-384 key".into()))?;
    let actual = secret
        .public_key()
        .to_public_key_der()
        .map_err(|_| Error::InvalidData("could not encode bottle public key".into()))?;
    if actual.as_bytes() != expected_spki {
        return Err(Error::Security(
            "bottle private key does not match its authenticated public key".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct SrpClient {
    private: BigUint,
}

#[derive(Clone, Debug)]
pub struct SrpProof {
    pub session_key: Zeroizing<[u8; 32]>,
    pub client_proof: [u8; 32],
}

impl SrpClient {
    pub fn new(private: &[u8]) -> Result<Self> {
        let private = BigUint::from_bytes_be(private);
        if private == BigUint::default() {
            return Err(Error::InvalidData("SRP private value is zero".into()));
        }
        Ok(Self { private })
    }

    pub fn public_a(&self) -> Result<Vec<u8>> {
        let modulus = srp_modulus()?;
        Ok(trim_biguint(
            &BigUint::from(2_u8).modpow(&self.private, &modulus),
        ))
    }

    pub fn process(
        &self,
        username: &[u8],
        password: &[u8],
        salt: &[u8],
        server_public: &[u8],
    ) -> Result<SrpProof> {
        let modulus = srp_modulus()?;
        let generator = BigUint::from(2_u8);
        let server = BigUint::from_bytes_be(server_public);
        if (&server % &modulus) == BigUint::default() {
            return Err(Error::Security("invalid SRP server public value".into()));
        }
        let public = generator.modpow(&self.private, &modulus);
        let public_bytes = trim_biguint(&public);
        let server_bytes = trim_biguint(&server);
        let modulus_padded = pad_biguint(&modulus, 256);
        let generator_padded = pad_biguint(&generator, 256);
        let k = BigUint::from_bytes_be(&hash256(&[&modulus_padded, &generator_padded]));
        let mut identity = Zeroizing::new(Vec::with_capacity(username.len() + password.len() + 1));
        identity.extend_from_slice(username);
        identity.push(b':');
        identity.extend_from_slice(password);
        let identity_hash = hash256(&[identity.as_slice()]);
        let x = BigUint::from_bytes_be(&hash256(&[salt, &identity_hash]));
        let u = BigUint::from_bytes_be(&hash256(&[&public_bytes, &server_bytes]));
        let kgx = (&k * generator.modpow(&x, &modulus)) % &modulus;
        let base = if server >= kgx {
            (&server - &kgx) % &modulus
        } else {
            (&server + &modulus - &kgx) % &modulus
        };
        let exponent = &self.private + (&u * &x);
        let shared = base.modpow(&exponent, &modulus);
        let session_key = Zeroizing::new(hash256(&[&trim_biguint(&shared)]));
        let n_hash = hash256(&[&modulus_padded]);
        let g_hash = hash256(&[&generator_padded]);
        let mut xor = [0_u8; 32];
        for (out, (left, right)) in xor.iter_mut().zip(n_hash.iter().zip(g_hash.iter())) {
            *out = left ^ right;
        }
        let client_proof = hash256(&[
            &xor,
            &hash256(&[username]),
            salt,
            &public_bytes,
            &server_bytes,
            session_key.as_slice(),
        ]);
        identity.zeroize();
        Ok(SrpProof {
            session_key,
            client_proof,
        })
    }

    pub fn expected_server_proof(
        &self,
        client_proof: &[u8],
        session_key: &[u8],
    ) -> Result<[u8; 32]> {
        Ok(hash256(&[&self.public_a()?, client_proof, session_key]))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EscrowRecord {
    pub label: String,
    pub metadata: Dictionary,
}

pub struct EscrowRecovery<'a> {
    host: String,
    email: String,
    pet: String,
    anisette: &'a dyn AnisetteProvider,
    client: Client,
}

impl Drop for EscrowRecovery<'_> {
    fn drop(&mut self) {
        self.pet.zeroize();
    }
}

impl<'a> EscrowRecovery<'a> {
    pub fn new(
        host: &str,
        email: &str,
        pet: &str,
        anisette: &'a dyn AnisetteProvider,
    ) -> Result<Self> {
        let parsed = url::Url::parse(host)?;
        if parsed.scheme() != "https" {
            return Err(Error::Config("escrowproxy endpoint must use HTTPS".into()));
        }
        Ok(Self {
            host: host.trim_end_matches('/').into(),
            email: email.into(),
            pet: pet.into(),
            anisette,
            client: apple_client(Duration::from_secs(45))?,
        })
    }

    fn headers(&self) -> Result<BTreeMap<String, String>> {
        let mut headers = BTreeMap::from([
            ("User-Agent".into(), ESCROW_USER_AGENT.into()),
            ("Accept".into(), "*/*".into()),
            ("Accept-Language".into(), "en-US,en;q=0.9".into()),
            ("X-Apple-I-Locale".into(), "en_US".into()),
            ("x-apple-i-device-type".into(), "1".into()),
            ("Content-Type".into(), "application/x-apple-plst".into()),
        ]);
        headers.extend(self.anisette.headers()?);
        headers.insert("X-Mme-Client-Info".into(), ESCROW_CLIENT_INFO.into());
        Ok(headers)
    }

    fn invoke(&self, command: &str, request: Dictionary) -> Result<Dictionary> {
        let value = Value::Dictionary(request);
        let mut body = Vec::new();
        value.to_writer_xml(&mut body)?;
        let response = apply_headers(
            self.client
                .post(format!("{}/escrowproxy/api/{command}", self.host))
                .basic_auth(&self.email, Some(&self.pet)),
            &self.headers()?,
        )?
        .body(body)
        .send()?;
        let status = response.status();
        let body = response_bytes(response)?;
        let value = Value::from_reader(Cursor::new(body))?;
        let dictionary = value
            .into_dictionary()
            .ok_or_else(|| Error::InvalidData("escrowproxy response is not a dictionary".into()))?;
        if !status.is_success() {
            return Err(Error::Apple(format!(
                "escrowproxy/{command} returned HTTP {status}"
            )));
        }
        Ok(dictionary)
    }

    fn request(command: &str, label: &str, transaction: &str) -> Dictionary {
        let wire = match command {
            "srp_init" => "SRP_INIT",
            "recover" => "RECOVER",
            "get_records" => "GETRECORDS",
            "get_club_cert" => "GETCLUB",
            "enroll" => "ENROLL",
            "delete" => "DELETE",
            value => value,
        };
        Dictionary::from_iter([
            (String::from("command"), Value::String(wire.into())),
            (String::from("label"), Value::String(label.into())),
            (
                String::from("transactionUUID"),
                Value::String(transaction.into()),
            ),
            (
                String::from("userActionLabel"),
                Value::String(USER_ACTION.into()),
            ),
            (String::from("version"), Value::Integer(1.into())),
        ])
    }

    pub fn list_records(&self) -> Result<Vec<EscrowRecord>> {
        let transaction = uuid::Uuid::new_v4()
            .hyphenated()
            .to_string()
            .to_ascii_uppercase();
        let response = self.invoke(
            "get_records",
            Self::request("get_records", "com.apple.securebackup.record", &transaction),
        )?;
        let entries = response
            .get("metadataList")
            .or_else(|| response.get("metadata_list"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let mut records = Vec::new();
        for entry in entries {
            let Some(entry) = entry.as_dictionary() else {
                continue;
            };
            let label = plist_string(entry, "label").unwrap_or_default();
            let metadata = plist_string(entry, "metadata")
                .and_then(|value| B64.decode(value).ok())
                .and_then(|value| Value::from_reader(Cursor::new(value)).ok())
                .and_then(Value::into_dictionary)
                .unwrap_or_default();
            records.push(EscrowRecord { label, metadata });
        }
        Ok(records)
    }

    /// Consumes one server-enforced escrow attempt. The caller must gate `confirmed` with a
    /// bottle-specific interactive confirmation immediately before invoking this method.
    pub fn recover_entropy(
        &self,
        label: &str,
        passcode: &[u8],
        confirmed: bool,
    ) -> Result<Zeroizing<Vec<u8>>> {
        if !confirmed {
            return Err(Error::Refused(
                "escrow recovery consumes one of 10 attempts; explicit confirmation is required"
                    .into(),
            ));
        }
        let transaction = uuid::Uuid::new_v4()
            .hyphenated()
            .to_string()
            .to_ascii_uppercase();
        let mut private = Zeroizing::new([0_u8; 32]);
        rand::rngs::OsRng.fill_bytes(&mut *private);
        let srp = SrpClient::new(private.as_slice())?;
        let public_a = srp.public_a()?;
        let mut init_request = Self::request("srp_init", label, &transaction);
        init_request.insert("blob".into(), Value::String(B64.encode(&public_a)));
        let init = self.invoke("srp_init", init_request)?;
        let dsid = plist_string(&init, "dsid")
            .ok_or_else(|| Error::InvalidData("escrow SRP response has no DSID".into()))?;
        let club_type = plist_integer(&init, "clubTypeID").unwrap_or_default();
        let init_blob = plist_string(&init, "respBlob")
            .ok_or_else(|| Error::InvalidData("escrow SRP response has no respBlob".into()))?;
        let init_blob = B64
            .decode(init_blob)
            .map_err(|_| Error::InvalidData("escrow SRP respBlob is not base64".into()))?;
        let (mut header, sections) = unpack_message(&init_blob, 24, 3)?;
        let id_section = sections
            .first()
            .ok_or_else(|| Error::InvalidData("escrow SRP response has no identifier".into()))?;
        let salt = sections
            .get(1)
            .ok_or_else(|| Error::InvalidData("escrow SRP response has no salt".into()))?;
        let server_public = sections
            .get(2)
            .ok_or_else(|| Error::InvalidData("escrow SRP response has no server key".into()))?;
        let proof = srp.process(dsid.as_bytes(), passcode, salt, server_public)?;
        header[..4].copy_from_slice(&165_u32.to_be_bytes());
        header[4..8].copy_from_slice(&(if club_type == 1 { 2_u32 } else { 0 }).to_be_bytes());
        let mut payload = KeyVaultMessage::new(header);
        payload.section_sized(id_section, 20)?;
        payload.section(&proof.client_proof);
        let mut recover_request = Self::request("recover", label, &transaction);
        recover_request.insert("blob".into(), Value::String(B64.encode(payload.pack()?)));
        let response = self.invoke("recover", recover_request)?;
        let response_blob = plist_string(&response, "respBlob")
            .ok_or_else(|| Error::InvalidData("escrow recovery response has no respBlob".into()))?;
        let response_blob = B64.decode(response_blob).map_err(|_| {
            Error::InvalidData("escrow recovery response blob is not base64".into())
        })?;
        let (response_header, sections) =
            unpack_message(&response_blob, if club_type == 1 { 40 } else { 24 }, 3)?;
        let server_proof = sections
            .first()
            .ok_or_else(|| Error::InvalidData("escrow recovery has no server proof".into()))?;
        if srp.expected_server_proof(&proof.client_proof, proof.session_key.as_slice())?
            != server_proof.as_slice()
        {
            return Err(Error::Security(
                "escrowproxy server SRP proof did not verify".into(),
            ));
        }
        let version = u32::from_be_bytes(
            response_header[4..8]
                .try_into()
                .map_err(|_| Error::InvalidData("escrow response header is truncated".into()))?,
        );
        let iv = sections
            .get(1)
            .ok_or_else(|| Error::InvalidData("escrow recovery has no IV".into()))?;
        let ciphertext = sections
            .get(2)
            .ok_or_else(|| Error::InvalidData("escrow recovery has no ciphertext".into()))?;
        let inner = match version {
            0 => cbc_decrypt(proof.session_key.as_slice(), iv, ciphertext)?,
            2 => aes_gcm_decrypt(
                proof.session_key.as_slice(),
                iv,
                ciphertext.as_slice(),
                "escrow recovery",
            )?,
            value => {
                return Err(Error::InvalidData(format!(
                    "unsupported escrow record version {value}"
                )));
            }
        };
        let (inner_header, inner_sections) = unpack_message(&inner, 16, 6)?;
        let rounds = u32::from_be_bytes(
            inner_header[8..12]
                .try_into()
                .map_err(|_| Error::InvalidData("inner escrow header is truncated".into()))?,
        );
        let second_salt = inner_sections
            .get(1)
            .ok_or_else(|| Error::InvalidData("inner escrow record has no salt".into()))?;
        if second_salt.len() < 16 {
            return Err(Error::InvalidData("inner escrow salt is too short".into()));
        }
        let encrypted_bottle = inner_sections
            .get(3)
            .ok_or_else(|| Error::InvalidData("inner escrow record has no bottle".into()))?;
        let mut derived = Zeroizing::new([0_u8; 16]);
        pbkdf2::pbkdf2_hmac::<Sha256>(passcode, second_salt, rounds, &mut *derived);
        let bottle_plist = cbc_decrypt(&*derived, &second_salt[..16], encrypted_bottle)?;
        let bottle = Value::from_reader(Cursor::new(bottle_plist.as_slice()))?
            .into_dictionary()
            .ok_or_else(|| Error::InvalidData("escrow bottle plist is not a dictionary".into()))?;
        let entropy = bottle
            .get("BottledPeerEntropy")
            .and_then(Value::as_data)
            .ok_or_else(|| Error::InvalidData("escrow bottle contains no entropy".into()))?;
        Ok(Zeroizing::new(entropy.to_vec()))
    }
}

#[derive(Clone, Debug)]
struct KeyVaultMessage {
    header: Vec<u8>,
    sections: Vec<Vec<u8>>,
}

impl KeyVaultMessage {
    fn new(header: Vec<u8>) -> Self {
        Self {
            header,
            sections: Vec::new(),
        }
    }

    fn section(&mut self, data: &[u8]) {
        let mut section = Vec::with_capacity(4 + data.len());
        section.extend_from_slice(&(data.len() as u32).to_be_bytes());
        section.extend_from_slice(data);
        self.sections.push(section);
    }

    fn section_sized(&mut self, data: &[u8], size: usize) -> Result<()> {
        let actual = data
            .len()
            .checked_add(4)
            .ok_or_else(|| Error::InvalidData("escrow section size overflow".into()))?;
        if actual > size {
            return Err(Error::InvalidData(format!(
                "escrow section slot {size} is smaller than {actual}"
            )));
        }
        self.section(data);
        self.sections
            .last_mut()
            .ok_or_else(|| Error::InvalidData("escrow section disappeared".into()))?
            .resize(size, 0);
        Ok(())
    }

    fn pack(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        let mut offsets = Vec::with_capacity(self.sections.len() + 1);
        for section in &self.sections {
            offsets.push(body.len());
            body.extend_from_slice(section);
        }
        offsets.push(body.len());
        let total = 4_usize
            .checked_add(self.header.len())
            .and_then(|value| value.checked_add(offsets.len() * 4))
            .and_then(|value| value.checked_add(body.len()))
            .ok_or_else(|| Error::InvalidData("escrow message size overflow".into()))?;
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(
            &u32::try_from(total)
                .map_err(|_| Error::InvalidData("escrow message is too large".into()))?
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.header);
        for offset in offsets {
            out.extend_from_slice(
                &u32::try_from(offset)
                    .map_err(|_| Error::InvalidData("escrow offset is too large".into()))?
                    .to_be_bytes(),
            );
        }
        out.extend_from_slice(&body);
        Ok(out)
    }
}

fn unpack_message(
    data: &[u8],
    header_len: usize,
    section_count: usize,
) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    if data.len() < 4
        || u32::from_be_bytes(
            data[..4]
                .try_into()
                .map_err(|_| Error::InvalidData("escrow length is truncated".into()))?,
        ) as usize
            > data.len()
    {
        return Err(Error::InvalidData("escrow message is truncated".into()));
    }
    let offsets_start = 4_usize
        .checked_add(header_len)
        .ok_or_else(|| Error::InvalidData("escrow header overflow".into()))?;
    let body_start = offsets_start
        .checked_add((section_count + 1) * 4)
        .ok_or_else(|| Error::InvalidData("escrow offset table overflow".into()))?;
    let header = data
        .get(4..offsets_start)
        .ok_or_else(|| Error::InvalidData("escrow header is truncated".into()))?
        .to_vec();
    if data.get(offsets_start..body_start).is_none() {
        return Err(Error::InvalidData(
            "escrow offset table is truncated".into(),
        ));
    }
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset_pos = offsets_start + index * 4;
        let offset = u32::from_be_bytes(
            data[offset_pos..offset_pos + 4]
                .try_into()
                .map_err(|_| Error::InvalidData("escrow offset is truncated".into()))?,
        ) as usize;
        let start = body_start
            .checked_add(offset)
            .ok_or_else(|| Error::InvalidData("escrow section offset overflow".into()))?;
        let size = u32::from_be_bytes(
            data.get(start..start + 4)
                .ok_or_else(|| Error::InvalidData("escrow section length is truncated".into()))?
                .try_into()
                .map_err(|_| Error::InvalidData("escrow section length is invalid".into()))?,
        ) as usize;
        let section_start = start + 4;
        let end = section_start
            .checked_add(size)
            .ok_or_else(|| Error::InvalidData("escrow section size overflow".into()))?;
        sections.push(
            data.get(section_start..end)
                .ok_or_else(|| Error::InvalidData("escrow section is truncated".into()))?
                .to_vec(),
        );
    }
    Ok((header, sections))
}

fn cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if iv.len() != 16 {
        return Err(Error::InvalidData("escrow CBC IV is not 16 bytes".into()));
    }
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    let plain = match key.len() {
        16 => Aes128CbcDec::new_from_slices(key, iv)
            .map_err(|_| Error::Security("invalid escrow AES-128-CBC key".into()))?
            .decrypt_padded_mut::<Pkcs7>(&mut buffer),
        32 => Aes256CbcDec::new_from_slices(key, iv)
            .map_err(|_| Error::Security("invalid escrow AES-256-CBC key".into()))?
            .decrypt_padded_mut::<Pkcs7>(&mut buffer),
        _ => return Err(Error::InvalidData("invalid escrow CBC key length".into())),
    }
    .map_err(|_| Error::Security("escrow CBC padding is invalid".into()))?;
    Ok(Zeroizing::new(plain.to_vec()))
}

fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    context: &str,
) -> Result<Zeroizing<Vec<u8>>> {
    let plaintext = match iv.len() {
        12 => Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::Security(format!("invalid {context} AES-GCM key")))?
            .decrypt(Nonce::from_slice(iv), ciphertext),
        16 => Aes256Gcm16::new_from_slice(key)
            .map_err(|_| Error::Security(format!("invalid {context} AES-GCM key")))?
            .decrypt(Nonce::<U16>::from_slice(iv), ciphertext),
        32 => Aes256Gcm32::new_from_slice(key)
            .map_err(|_| Error::Security(format!("invalid {context} AES-GCM key")))?
            .decrypt(Nonce::<U32>::from_slice(iv), ciphertext),
        length => {
            return Err(Error::InvalidData(format!(
                "unsupported {context} AES-GCM IV length {length}"
            )));
        }
    }
    .map_err(|_| Error::Security(format!("{context} AES-GCM authentication failed")))?;
    Ok(Zeroizing::new(plaintext))
}

fn plist_string(dictionary: &Dictionary, key: &str) -> Option<String> {
    match dictionary.get(key) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Integer(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn plist_integer(dictionary: &Dictionary, key: &str) -> Option<i64> {
    dictionary.get(key).and_then(|value| {
        value.as_signed_integer().or_else(|| {
            value
                .as_unsigned_integer()
                .and_then(|value| i64::try_from(value).ok())
        })
    })
}

fn apply_headers(
    mut request: RequestBuilder,
    headers: &BTreeMap<String, String>,
) -> Result<RequestBuilder> {
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| Error::InvalidData(format!("invalid HTTP header name {name}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| Error::InvalidData("invalid HTTP header value".into()))?;
        request = request.header(name, value);
    }
    Ok(request)
}

fn response_bytes(response: Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE)
    {
        return Err(Error::InvalidData(
            "escrow response exceeds size limit".into(),
        ));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::Apple(format!("could not read escrow response: {error}")))?;
    if bytes.len() as u64 > MAX_RESPONSE {
        return Err(Error::InvalidData(
            "escrow response exceeds size limit".into(),
        ));
    }
    Ok(bytes)
}

fn srp_modulus() -> Result<BigUint> {
    BigUint::parse_bytes(SRP_N_HEX.as_bytes(), 16)
        .ok_or_else(|| Error::InvalidData("invalid built-in SRP modulus".into()))
}

fn hash256(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

fn trim_biguint(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.is_empty() { vec![0] } else { bytes }
}

fn pad_biguint(value: &BigUint, width: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut out = vec![0_u8; width.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::AppPaths;
    use crate::security::SoftwareFileBackend;
    use p384::pkcs8::EncodePublicKey;

    #[test]
    fn bottle_round_trip() {
        let bottle = Bottle {
            peer_id: "peer".into(),
            bottle_id: "bottle".into(),
            escrowed_signing_spki: vec![1],
            escrowed_encryption_spki: vec![2],
            ciphertext: vec![3],
            authentication_code: vec![4],
            iv: vec![5; 12],
        };
        assert_eq!(
            Bottle::parse(&bottle.encode()).unwrap_or_else(|e| panic!("parse: {e}")),
            bottle
        );
    }

    #[test]
    fn srp_public_value_is_trimmed() {
        let client = SrpClient::new(&[1]).unwrap_or_else(|e| panic!("client: {e}"));
        assert_eq!(
            client.public_a().unwrap_or_else(|e| panic!("A: {e}")),
            vec![2]
        );
    }

    #[test]
    fn key_vault_layout_is_exact() {
        let mut message = KeyVaultMessage::new(b"HHHH".to_vec());
        message.section(b"AB");
        message.section(b"CDE");
        let packed = message.pack().unwrap_or_else(|e| panic!("pack: {e}"));
        assert_eq!(
            hex::encode(&packed),
            "000000214848484800000000000000060000000d00000002414200000003434445"
        );
        let (header, sections) =
            unpack_message(&packed, 4, 2).unwrap_or_else(|e| panic!("unpack: {e}"));
        assert_eq!(header, b"HHHH");
        assert_eq!(sections, [b"AB".to_vec(), b"CDE".to_vec()]);
    }

    #[test]
    fn escrow_srp_known_answer() {
        let client = SrpClient::new(&5_u64.to_be_bytes()).unwrap_or_else(|e| panic!("client: {e}"));
        let modulus = srp_modulus().unwrap_or_else(|e| panic!("N: {e}"));
        let generator = BigUint::from(2_u8);
        let salt: Vec<u8> = (0_u8..16).collect();
        let username = b"1234567890";
        let password = b"0000";
        let x = BigUint::from_bytes_be(&hash256(&[&salt, &hash256(&[b"1234567890:0000"])]));
        let verifier = generator.modpow(&x, &modulus);
        let k = BigUint::from_bytes_be(&hash256(&[
            &pad_biguint(&modulus, 256),
            &pad_biguint(&generator, 256),
        ]));
        let server = (&k * verifier + generator.modpow(&BigUint::from(7_u8), &modulus)) % &modulus;
        let proof = client
            .process(username, password, &salt, &trim_biguint(&server))
            .unwrap_or_else(|e| panic!("proof: {e}"));
        assert_eq!(
            hex::encode(proof.session_key.as_slice()),
            "2d19ff43e3713fa1e0e46215140438f4cead8a97d1f0078c0e4d082a6879fad8"
        );
        assert_eq!(
            hex::encode(proof.client_proof),
            "f4e679ce9d938ce6a6532f3f94e685c137f96754b7a6d4947777380469ffdd20"
        );
    }

    #[test]
    fn recovers_synthetic_32_byte_iv_bottle() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths =
            AppPaths::for_test(temp.path()).unwrap_or_else(|error| panic!("paths: {error}"));
        let backend = SoftwareFileBackend::new(paths);
        let original_signing = backend
            .generate_p384(KeyUsage::Signing)
            .unwrap_or_else(|error| panic!("signing: {error}"));
        let original_encryption = backend
            .generate_p384(KeyUsage::Agreement)
            .unwrap_or_else(|error| panic!("encryption: {error}"));
        let signing_x963 = backend
            .export_private_x963_for_test(&original_signing)
            .unwrap_or_else(|error| panic!("export signing: {error}"));
        let encryption_x963 = backend
            .export_private_x963_for_test(&original_encryption)
            .unwrap_or_else(|error| panic!("export encryption: {error}"));
        let signing_message = Writer::new().uint64(1, 1).bytes(2, &signing_x963).finish();
        let encryption_message = Writer::new()
            .uint64(1, 1)
            .bytes(2, &encryption_x963)
            .finish();
        let internal = Writer::new()
            .message(3, &signing_message)
            .message(4, &encryption_message)
            .finish();
        let entropy = [0x42_u8; 72];
        let adsid = "001385-10-AAAA";
        let derived_spki = |info: &[u8]| {
            let private = derive_private_x963(&entropy, adsid, info)
                .unwrap_or_else(|error| panic!("derive: {error}"));
            SecretKey::from_slice(&private[97..])
                .unwrap_or_else(|error| panic!("secret: {error}"))
                .public_key()
                .to_public_key_der()
                .unwrap_or_else(|error| panic!("spki: {error}"))
                .as_bytes()
                .to_vec()
        };
        let key = derive_symmetric_key(&entropy, adsid)
            .unwrap_or_else(|error| panic!("symmetric key: {error}"));
        let iv = [0x11_u8; 32];
        let sealed = Aes256Gcm32::new_from_slice(key.as_slice())
            .unwrap_or_else(|error| panic!("cipher: {error}"))
            .encrypt(Nonce::<U32>::from_slice(&iv), internal.as_slice())
            .unwrap_or_else(|error| panic!("encrypt: {error}"));
        let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
        let bottle = Bottle {
            peer_id: "SHA256:sponsor".into(),
            bottle_id: "bottle".into(),
            escrowed_signing_spki: derived_spki(HKDF_INFO_SIGNING),
            escrowed_encryption_spki: derived_spki(HKDF_INFO_ENCRYPTION),
            ciphertext: ciphertext.to_vec(),
            authentication_code: tag.to_vec(),
            iv: iv.to_vec(),
        };
        let recovered = recover_identity(&backend, &bottle, &entropy, adsid)
            .unwrap_or_else(|error| panic!("recover: {error}"));
        assert_eq!(
            backend
                .export_private_x963_for_test(&recovered.signing_key)
                .unwrap_or_else(|error| panic!("recovered signing: {error}"))
                .as_slice(),
            signing_x963.as_slice()
        );
        assert_eq!(
            backend
                .export_private_x963_for_test(&recovered.encryption_key)
                .unwrap_or_else(|error| panic!("recovered encryption: {error}"))
                .as_slice(),
            encryption_x963.as_slice()
        );
    }
}
