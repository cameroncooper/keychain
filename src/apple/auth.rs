use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::Aes256;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use pbkdf2::pbkdf2_hmac;
use plist::{Dictionary, Value};
use rand::RngCore;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{HeaderName, HeaderValue};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::anisette::AnisetteProvider;
use super::http::{apple_client, apple_unpooled_client};
use crate::model::{AccountState, DeviceIdentity, MobileMeState};
use crate::secret::zeroize_plist_dictionary;
use crate::{Error, Result};

const GSA_ENDPOINT: &str = "https://gsa.apple.com/grandslam/GsService2";
// Match the login (not provisioning) profile in the pinned Mac provider's
// native/apple-core/src/login/{device,messages}.rs. Each service still owns its
// profile; helper metadata cannot choose arbitrary HTTP identity headers.
const GSA_USER_AGENT: &str = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0";
const GSA_CLIENT_INFO: &str = concat!(
    "<MacBookPro13,2> <macOS;13.1;22C65> ",
    "<com.apple.AuthKit/1 (com.apple.akd/1.0)>"
);
const LOGIN_DELEGATES_URL: &str = "https://setup.icloud.com/setup/iosbuddy/loginDelegates";
const ACCOUNT_SETTINGS_URL: &str = "https://setup.icloud.com/setup/get_account_settings";
const TWO_FACTOR_OPTIONS_URL: &str = "https://gsa.apple.com/auth";
const SMS_FACTOR_REQUEST_URL: &str = "https://gsa.apple.com/auth/verify/phone";
const SMS_FACTOR_SUBMIT_URL: &str = "https://gsa.apple.com/auth/verify/phone/securitycode";
const ICLOUD_USER_AGENT: &str = "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0";
const ICLOUD_CLIENT_INFO: &str = concat!(
    "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> ",
    "<com.apple.AOSKit/282 (com.apple.accountsd/113)>"
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
const MAX_APPLE_RESPONSE: u64 = 64 * 1024 * 1024;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub fn load_or_create_device(
    existing: Option<DeviceIdentity>,
    save: impl FnOnce(&DeviceIdentity) -> Result<()>,
) -> Result<DeviceIdentity> {
    if let Some(device) = existing {
        return Ok(device);
    }
    let device = DeviceIdentity {
        schema_version: 1,
        device_id: uuid::Uuid::new_v4()
            .hyphenated()
            .to_string()
            .to_ascii_uppercase(),
        serial: format!("C02{}", &uuid::Uuid::new_v4().simple().to_string()[..9])
            .to_ascii_uppercase(),
        local_user_uuid: uuid::Uuid::new_v4()
            .hyphenated()
            .to_string()
            .to_ascii_uppercase(),
    };
    save(&device)?;
    Ok(device)
}

pub fn identity_headers(
    device: &DeviceIdentity,
    anisette: &dyn AnisetteProvider,
) -> Result<BTreeMap<String, String>> {
    let now = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .map_err(|_| Error::InvalidData("invalid current timestamp".into()))?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| Error::InvalidData("could not format current timestamp".into()))?;
    let mut headers = BTreeMap::from([
        ("X-Apple-I-Client-Time".into(), now),
        ("X-Apple-I-TimeZone".into(), "UTC".into()),
        ("loc".into(), "en_US".into()),
        ("X-Apple-Locale".into(), "en_US".into()),
        ("X-Apple-I-MD-RINFO".into(), "17106176".into()),
        (
            "X-Apple-I-MD-LU".into(),
            B64.encode(device.local_user_uuid.to_ascii_uppercase()),
        ),
        (
            "X-Mme-Device-Id".into(),
            device.device_id.to_ascii_uppercase(),
        ),
        ("X-Apple-I-SRL-NO".into(), device.serial.clone()),
    ]);
    headers.extend(anisette.validation_headers()?);
    Ok(headers)
}

pub struct GsaClient<'a> {
    device: &'a DeviceIdentity,
    anisette: &'a dyn AnisetteProvider,
    client: Client,
}

struct SecretCpd(Dictionary);
impl Drop for SecretCpd {
    fn drop(&mut self) {
        zeroize_plist_dictionary(&mut self.0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmsFactor {
    pub phone_id: u64,
    pub mode: String,
    pub display: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TwoFactorMethod {
    TrustedDevices,
    Phone(SmsFactor),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TwoFactorPrompt {
    Choose(Vec<TwoFactorMethod>),
    Code(TwoFactorMethod),
}

#[derive(Debug)]
pub enum TwoFactorResponse {
    Choose(usize),
    Code(Zeroizing<String>),
    Resend,
    ChangeMethod,
    Cancel,
}

impl<'a> GsaClient<'a> {
    pub fn new(device: &'a DeviceIdentity, anisette: &'a dyn AnisetteProvider) -> Result<Self> {
        Ok(Self {
            device,
            anisette,
            client: apple_unpooled_client(Duration::from_secs(20))?,
        })
    }

    fn cpd(&self) -> Result<Dictionary> {
        let mut cpd = Dictionary::from_iter([
            (String::from("bootstrap"), Value::Boolean(true)),
            (String::from("icscrec"), Value::Boolean(true)),
            (String::from("pbe"), Value::Boolean(false)),
            (String::from("prkgen"), Value::Boolean(true)),
            (String::from("svct"), Value::String("iCloud".into())),
        ]);
        for (key, value) in identity_headers(self.device, self.anisette)? {
            cpd.insert(key, Value::String(value));
        }
        // The helper supplies ADI validation material, not our GSA client
        // identity. Keep CPD and the HTTP header consistent even with an older
        // helper whose default branding still advertises Xcode.
        cpd.insert(
            "X-Mme-Client-Info".into(),
            Value::String(GSA_CLIENT_INFO.into()),
        );
        Ok(cpd)
    }

    fn request(&self, parameters: Dictionary, cpd: &Dictionary) -> Result<Dictionary> {
        let operation = match parameters.get("o").and_then(Value::as_string) {
            Some("init") => "GSA init",
            Some("complete") => "GSA complete",
            _ => "GSA request",
        };
        let mut request = Dictionary::new();
        request.insert("cpd".into(), Value::Dictionary(cpd.clone()));
        request.extend(parameters);
        let body = Value::Dictionary(Dictionary::from_iter([
            (
                String::from("Header"),
                Value::Dictionary(Dictionary::from_iter([(
                    String::from("Version"),
                    Value::String("1.0.1".into()),
                )])),
            ),
            (String::from("Request"), Value::Dictionary(request)),
        ]));
        let encoded = plist_xml(&body)?;
        let response = self
            .client
            .post(GSA_ENDPOINT)
            .header("Content-Type", "text/x-xml-plist")
            .header("Accept", "*/*")
            .header("User-Agent", GSA_USER_AGENT)
            .header("X-MMe-Client-Info", GSA_CLIENT_INFO)
            .body(encoded)
            .send()?;
        let mut parsed = plist_response(response, operation)?
            .into_dictionary()
            .ok_or_else(|| Error::InvalidData("GSA response is not a dictionary".into()))?;
        let result = parsed.remove("Response").and_then(Value::into_dictionary);
        zeroize_plist_dictionary(&mut parsed);
        result.ok_or_else(|| Error::InvalidData("GSA response has no Response dictionary".into()))
    }

    pub fn authenticate(
        &self,
        username: &str,
        password: &str,
        mut two_factor: impl FnMut(TwoFactorPrompt) -> Result<TwoFactorResponse>,
    ) -> Result<AuthResult> {
        let mut result = self.authenticate_once(username, password, "sign-in")?;
        let auth_mode =
            dictionary(&result.complete, "Status").and_then(|status| string(status, "au"));
        if matches!(
            auth_mode.as_deref(),
            Some("trustedDeviceSecondaryAuth" | "secondaryAuth")
        ) {
            let dsid = string_or_integer(&result.spd, &["adsid", "DsPrsId"])
                .ok_or_else(|| Error::Apple("2FA response has no account DSID".into()))?;
            let idms = string_or_integer(&result.spd, &["GsIdmsToken", "GsIdMS"])
                .ok_or_else(|| Error::Apple("2FA response has no identity token".into()))?;
            self.complete_two_factor(
                &dsid,
                &idms,
                auth_mode.as_deref() == Some("trustedDeviceSecondaryAuth"),
                &mut two_factor,
            )?;
            result = self.authenticate_once(username, password, "re-auth after 2FA")?;
            if dictionary(&result.complete, "Status")
                .and_then(|status| string(status, "au"))
                .is_some()
            {
                return Err(Error::Apple(
                    "Apple still requested 2FA after accepting the code".into(),
                ));
            }
        }
        Ok(result)
    }

    fn complete_two_factor(
        &self,
        dsid: &str,
        idms: &str,
        trusted_devices: bool,
        two_factor: &mut impl FnMut(TwoFactorPrompt) -> Result<TwoFactorResponse>,
    ) -> Result<()> {
        let mut methods = Vec::new();
        if trusted_devices {
            methods.push(TwoFactorMethod::TrustedDevices);
        }
        methods.extend(
            self.sms_factors(dsid, idms)?
                .into_iter()
                .map(TwoFactorMethod::Phone),
        );
        if methods.is_empty() {
            return Err(Error::Apple(
                "Apple offered 2FA but returned no usable verification methods".into(),
            ));
        }

        let mut selected = self.choose_two_factor(&methods, two_factor)?;
        loop {
            self.trigger_two_factor(dsid, idms, &selected)?;
            match two_factor(TwoFactorPrompt::Code(selected.clone()))? {
                TwoFactorResponse::Code(code) => {
                    self.submit_two_factor(&code, dsid, idms, &selected)?;
                    return Ok(());
                }
                TwoFactorResponse::Resend => {}
                TwoFactorResponse::ChangeMethod => {
                    selected = self.choose_two_factor(&methods, two_factor)?;
                }
                TwoFactorResponse::Cancel => {
                    return Err(Error::Refused("2FA cancelled".into()));
                }
                TwoFactorResponse::Choose(_) => {
                    return Err(Error::InvalidData(
                        "2FA handler selected a method while a code was requested".into(),
                    ));
                }
            }
        }
    }

    fn choose_two_factor(
        &self,
        methods: &[TwoFactorMethod],
        two_factor: &mut impl FnMut(TwoFactorPrompt) -> Result<TwoFactorResponse>,
    ) -> Result<TwoFactorMethod> {
        if methods.len() == 1 {
            return Ok(methods[0].clone());
        }
        match two_factor(TwoFactorPrompt::Choose(methods.to_vec()))? {
            TwoFactorResponse::Choose(index) => methods
                .get(index)
                .cloned()
                .ok_or_else(|| Error::Refused("invalid 2FA method selection".into())),
            TwoFactorResponse::Cancel => Err(Error::Refused("2FA cancelled".into())),
            _ => Err(Error::InvalidData(
                "2FA handler returned a code while a method was requested".into(),
            )),
        }
    }

    fn trigger_two_factor(&self, dsid: &str, idms: &str, method: &TwoFactorMethod) -> Result<()> {
        match method {
            TwoFactorMethod::TrustedDevices => self.trigger_trusted_factor(dsid, idms),
            TwoFactorMethod::Phone(factor) => self.trigger_sms_factor(dsid, idms, factor),
        }
    }

    fn submit_two_factor(
        &self,
        code: &str,
        dsid: &str,
        idms: &str,
        method: &TwoFactorMethod,
    ) -> Result<()> {
        match method {
            TwoFactorMethod::TrustedDevices => self.submit_trusted_factor(code, dsid, idms),
            TwoFactorMethod::Phone(factor) => self.submit_sms_factor(code, dsid, idms, factor),
        }
    }

    fn initialize_srp(&self, username: &str) -> Result<(GsaSrp, Dictionary, SecretCpd)> {
        let mut private = Zeroizing::new([0_u8; 256]);
        rand::rngs::OsRng.fill_bytes(&mut *private);
        private[0] |= 0x80;
        let srp = GsaSrp::new(username, private.as_slice())?;
        let parameters = Dictionary::from_iter([
            (String::from("A2k"), Value::Data(srp.public_a())),
            (
                String::from("ps"),
                Value::Array(vec![
                    Value::String("s2k".into()),
                    Value::String("s2k_fo".into()),
                ]),
            ),
            (String::from("u"), Value::String(username.into())),
            (String::from("o"), Value::String("init".into())),
        ]);
        let mut cpd = SecretCpd(self.cpd()?);
        let mut init = self.request(parameters.clone(), &cpd.0)?;
        if let Some(sim) = requested_resync(&init)? {
            // Only Apple's explicit pre-password 434 request authorizes this
            // one bounded retry. No identity is regenerated and no proof,
            // second-factor or escrow operation is replayed.
            self.anisette.resync(&sim)?;
            cpd = SecretCpd(self.cpd()?);
            init = self.request(parameters, &cpd.0)?;
        }
        Ok((srp, init, cpd))
    }

    fn authenticate_once(&self, username: &str, password: &str, stage: &str) -> Result<AuthResult> {
        let (mut srp, init, cpd) = self.initialize_srp(username)?;
        let protocol = string(&init, "sp").ok_or_else(|| {
            let hint = if integer(dictionary(&init, "Status").unwrap_or(&init), "ec").ok()
                == Some(-80045)
            {
                "; check anisette/client compatibility rather than retrying the password"
            } else {
                ""
            };
            Error::Apple(format!(
                "{stage}: GSA init failed before password proof: {}{hint}",
                status(&init)
            ))
        })?;
        if protocol != "s2k" && protocol != "s2k_fo" {
            return Err(Error::InvalidData(format!(
                "unsupported Apple password protocol {protocol}"
            )));
        }
        let salt = data(&init, "s")?;
        let iterations = integer(&init, "i")?
            .try_into()
            .map_err(|_| Error::InvalidData("GSA PBKDF iteration count overflow".into()))?;
        let server = data(&init, "B")?;
        // GrandSlam returns the continuation challenge as a plist string, not a data blob.
        let challenge = required_string(&init, "c")?;
        let mut encrypted_password = encrypt_password(password, salt, iterations, &protocol);
        let proof = srp.process_challenge(salt, server, encrypted_password.as_slice())?;
        encrypted_password.zeroize();
        let complete = self.request(
            Dictionary::from_iter([
                (String::from("c"), Value::String(challenge)),
                (String::from("M1"), Value::Data(proof.client_proof.to_vec())),
                (String::from("u"), Value::String(username.into())),
                (String::from("o"), Value::String("complete".into())),
            ]),
            &cpd.0,
        )?;
        drop(cpd);
        let server_proof = data(&complete, "M2").map_err(|_| {
            Error::Apple(format!(
                "{stage}: GSA complete failed: {}",
                status(&complete)
            ))
        })?;
        if server_proof != proof.server_proof {
            return Err(Error::Security(
                "GSA server SRP proof did not verify".into(),
            ));
        }
        let encrypted_spd = data(&complete, "spd")?;
        let plain = decrypt_spd(proof.session_key.as_slice(), encrypted_spd)?;
        let spd = Value::from_reader(Cursor::new(plain.as_slice()))
            .map_err(|error| {
                Error::InvalidData(format!(
                    "{stage}: authenticated GSA session data is not a valid property list: {error}"
                ))
            })?
            .into_dictionary()
            .ok_or_else(|| Error::InvalidData("GSA spd is not a dictionary".into()))?;
        Ok(AuthResult {
            complete,
            spd,
            session_key: proof.session_key,
        })
    }

    fn two_factor_headers(&self, dsid: &str, idms: &str) -> Result<BTreeMap<String, String>> {
        let mut headers = BTreeMap::from([
            ("User-Agent".into(), "Xcode".into()),
            ("Accept-Language".into(), "en-us".into()),
            (
                "X-Apple-Identity-Token".into(),
                B64.encode(format!("{dsid}:{idms}")),
            ),
            ("X-Apple-App-Info".into(), "com.apple.gs.xcode.auth".into()),
            ("X-Xcode-Version".into(), "11.2 (11B41)".into()),
            ("X-Mme-Client-Info".into(), GSA_CLIENT_INFO.into()),
        ]);
        headers.extend(identity_headers(self.device, self.anisette)?);
        Ok(headers)
    }

    fn trigger_trusted_factor(&self, dsid: &str, idms: &str) -> Result<()> {
        let mut headers = self.two_factor_headers(dsid, idms)?;
        headers.insert("Content-Type".into(), "text/x-xml-plist".into());
        headers.insert("Accept".into(), "text/x-xml-plist".into());
        let request = apply_headers(
            self.client
                .get("https://gsa.apple.com/auth/verify/trusteddevice"),
            &headers,
        )?;
        require_success(request.send()?, "trusted-device 2FA trigger")
    }

    fn submit_trusted_factor(&self, code: &str, dsid: &str, idms: &str) -> Result<()> {
        let mut headers = self.two_factor_headers(dsid, idms)?;
        headers.insert("Content-Type".into(), "text/x-xml-plist".into());
        headers.insert("Accept".into(), "text/x-xml-plist".into());
        headers.insert("security-code".into(), code.into());
        check_factor(
            apply_headers(
                self.client
                    .get("https://gsa.apple.com/grandslam/GsService2/validate"),
                &headers,
            )?
            .send()?,
            "trusted-device",
        )
    }

    fn sms_factor_headers(&self, dsid: &str, idms: &str) -> Result<BTreeMap<String, String>> {
        let mut headers = self.two_factor_headers(dsid, idms)?;
        headers.insert("Content-Type".into(), "application/json".into());
        headers.insert("Accept".into(), "application/json".into());
        Ok(headers)
    }

    fn sms_factors(&self, dsid: &str, idms: &str) -> Result<Vec<SmsFactor>> {
        let response = apply_headers(
            self.client.get(TWO_FACTOR_OPTIONS_URL),
            &self.sms_factor_headers(dsid, idms)?,
        )?
        .send()?;
        let status = response.status();
        let bytes = response_bytes(response)?;
        if !status.is_success() {
            return Err(Error::Apple(format!(
                "could not retrieve trusted phone numbers: HTTP {status}{}",
                service_error_suffix(&bytes)
            )));
        }
        let options = two_factor_options(&bytes)?;
        sms_factors(&options)
    }

    fn trigger_sms_factor(&self, dsid: &str, idms: &str, factor: &SmsFactor) -> Result<()> {
        let request = apply_headers(
            self.client
                .put(SMS_FACTOR_REQUEST_URL)
                .json(&serde_json::json!({
                    "phoneNumber":{"id":factor.phone_id},"mode":factor.mode
                })),
            &self.sms_factor_headers(dsid, idms)?,
        )?;
        require_sms_trigger(request.send()?, factor)
    }

    fn submit_sms_factor(
        &self,
        code: &str,
        dsid: &str,
        idms: &str,
        factor: &SmsFactor,
    ) -> Result<()> {
        check_factor(
            apply_headers(
                self.client
                    .post(SMS_FACTOR_SUBMIT_URL)
                    .json(&serde_json::json!({
                        "phoneNumber":{"id":factor.phone_id},"mode":factor.mode,
                        "securityCode":{"code":code}
                    })),
                &self.sms_factor_headers(dsid, idms)?,
            )?
            .send()?,
            "SMS",
        )
    }
}

pub struct AuthResult {
    pub complete: Dictionary,
    pub spd: Dictionary,
    pub session_key: Zeroizing<[u8; 32]>,
}

impl Drop for AuthResult {
    fn drop(&mut self) {
        zeroize_plist_dictionary(&mut self.complete);
        zeroize_plist_dictionary(&mut self.spd);
    }
}

struct GsaSrp {
    username: Vec<u8>,
    private: BigUint,
    public: BigUint,
    modulus: BigUint,
}

struct GsaProof {
    session_key: Zeroizing<[u8; 32]>,
    client_proof: [u8; 32],
    server_proof: [u8; 32],
}

impl GsaSrp {
    fn new(username: &str, private: &[u8]) -> Result<Self> {
        let modulus = BigUint::parse_bytes(SRP_N_HEX.as_bytes(), 16)
            .ok_or_else(|| Error::InvalidData("invalid built-in SRP modulus".into()))?;
        let private = BigUint::from_bytes_be(private);
        let public = BigUint::from(2_u8).modpow(&private, &modulus);
        Ok(Self {
            username: username.as_bytes().to_vec(),
            private,
            public,
            modulus,
        })
    }

    fn public_a(&self) -> Vec<u8> {
        trim(&self.public)
    }

    fn process_challenge(
        &mut self,
        salt: &[u8],
        server_public: &[u8],
        password: &[u8],
    ) -> Result<GsaProof> {
        let generator = BigUint::from(2_u8);
        let server = BigUint::from_bytes_be(server_public);
        if (&server % &self.modulus) == BigUint::default() {
            return Err(Error::Security(
                "invalid GSA SRP server public value".into(),
            ));
        }
        let width = self.modulus.to_bytes_be().len();
        let k = BigUint::from_bytes_be(&hash256(&[
            &pad(&self.modulus, width),
            &pad(&generator, width),
        ]));
        let u =
            BigUint::from_bytes_be(&hash256(&[&pad(&self.public, width), &pad(&server, width)]));
        if u == BigUint::default() {
            return Err(Error::Security("invalid GSA SRP scrambling value".into()));
        }
        // pysrp's no_username_in_x() leaves the colon in H(":" || password).
        let mut inner = Zeroizing::new(Vec::with_capacity(password.len() + 1));
        inner.push(b':');
        inner.extend_from_slice(password);
        let x = BigUint::from_bytes_be(&hash256(&[salt, &hash256(&[inner.as_slice()])]));
        inner.zeroize();
        let verifier = generator.modpow(&x, &self.modulus);
        let base = if server >= (&k * &verifier) {
            (&server - (&k * &verifier)) % &self.modulus
        } else {
            // Big integers are unsigned; normalize pysrp's negative base modulo N.
            ((&server + ((&k * &verifier) / &self.modulus + 1_u8) * &self.modulus)
                - (&k * &verifier))
                % &self.modulus
        };
        let shared = base.modpow(&(&self.private + &u * &x), &self.modulus);
        let session_key = Zeroizing::new(hash256(&[&trim(&shared)]));
        let mut xor = hash256(&[&trim(&self.modulus)]);
        let generator_hash = hash256(&[&pad(&generator, width)]);
        for (left, right) in xor.iter_mut().zip(generator_hash) {
            *left ^= right;
        }
        let client_proof = hash256(&[
            &xor,
            &hash256(&[&self.username]),
            salt,
            &trim(&self.public),
            &trim(&server),
            session_key.as_slice(),
        ]);
        let server_proof = hash256(&[&trim(&self.public), &client_proof, session_key.as_slice()]);
        Ok(GsaProof {
            session_key,
            client_proof,
            server_proof,
        })
    }
}

fn encrypt_password(
    password: &str,
    salt: &[u8],
    iterations: u32,
    protocol: &str,
) -> Zeroizing<[u8; 32]> {
    let digest = Sha256::digest(password.as_bytes());
    let mut input = if protocol == "s2k_fo" {
        Zeroizing::new(hex::encode(digest).into_bytes())
    } else {
        Zeroizing::new(digest.to_vec())
    };
    let mut output = Zeroizing::new([0_u8; 32]);
    pbkdf2_hmac::<Sha256>(&input, salt, iterations, &mut *output);
    input.zeroize();
    output
}

fn decrypt_spd(session_key: &[u8], encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let key = hmac_key(session_key, b"extra data key:")?;
    let iv = hmac_key(session_key, b"extra data iv:")?;
    let mut buffer = Zeroizing::new(encrypted.to_vec());
    let plain = Aes256CbcDec::new_from_slices(key.as_slice(), &iv[..16])
        .map_err(|_| Error::Security("invalid GSA CBC key".into()))?
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| Error::Security("GSA spd padding is invalid".into()))?;
    Ok(Zeroizing::new(plain.to_vec()))
}

fn hmac_key(session_key: &[u8], label: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(session_key)
        .map_err(|_| Error::Security("invalid GSA HMAC key".into()))?;
    mac.update(label);
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

pub struct AccountLogin {
    pub account: AccountState,
    pub pet: Zeroizing<String>,
}

pub fn login_account(
    username: &str,
    password: &str,
    device: &DeviceIdentity,
    anisette: &dyn AnisetteProvider,
    two_factor: impl FnMut(TwoFactorPrompt) -> Result<TwoFactorResponse>,
) -> Result<AccountState> {
    Ok(login_account_with_pet(username, password, device, anisette, two_factor)?.account)
}

/// Authenticate an account while retaining the short-lived PET for an immediate escrow request.
///
/// The caller must keep this result in memory only. `pet` is zeroized when dropped and must never
/// be added to persistent account state.
pub fn login_account_with_pet(
    username: &str,
    password: &str,
    device: &DeviceIdentity,
    anisette: &dyn AnisetteProvider,
    mut two_factor: impl FnMut(TwoFactorPrompt) -> Result<TwoFactorResponse>,
) -> Result<AccountLogin> {
    let gsa = GsaClient::new(device, anisette)?;
    let auth = gsa.authenticate(username, password, &mut two_factor)?;
    let adsid = string_or_integer(&auth.spd, &["adsid", "DsPrsId"])
        .ok_or_else(|| Error::Apple("GSA response contains no DSID".into()))?;
    let tokens = dictionary(&auth.spd, "t")
        .ok_or_else(|| Error::Apple("GSA response contains no application tokens".into()))?;
    let pet_entry = dictionary(tokens, "com.apple.gs.idms.pet")
        .ok_or_else(|| Error::Apple("GSA response contains no PET".into()))?;
    let pet = Zeroizing::new(
        string(pet_entry, "token")
            .ok_or_else(|| Error::Apple("GSA PET entry contains no token".into()))?,
    );
    let (numeric_dsid, mme_token, service_data) =
        login_mobileme(username, &pet, &adsid, device, anisette)?;
    let mut mobile_tokens = BTreeMap::new();
    retain_passwords_tokens(&mut mobile_tokens, dictionary(&service_data, "tokens"));
    let mut account = AccountState {
        schema_version: 1,
        username: username.into(),
        adsid,
        logged_in_at: unix_now(),
        mobileme: MobileMeState {
            dsid: numeric_dsid,
            auth_token: mme_token,
            cloudkit_user_id: None,
            tokens: mobile_tokens,
            minted_at: unix_now(),
        },
        webservices: BTreeMap::new(),
    };
    refresh_account_settings(&mut account, device, anisette)?;
    Ok(AccountLogin { account, pet })
}

pub fn mint_pet(
    username: &str,
    password: &str,
    device: &DeviceIdentity,
    anisette: &dyn AnisetteProvider,
    two_factor: impl FnMut(TwoFactorPrompt) -> Result<TwoFactorResponse>,
) -> Result<Zeroizing<String>> {
    let auth = GsaClient::new(device, anisette)?.authenticate(username, password, two_factor)?;
    dictionary(&auth.spd, "t")
        .and_then(|tokens| dictionary(tokens, "com.apple.gs.idms.pet"))
        .and_then(|entry| string(entry, "token"))
        .map(Zeroizing::new)
        .ok_or_else(|| Error::Apple("GSA response contains no PET".into()))
}

fn login_mobileme(
    username: &str,
    pet: &str,
    adsid: &str,
    device: &DeviceIdentity,
    anisette: &dyn AnisetteProvider,
) -> Result<(String, String, Dictionary)> {
    let body = Value::Dictionary(Dictionary::from_iter([
        (String::from("apple-id"), Value::String(username.into())),
        (
            String::from("delegates"),
            Value::Dictionary(Dictionary::from_iter([(
                String::from("com.apple.mobileme"),
                Value::Dictionary(Dictionary::new()),
            )])),
        ),
        (String::from("password"), Value::String(pet.into())),
        (
            String::from("client-id"),
            Value::String(device.local_user_uuid.clone()),
        ),
    ]));
    let mut headers = BTreeMap::from([
        ("X-Apple-ADSID".into(), adsid.into()),
        ("User-Agent".into(), ICLOUD_USER_AGENT.into()),
        ("X-Mme-Client-Info".into(), ICLOUD_CLIENT_INFO.into()),
        ("Accept".into(), "*/*".into()),
        ("Authorization".into(), basic(username, pet)),
    ]);
    headers.extend(identity_headers(device, anisette)?);
    let client = apple_client(Duration::from_secs(30))?;
    let response = apply_headers(client.post(LOGIN_DELEGATES_URL), &headers)?
        .body(plist_xml(&body)?)
        .send()?;
    let value = plist_response(response, "loginDelegates")?;
    let root = value
        .as_dictionary()
        .ok_or_else(|| Error::InvalidData("loginDelegates response is not a dictionary".into()))?;
    let mobileme = dictionary(root, "delegates")
        .and_then(|delegates| dictionary(delegates, "com.apple.mobileme"))
        .ok_or_else(|| {
            Error::InvalidData("loginDelegates response has no mobileme delegate".into())
        })?;
    let status_code = integer(mobileme, "status")
        .or_else(|_| integer(root, "status"))
        .unwrap_or(-1);
    if status_code != 0 {
        let message = string(mobileme, "status-message")
            .or_else(|| string(root, "status-message"))
            .unwrap_or_else(|| "unknown error".into());
        return Err(Error::Apple(format!(
            "loginDelegates status {status_code}: {message}"
        )));
    }
    let service_data = dictionary(mobileme, "service-data")
        .cloned()
        .ok_or_else(|| Error::InvalidData("loginDelegates has no service-data".into()))?;
    let dsid = string_or_integer(root, &["dsid"])
        .or_else(|| {
            dictionary(&service_data, "appleAccountInfo")
                .and_then(|info| string_or_integer(info, &["dsid"]))
        })
        .ok_or_else(|| Error::InvalidData("loginDelegates has no DSID".into()))?;
    let token = dictionary(&service_data, "tokens")
        .and_then(|tokens| string(tokens, "mmeAuthToken"))
        .ok_or_else(|| Error::InvalidData("loginDelegates has no mmeAuthToken".into()))?;
    Ok((dsid, token, service_data))
}

pub fn refresh_account_settings(
    account: &mut AccountState,
    device: &DeviceIdentity,
    anisette: &dyn AnisetteProvider,
) -> Result<()> {
    let mut headers = BTreeMap::from([
        (
            "Authorization".into(),
            basic(&account.mobileme.dsid, &account.mobileme.auth_token),
        ),
        ("X-Mme-Client-Info".into(), ICLOUD_CLIENT_INFO.into()),
        ("User-Agent".into(), ICLOUD_USER_AGENT.into()),
        ("Accept".into(), "*/*".into()),
    ]);
    headers.extend(identity_headers(device, anisette)?);
    let client = apple_client(Duration::from_secs(30))?;
    let response = apply_headers(client.post(ACCOUNT_SETTINGS_URL), &headers)?
        .body(Vec::new())
        .send()?;
    let status_code = response.status();
    let value = plist_response(response, "account settings")?;
    let root = value.as_dictionary().ok_or_else(|| {
        Error::InvalidData("account settings response is not a dictionary".into())
    })?;
    if status_code == reqwest::StatusCode::UNAUTHORIZED
        || string(root, "ErrorID").as_deref() == Some("UNAUTHORIZED")
    {
        return Err(Error::AuthenticationRequired(
            "iCloud credentials expired; run `keychain login`".into(),
        ));
    }
    if let Ok(code) = integer(root, "status") {
        if code != 0 {
            return Err(Error::Apple(format!(
                "account settings status {code}: {}",
                string(root, "status-message").unwrap_or_default()
            )));
        }
    }
    account.webservices = extract_webservices(root);
    retain_passwords_tokens(&mut account.mobileme.tokens, dictionary(root, "tokens"));
    Ok(())
}

fn extract_webservices(settings: &Dictionary) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(services) = dictionary(settings, "webservices") {
        for (name, value) in services {
            if let Some(url) = value.as_dictionary().and_then(|entry| string(entry, "url")) {
                out.insert(name.clone(), url);
            }
        }
    }
    if let Some(mobileme) = dictionary(settings, "com.apple.mobileme") {
        for (name, value) in mobileme {
            let Some(entry) = value.as_dictionary() else {
                continue;
            };
            let url = ["url", "escrowProxyUrl", "configURL", "wsUrl"]
                .iter()
                .find_map(|key| string(entry, key));
            if let Some(url) = url {
                out.entry(name.clone()).or_insert_with(|| url.clone());
                out.entry(name.rsplit('.').next().unwrap_or(name).to_ascii_lowercase())
                    .or_insert(url);
            }
        }
    }
    out
}

fn retain_passwords_tokens(
    destination: &mut BTreeMap<String, String>,
    tokens: Option<&Dictionary>,
) {
    if let Some(token) = tokens.and_then(|tokens| string(tokens, "cloudKitToken")) {
        destination.insert("cloudKitToken".into(), token);
    }
}

fn check_factor(response: Response, kind: &str) -> Result<()> {
    let successful = response.status().is_success();
    let status_code = response.status();
    let bytes = response_bytes(response)?;
    let body = Value::from_reader(Cursor::new(bytes)).ok();
    let body = body.as_ref().and_then(Value::as_dictionary);
    let error_code = body
        .and_then(|body| integer(body, "ec").ok())
        .unwrap_or_default();
    if !successful || error_code != 0 {
        return Err(Error::Apple(format!(
            "{kind} 2FA code rejected: {}",
            body.and_then(|body| string(body, "em"))
                .unwrap_or_else(|| status_code.to_string())
        )));
    }
    Ok(())
}

fn two_factor_options(bytes: &[u8]) -> Result<serde_json::Value> {
    if let Ok(value) = serde_json::from_slice(bytes) {
        return Ok(value);
    }

    // Older GSA variants wrap the same JSON in a script element instead of returning it directly.
    let html = std::str::from_utf8(bytes).map_err(|_| {
        Error::InvalidData("Apple 2FA options are neither JSON nor UTF-8 HTML".into())
    })?;
    let marker = html
        .find("boot_args")
        .ok_or_else(|| Error::InvalidData("Apple 2FA options contain no boot_args data".into()))?;
    let script = html[..marker]
        .rfind("<script")
        .ok_or_else(|| Error::InvalidData("Apple 2FA boot_args script is malformed".into()))?;
    let content = html[script..]
        .find('>')
        .map(|offset| script + offset + 1)
        .ok_or_else(|| Error::InvalidData("Apple 2FA boot_args script is malformed".into()))?;
    let end = html[content..]
        .find("</script>")
        .map(|offset| content + offset)
        .ok_or_else(|| Error::InvalidData("Apple 2FA boot_args script is unterminated".into()))?;
    serde_json::from_str(html[content..end].trim()).map_err(|error| {
        Error::InvalidData(format!(
            "Apple 2FA boot_args data is not valid JSON: {error}"
        ))
    })
}

fn sms_factors(options: &serde_json::Value) -> Result<Vec<SmsFactor>> {
    let verification = options
        .pointer("/direct/phoneNumberVerification")
        .unwrap_or(options);
    let fallback_mode = verification.get("mode").and_then(serde_json::Value::as_str);

    let mut factors: Vec<SmsFactor> = Vec::new();
    for key in ["trustedPhoneNumber", "phoneNumber"] {
        if let Some(factor) = verification
            .get(key)
            .and_then(|number| sms_factor_from_json(number, fallback_mode))
        {
            if !factors
                .iter()
                .any(|known| known.phone_id == factor.phone_id && known.mode == factor.mode)
            {
                factors.push(factor);
            }
        }
    }

    let numbers = verification
        .get("trustedPhoneNumbers")
        .and_then(serde_json::Value::as_array);
    for factor in numbers
        .into_iter()
        .flatten()
        .filter_map(|number| sms_factor_from_json(number, fallback_mode))
    {
        if !factors
            .iter()
            .any(|known| known.phone_id == factor.phone_id && known.mode == factor.mode)
        {
            factors.push(factor);
        }
    }
    if factors.is_empty() {
        Err(Error::Apple(
            "Apple returned no supported SMS or voice 2FA number".into(),
        ))
    } else {
        Ok(factors)
    }
}

fn sms_factor_from_json(
    number: &serde_json::Value,
    fallback_mode: Option<&str>,
) -> Option<SmsFactor> {
    let phone_id = number.get("id").and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    })?;
    let mode = number
        .get("pushMode")
        .and_then(serde_json::Value::as_str)
        .or(fallback_mode)
        .unwrap_or("sms")
        .to_ascii_lowercase();
    if !matches!(mode.as_str(), "sms" | "voice") {
        return None;
    }
    let display = number
        .get("numberWithDialCode")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            number
                .get("obfuscatedNumber")
                .and_then(serde_json::Value::as_str)
        })
        .map(str::to_owned)
        .or_else(|| {
            number
                .get("lastTwoDigits")
                .and_then(serde_json::Value::as_str)
                .map(|digits| format!("trusted phone ending in {digits}"))
        })
        .unwrap_or_else(|| "trusted phone".into());
    Some(SmsFactor {
        phone_id,
        mode,
        display,
    })
}

fn require_sms_trigger(response: Response, factor: &SmsFactor) -> Result<()> {
    let status = response.status();
    let bytes = response_bytes(response)?;
    if status.is_success()
        || (status == reqwest::StatusCode::PRECONDITION_FAILED
            && is_active_sms_challenge(&bytes, factor))
    {
        return Ok(());
    }
    Err(Error::Apple(format!(
        "SMS 2FA trigger returned HTTP {status}{}",
        service_error_suffix(&bytes)
    )))
}

fn is_active_sms_challenge(bytes: &[u8], factor: &SmsFactor) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    let mode_matches = value
        .get("mode")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|mode| mode.eq_ignore_ascii_case(&factor.mode));
    let phone_matches = ["trustedPhoneNumber", "phoneNumber"]
        .iter()
        .filter_map(|key| value.get(key))
        .any(|number| {
            sms_factor_from_json(number, Some(&factor.mode))
                .is_some_and(|candidate| candidate.phone_id == factor.phone_id)
        });
    let code = value.get("securityCode");
    let six_digits = code
        .and_then(|code| code.get("length"))
        .and_then(serde_json::Value::as_u64)
        == Some(6);
    let locked = [
        "securityCodeLocked",
        "securityCodeCooldown",
        "tooManyCodesValidated",
    ]
    .iter()
    .any(|key| {
        code.and_then(|code| code.get(key))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    });
    mode_matches && phone_matches && six_digits && !locked
}

fn service_error_suffix(bytes: &[u8]) -> String {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return String::new();
    };
    let Some(error) = value
        .get("serviceErrors")
        .and_then(serde_json::Value::as_array)
        .and_then(|errors| errors.first())
    else {
        return String::new();
    };
    let code = error
        .get("code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let message = error
        .get("message")
        .and_then(serde_json::Value::as_str)
        .or_else(|| error.get("title").and_then(serde_json::Value::as_str))
        .unwrap_or("Apple rejected the request");
    let message: String = message
        .chars()
        .filter(|character| !character.is_control())
        .take(200)
        .collect();
    format!(" (Apple code {code}: {message})")
}

fn require_success(response: Response, operation: &str) -> Result<()> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(Error::Apple(format!(
            "{operation} returned HTTP {}",
            response.status()
        )))
    }
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

fn plist_xml(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    value.to_writer_xml(&mut out)?;
    Ok(out)
}

fn plist_response(response: Response, operation: &str) -> Result<Value> {
    let status = response.status().as_u16();
    let content = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let content_kind = if content.contains("html") {
        "HTML"
    } else if content.contains("json") {
        "JSON"
    } else if content.contains("xml") || content.contains("plist") {
        "plist/XML"
    } else if content.starts_with("text/") {
        "text"
    } else {
        "unrecognized content"
    };
    let bytes = Zeroizing::new(response_bytes(response)?);
    parse_auth_plist(operation, status, content_kind, &bytes)
}

fn parse_auth_plist(
    operation: &str,
    status: u16,
    content_kind: &str,
    bytes: &[u8],
) -> Result<Value> {
    let value = Value::from_reader(Cursor::new(bytes)).map_err(|error| {
        // Never include the body: successful authentication responses contain
        // tokens. Only fixed metadata and parser event kinds are diagnostic.
        Error::Apple(format!("{operation}: HTTP {status} returned {content_kind} ({} bytes), not a valid Apple property list: {error}", bytes.len()))
    })?;
    if value.as_dictionary().is_none() {
        return Err(Error::Apple(format!(
            "{operation}: HTTP {status} returned {content_kind}, not an Apple property-list dictionary"
        )));
    }
    Ok(value)
}

fn response_bytes(response: Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_APPLE_RESPONSE)
    {
        return Err(Error::InvalidData(
            "Apple response exceeds size limit".into(),
        ));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_APPLE_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::Apple(format!("could not read Apple response: {error}")))?;
    if bytes.len() as u64 > MAX_APPLE_RESPONSE {
        return Err(Error::InvalidData(
            "Apple response exceeds size limit".into(),
        ));
    }
    Ok(bytes)
}

fn data<'a>(dictionary: &'a Dictionary, key: &str) -> Result<&'a [u8]> {
    dictionary
        .get(key)
        .and_then(Value::as_data)
        .ok_or_else(|| Error::InvalidData(format!("missing data field {key}")))
}

fn dictionary<'a>(dictionary: &'a Dictionary, key: &str) -> Option<&'a Dictionary> {
    dictionary.get(key).and_then(Value::as_dictionary)
}

fn string(dictionary: &Dictionary, key: &str) -> Option<String> {
    dictionary
        .get(key)
        .and_then(Value::as_string)
        .map(str::to_owned)
}

fn required_string(dictionary: &Dictionary, key: &str) -> Result<String> {
    string(dictionary, key).ok_or_else(|| Error::InvalidData(format!("missing string field {key}")))
}

fn string_or_integer(dictionary: &Dictionary, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| match dictionary.get(key) {
        Some(Value::String(value)) => Some(value.clone()),
        Some(Value::Integer(value)) => Some(value.to_string()),
        _ => None,
    })
}

fn integer(dictionary: &Dictionary, key: &str) -> Result<i64> {
    dictionary
        .get(key)
        .and_then(|value| {
            value.as_signed_integer().or_else(|| {
                value
                    .as_unsigned_integer()
                    .and_then(|value| i64::try_from(value).ok())
            })
        })
        .ok_or_else(|| Error::InvalidData(format!("integer field {key} overflows i64")))
}

fn status(response: &Dictionary) -> String {
    let status = dictionary(response, "Status").unwrap_or(response);
    format!(
        "ec={} em={:?} au={:?}",
        integer(status, "ec").unwrap_or_default(),
        string(status, "em"),
        string(status, "au")
    )
}

fn requested_resync(response: &Dictionary) -> Result<Option<String>> {
    let status = dictionary(response, "Status").unwrap_or(response);
    if integer(status, "hsc").ok() != Some(434) || integer(status, "ec").ok() != Some(-22421) {
        return Ok(None);
    }
    let sim = match status.get("X-Apple-I-MD-DATA") {
        Some(Value::Data(bytes)) if !bytes.is_empty() && bytes.len() <= 3072 => B64.encode(bytes),
        Some(Value::String(value)) if !value.is_empty() && value.len() <= 4096 => {
            let bytes = B64
                .decode(value)
                .map_err(|_| Error::InvalidData("invalid anisette resync encoding".into()))?;
            if bytes.is_empty() {
                return Err(Error::InvalidData("empty anisette resync data".into()));
            }
            value.clone()
        }
        _ => {
            return Err(Error::InvalidData(
                "Apple requested anisette resync without bounded SIM data".into(),
            ));
        }
    };
    Ok(Some(sim))
}

fn basic(username: &str, password: &str) -> String {
    format!("Basic {}", B64.encode(format!("{username}:{password}")))
}

fn hash256(parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

fn trim(value: &BigUint) -> Vec<u8> {
    let value = value.to_bytes_be();
    if value.is_empty() { vec![0] } else { value }
}

fn pad(value: &BigUint, width: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut out = vec![0_u8; width.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resync_requires_explicit_pre_password_status_and_bounded_valid_sim() -> Result<()> {
        let response = |ec: i64, hsc: i64, sim: Value| {
            Dictionary::from_iter([(
                String::from("Status"),
                Value::Dictionary(Dictionary::from_iter([
                    (String::from("ec"), Value::Integer(ec.into())),
                    (String::from("hsc"), Value::Integer(hsc.into())),
                    (String::from("X-Apple-I-MD-DATA"), sim),
                ])),
            )])
        };
        let sim = Value::Data(vec![1; 36]);
        assert_eq!(
            requested_resync(&response(-22421_i64, 434_i64, sim.clone()))?,
            Some(B64.encode([1; 36]))
        );
        assert!(requested_resync(&response(-80045, 434, sim.clone()))?.is_none());
        assert!(requested_resync(&response(-22421, 200, sim))?.is_none());
        assert!(requested_resync(&response(-22421, 434, Value::Data(vec![0; 3073]))).is_err());
        assert!(
            requested_resync(&response(-22421, 434, Value::String("invalid!".into()))).is_err()
        );
        Ok(())
    }

    struct LegacyAnisette;
    impl AnisetteProvider for LegacyAnisette {
        fn headers(&self) -> Result<BTreeMap<String, String>> {
            Ok(BTreeMap::from([
                (
                    "X-MMe-Client-Info".into(),
                    "obsolete Xcode suggestion".into(),
                ),
                ("x-mme-client-info".into(), "second casing".into()),
                ("X-Apple-I-MD".into(), "synthetic-otp".into()),
                ("X-Apple-I-MD-M".into(), "synthetic-machine".into()),
            ]))
        }
    }

    #[test]
    fn service_client_identity_cannot_be_overwritten_by_anisette_suggestions() -> Result<()> {
        let provider = LegacyAnisette;
        let device = DeviceIdentity {
            schema_version: 1,
            device_id: "device".into(),
            serial: "serial".into(),
            local_user_uuid: "user".into(),
        };
        let headers = identity_headers(&device, &provider)?;
        assert_eq!(
            headers.get("X-Apple-I-MD").map(String::as_str),
            Some("synthetic-otp")
        );
        assert!(
            headers
                .keys()
                .all(|name| !name.eq_ignore_ascii_case("x-mme-client-info"))
        );
        let client = GsaClient::new(&device, &provider)?;
        let cpd = client.cpd()?;
        assert_eq!(
            cpd.get("X-Mme-Client-Info").and_then(Value::as_string),
            Some(GSA_CLIENT_INFO)
        );
        assert!(!GSA_CLIENT_INFO.contains("Xcode"));
        let headers = client.two_factor_headers("test", "test")?;
        assert_eq!(
            headers.get("X-Mme-Client-Info").map(String::as_str),
            Some(GSA_CLIENT_INFO)
        );
        Ok(())
    }

    #[test]
    fn non_plist_auth_errors_report_stage_and_http_status_without_body() {
        let body = b"Access denied synthetic-sensitive-response";
        let error = parse_auth_plist("GSA init", 403, "text", body)
            .err()
            .unwrap_or_else(|| panic!("non-plist response accepted"))
            .to_string();
        assert!(error.contains("GSA init: HTTP 403"));
        assert!(!error.contains("synthetic-sensitive-response"));
        assert!(
            parse_auth_plist("GSA complete", 200, "plist/XML", b"<plist><dict/></plist>").is_ok()
        );
        assert!(parse_auth_plist("GSA init", 403, "text", b"Forbidden").is_err());
    }

    #[test]
    #[ignore = "requires configured account and network; sends SRP init only, no password proof or escrow attempt"]
    fn live_srp_init_without_password_or_escrow() -> Result<()> {
        keychain_sep_driver::memory::make_process_nondumpable()
            .map_err(|error| Error::io("live-test process protection", error))?;
        use crate::apple::anisette::ManagedAnisette;
        use crate::config::Config;
        use crate::paths::{AppPaths, StateLock};
        use crate::security::SoftwareFileBackend;
        use crate::store::StateStore;
        let paths = AppPaths::discover()?;
        let _lock = StateLock::acquire(&paths)?;
        let config = Config::load(&paths)?;
        let backend = SoftwareFileBackend::new(paths.clone());
        let store = StateStore::new(&paths, &backend);
        let account = store
            .load_account()?
            .ok_or_else(|| Error::Config("live check needs an existing account".into()))?;
        let device = store
            .load_device()?
            .ok_or_else(|| Error::Config("live check needs an existing device".into()))?;
        let helper = std::env::var_os("KEYCHAIN_TEST_ANISETTE_HELPER")
            .map(std::path::PathBuf::from)
            .or(config.anisette_helper)
            .ok_or_else(|| Error::Config("anisette is not configured".into()))?;
        let helper_paths = match std::env::var_os("KEYCHAIN_TEST_ANISETTE_PROFILE") {
            Some(root) => {
                let root = std::path::PathBuf::from(root);
                AppPaths::new(
                    root.join("config"),
                    root.join("state"),
                    root.join("runtime"),
                )?
            }
            None => paths.clone(),
        };
        let anisette = ManagedAnisette::start(&helper, &helper_paths)?;
        let (_, init, _cpd) =
            GsaClient::new(&device, &anisette)?.initialize_srp(&account.username)?;
        if !matches!(string(&init, "sp").as_deref(), Some("s2k" | "s2k_fo")) {
            return Err(Error::Apple(format!(
                "GSA init refused before any password proof: {}",
                status(&init)
            )));
        }
        assert!(!data(&init, "s")?.is_empty());
        assert!(!data(&init, "B")?.is_empty());
        assert!(!required_string(&init, "c")?.is_empty());
        Ok(())
    }

    #[test]
    fn no_username_srp_x_keeps_colon() {
        let password = b"derived password";
        let salt = b"salt";
        let expected = hash256(&[salt, &hash256(&[b":derived password"])]);
        let wrong = hash256(&[salt, &hash256(&[password])]);
        assert_ne!(expected, wrong);
    }

    #[test]
    fn gsa_continuation_challenge_is_a_string() {
        let init = Dictionary::from_iter([(
            String::from("c"),
            Value::String("continuation-token".into()),
        )]);
        assert_eq!(
            required_string(&init, "c").unwrap_or_else(|error| panic!("challenge: {error}")),
            "continuation-token"
        );

        let wrong_type = Dictionary::from_iter([(
            String::from("c"),
            Value::Data(b"continuation-token".to_vec()),
        )]);
        assert!(matches!(
            required_string(&wrong_type, "c"),
            Err(Error::InvalidData(_))
        ));
    }

    #[test]
    fn sms_factor_endpoint_has_no_trailing_slash() {
        assert_eq!(
            SMS_FACTOR_REQUEST_URL,
            "https://gsa.apple.com/auth/verify/phone"
        );
        assert!(!SMS_FACTOR_REQUEST_URL.ends_with('/'));
    }

    #[test]
    fn sms_factor_uses_apples_default_phone_id_and_mode() {
        let options = serde_json::json!({
            "trustedPhoneNumbers": [
                {"id": 2, "pushMode": "sms"},
                {"id": 7, "pushMode": "voice"}
            ],
            "trustedPhoneNumber": {"id": 7, "pushMode": "voice"},
            "phoneNumber": {"id": 7, "pushMode": "voice"}
        });
        assert_eq!(
            sms_factors(&options).unwrap_or_else(|error| panic!("factor: {error}")),
            vec![
                SmsFactor {
                    phone_id: 7,
                    mode: "voice".into(),
                    display: "trusted phone".into(),
                },
                SmsFactor {
                    phone_id: 2,
                    mode: "sms".into(),
                    display: "trusted phone".into(),
                }
            ]
        );
    }

    #[test]
    fn sms_factor_parses_legacy_boot_args_html() {
        let html = br#"<html><script class="boot_args">{
            "direct":{"phoneNumberVerification":{"trustedPhoneNumbers":[
                {"id":"3","pushMode":"sms"}
            ]}}
        }</script></html>"#;
        let options = two_factor_options(html).unwrap_or_else(|error| panic!("options: {error}"));
        assert_eq!(
            sms_factors(&options).unwrap_or_else(|error| panic!("factor: {error}")),
            vec![SmsFactor {
                phone_id: 3,
                mode: "sms".into(),
                display: "trusted phone".into(),
            }]
        );
    }

    #[test]
    fn recognizes_only_matching_unlocked_active_sms_challenge() {
        let factor = SmsFactor {
            phone_id: 2,
            mode: "sms".into(),
            display: "trusted phone".into(),
        };
        let active = serde_json::to_vec(&serde_json::json!({
            "mode": "sms",
            "trustedPhoneNumber": {"id": 2, "pushMode": "sms"},
            "securityCode": {
                "length": 6,
                "securityCodeLocked": false,
                "securityCodeCooldown": false,
                "tooManyCodesValidated": false
            }
        }))
        .unwrap_or_else(|error| panic!("json: {error}"));
        assert!(is_active_sms_challenge(&active, &factor));

        let wrong_phone = serde_json::to_vec(&serde_json::json!({
            "mode": "sms",
            "trustedPhoneNumber": {"id": 9, "pushMode": "sms"},
            "securityCode": {"length": 6}
        }))
        .unwrap_or_else(|error| panic!("json: {error}"));
        assert!(!is_active_sms_challenge(&wrong_phone, &factor));
    }

    #[test]
    fn generated_device_is_stable_shape() {
        let device = load_or_create_device(None, |_| Ok(()))
            .unwrap_or_else(|error| panic!("device: {error}"));
        assert_eq!(device.serial.len(), 12);
        assert_eq!(device.device_id.len(), 36);
    }

    #[test]
    fn persistent_token_filter_keeps_only_cloudkit() {
        let tokens = Dictionary::from_iter([
            (
                String::from("cloudKitToken"),
                Value::String("needed".into()),
            ),
            (String::from("mmeFMIPToken"), Value::String("unused".into())),
            (
                String::from("com.apple.gs.idms.pet"),
                Value::String("must-not-persist".into()),
            ),
        ]);
        let mut retained = BTreeMap::new();
        retain_passwords_tokens(&mut retained, Some(&tokens));
        assert_eq!(
            retained,
            BTreeMap::from([("cloudKitToken".into(), "needed".into())])
        );
    }
}
