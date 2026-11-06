use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedCode {
    pub code: String,
    pub expires: u64,
    pub period: u64,
}

impl std::fmt::Debug for GeneratedCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GeneratedCode")
            .field("code", &"[REDACTED]")
            .field("expires", &self.expires)
            .field("period", &self.period)
            .finish()
    }
}

#[derive(Clone, Copy)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}
struct Configuration {
    key: keychain_sep_driver::memory::SecretBuffer,
    key_len: usize,
    digits: u32,
    period: u64,
    algorithm: Algorithm,
}
impl Configuration {
    fn parse(uri: &str) -> Option<Self> {
        if uri.len() > 4096 || uri.contains('#') || uri.chars().any(char::is_control) {
            return None;
        }
        let (scheme, rest) = uri.split_once("://")?;
        let (host, label_and_query) = rest.split_once('/')?;
        let (_, query) = label_and_query.split_once('?')?;
        if !scheme.eq_ignore_ascii_case("otpauth") || !host.eq_ignore_ascii_case("totp") {
            return None;
        }
        // Every decoder destination has final size and checked protections before
        // seed bytes arrive, including partial/error paths. Never own a Url or
        // decoded query String containing the seed.
        let mut configuration = Self {
            key: keychain_sep_driver::memory::SecretBuffer::new().ok()?,
            key_len: 0,
            digits: 6,
            period: 30,
            algorithm: Algorithm::Sha1,
        };
        let mut name = keychain_sep_driver::memory::SecretBuffer::new().ok()?;
        let mut value = keychain_sep_driver::memory::SecretBuffer::new().ok()?;
        let mut seen = 0u8;
        for (index, parameter) in query
            .split('&')
            .filter(|value| !value.is_empty())
            .enumerate()
        {
            if index >= 32 {
                return None;
            }
            let (raw_name, raw_value) = parameter.split_once('=').unwrap_or((parameter, ""));
            name.as_mut_array().zeroize();
            let name_len = decode_form(raw_name.as_bytes(), name.as_mut_array())?;
            let flag = match &name.as_array()[..name_len] {
                b"secret" => 1,
                b"digits" => 2,
                b"period" => 4,
                b"algorithm" => 8,
                _ => continue,
            };
            if seen & flag != 0 {
                return None;
            }
            seen |= flag;
            value.as_mut_array().zeroize();
            let length = decode_form(raw_value.as_bytes(), value.as_mut_array())?;
            match flag {
                1 => {
                    let bytes = value.as_mut_array();
                    let mut size = 0;
                    for index in 0..length {
                        if bytes[index] != b' ' {
                            bytes[size] = bytes[index].to_ascii_uppercase();
                            size += 1;
                        }
                    }
                    while size > 0 && bytes[size - 1] == b'=' {
                        size -= 1;
                    }
                    let encoding = data_encoding::BASE32_NOPAD;
                    let key_len = encoding.decode_len(size).ok()?;
                    if key_len == 0 || key_len > 4096 {
                        return None;
                    }
                    encoding
                        .decode_mut(
                            &bytes[..size],
                            &mut configuration.key.as_mut_array()[..key_len],
                        )
                        .ok()?;
                    configuration.key_len = key_len;
                }
                2 => {
                    configuration.digits = std::str::from_utf8(&value.as_array()[..length])
                        .ok()?
                        .parse()
                        .ok()?
                }
                4 => {
                    configuration.period = std::str::from_utf8(&value.as_array()[..length])
                        .ok()?
                        .parse()
                        .ok()?
                }
                8 => {
                    let algorithm = &value.as_array()[..length];
                    configuration.algorithm = if algorithm.eq_ignore_ascii_case(b"SHA1") {
                        Algorithm::Sha1
                    } else if algorithm.eq_ignore_ascii_case(b"SHA256") {
                        Algorithm::Sha256
                    } else if algorithm.eq_ignore_ascii_case(b"SHA512") {
                        Algorithm::Sha512
                    } else {
                        return None;
                    };
                }
                _ => return None,
            }
        }
        if seen & 1 == 0 || !(6..=10).contains(&configuration.digits) || configuration.period == 0 {
            return None;
        }
        Some(configuration)
    }
}

// Form query decoding into the already protected destination. Invalid percent
// escapes fail closed. This performs no allocation or cryptographic operation.
fn decode_form(input: &[u8], output: &mut [u8]) -> Option<usize> {
    let hex = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    let (mut read, mut written) = (0, 0);
    while read < input.len() {
        let byte = match input[read] {
            b'+' => b' ',
            b'%' => {
                let byte = (hex(*input.get(read + 1)?)? << 4) | hex(*input.get(read + 2)?)?;
                read += 2;
                byte
            }
            byte => byte,
        };
        *output.get_mut(written)? = byte;
        written += 1;
        read += 1;
    }
    Some(written)
}

pub(crate) fn is_valid(uri: &str) -> bool {
    keychain_sep_driver::memory::with_secret_stack(|| Configuration::parse(uri).is_some())
        .unwrap_or(false)
}

/// Generate only the current code, never return its seed. Primary parser/seed
/// buffers and the worker stack are locked, dump-excluded and wiped on exit.
/// This does not promise erasure of register copies or unrelated heap storage.
pub fn generate(uri: &str, at: u64) -> Option<GeneratedCode> {
    keychain_sep_driver::memory::with_secret_stack(|| generate_inner(uri, at))
        .ok()
        .flatten()
}

fn generate_inner(uri: &str, at: u64) -> Option<GeneratedCode> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};
    let configuration = Configuration::parse(uri)?;
    let digits = configuration.digits;
    let period = configuration.period;
    let key = &configuration.key.as_array()[..configuration.key_len];
    let counter = at / period;
    let expires = counter.checked_add(1)?.checked_mul(period)?;
    let msg = counter.to_be_bytes();
    let mut mac = Zeroizing::new([0_u8; 64]);
    macro_rules! compute_mac {
        ($digest:ty) => {{
            let output = Zeroizing::new(
                Hmac::<$digest>::new_from_slice(key)
                    .ok()?
                    .chain_update(msg)
                    .finalize()
                    .into_bytes(),
            );
            mac[..output.len()].copy_from_slice(&output);
            output.len()
        }};
    }
    let mac_len = match configuration.algorithm {
        Algorithm::Sha1 => compute_mac!(Sha1),
        Algorithm::Sha256 => compute_mac!(Sha256),
        Algorithm::Sha512 => compute_mac!(Sha512),
    };
    let offset = usize::from(mac[mac_len - 1] & 0x0f);
    let value = u32::from_be_bytes(mac.get(offset..offset + 4)?.try_into().ok()?) & 0x7fff_ffff;
    let code = u64::from(value) % 10_u64.pow(digits);
    Some(GeneratedCode {
        code: format!("{code:0width$}", width = digits as usize),
        expires,
        period,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6238_vectors_all_algorithms_and_times() {
        let vectors = [
            (59, ["94287082", "46119246", "90693936"]),
            (1_111_111_109, ["07081804", "68084774", "25091201"]),
            (1_111_111_111, ["14050471", "67062674", "99943326"]),
            (1_234_567_890, ["89005924", "91819424", "93441116"]),
            (2_000_000_000, ["69279037", "90698825", "38618901"]),
            (20_000_000_000, ["65353130", "77737706", "47863826"]),
        ];
        let seeds = [
            ("SHA1", "12345678901234567890"),
            ("SHA256", "12345678901234567890123456789012"),
            (
                "SHA512",
                "1234567890123456789012345678901234567890123456789012345678901234",
            ),
        ];
        for (at, expected) in vectors {
            for (index, (algorithm, seed)) in seeds.iter().enumerate() {
                let uri = format!(
                    "otpauth://totp/test?secret={}&digits=8&period=30&algorithm={algorithm}",
                    data_encoding::BASE32_NOPAD.encode(seed.as_bytes())
                );
                let code =
                    generate(&uri, at).unwrap_or_else(|| panic!("RFC vector {algorithm} {at}"));
                assert_eq!(code.code, expected[index]);
                assert_eq!(code.expires, (at / 30 + 1) * 30);
            }
        }
    }

    #[test]
    fn malformed_ambiguous_and_out_of_bounds_inputs_are_rejected() {
        let valid = "otpauth://totp/test?secret=MZXW6";
        for uri in [
            "not a uri".to_owned(),
            valid.replace("totp/test", "hotp/test"),
            valid.replace("secret=MZXW6", "secret="),
            valid.replace("secret=MZXW6", "secret=MZX!6"),
            valid.replace("secret=MZXW6", "secret=%C3%A9"),
            format!("{valid}&secret=GEZD"),
            format!("{valid}&%73ecret=GEZD"),
            format!("{valid}&digits=7&digits=8"),
            format!("{valid}&period=30&period=60"),
            format!("{valid}&algorithm=SHA1&algorithm=SHA256"),
            format!("{valid}&digits=5"),
            format!("{valid}&digits=11"),
            format!("{valid}&digits=invalid"),
            format!("{valid}&period=0"),
            format!("{valid}&period=invalid"),
            format!("{valid}&algorithm=MD5"),
            format!("{valid}#fragment"),
            format!("{valid}\n"),
            format!("{valid}&{}", "x=1&".repeat(33)),
            format!("{valid}&label={}", "x".repeat(4096)),
        ] {
            assert!(
                generate(&uri, 59).is_none(),
                "invalid configuration accepted"
            );
        }
        assert!(generate(valid, u64::MAX).is_none());
        assert!(generate(&format!("{valid}&period=1"), u64::MAX).is_none());
        assert!(generate(&format!("{valid}&period={}", u64::MAX), u64::MAX - 1).is_some());
    }

    #[test]
    fn accepts_percent_encoded_spaced_lowercase_and_padded_base32() {
        let plain = generate("otpauth://totp/test?secret=MZXW6&digits=6&period=30", 59);
        let padded = generate(
            "otpauth://totp/test?secret=mz%20xw6%3D%3D%3D&digits=6&period=30",
            59,
        );
        assert!(padded.is_some());
        assert_eq!(padded, plain);
    }

    #[test]
    fn protected_form_decoder_matches_standard_valid_bytes_and_refuses_truncation() {
        let mut output = [0u8; 4096];
        for byte in 0u8..=255 {
            let encoded = format!("prefix+%{byte:02x}%{byte:02X}");
            let length = decode_form(encoded.as_bytes(), &mut output)
                .unwrap_or_else(|| panic!("valid form encoding"));
            let query = format!("value={encoded}");
            // Compare raw decoded bytes; form_urlencoded's UTF-8 repair is not
            // applicable to the ASCII seed/algorithm/numeric fields we accept.
            if byte.is_ascii() {
                let decoded = url::form_urlencoded::parse(query.as_bytes())
                    .next()
                    .unwrap_or_else(|| panic!("standard decoder"))
                    .1;
                assert_eq!(&output[..length], decoded.as_bytes());
            }
        }
        for invalid in [b"%".as_slice(), b"%1", b"%zz", b"a%0x"] {
            assert!(decode_form(invalid, &mut output).is_none());
        }
        assert!(decode_form(b"ab", &mut [0u8; 1]).is_none());
        assert!(is_valid("otpauth://totp/test?secret=MZXW6"));
        assert!(!is_valid("otpauth://totp/test?secret=MZXW6&%73ecret=MZXW6"));
    }

    #[test]
    fn locked_seed_allocation_failure_has_no_fallback() {
        const CHILD: &str = "KEYCHAIN_TEST_TOTP_NO_MEMLOCK";
        const URI: &str = "otpauth://totp/test?secret=MZXW6";
        if std::env::var_os(CHILD).is_some() {
            assert!(keychain_sep_driver::memory::SecretBuffer::new().is_err());
            assert!(!is_valid(URI));
            assert!(generate(URI, 59).is_none());
            return;
        }
        if keychain_sep_driver::peer::effective_uid() == 0 {
            return;
        }
        let executable =
            std::env::current_exe().unwrap_or_else(|error| panic!("test executable: {error}"));
        let status = std::process::Command::new("/usr/bin/prlimit")
            .args(["--memlock=0:0", "--"])
            .arg(executable)
            .args([
                "--exact",
                "totp::tests::locked_seed_allocation_failure_has_no_fallback",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap_or_else(|error| panic!("isolated memlock check: {error}"));
        assert!(status.success());
    }

    #[test]
    fn generated_codes_are_redacted_in_debug_output() {
        let code = generate("otpauth://totp/test?secret=MZXW6", 59)
            .unwrap_or_else(|| panic!("valid config"));
        assert!(!format!("{code:?}").contains(&code.code));
    }
}
