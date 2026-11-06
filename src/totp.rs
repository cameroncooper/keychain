use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
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

/// Generate only the current code, never return its seed. Application-owned
/// seed/parser/MAC buffers are wiped on all exits. HMAC/digest implementation
/// scratch and compiler copies are not individually locked or proven erased.
pub fn generate(uri: &str, at: u64) -> Option<GeneratedCode> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};

    // Parse the public URI structure by borrowing rather than making a Url that
    // owns a second full seed-bearing URI. Bound work before decoding parameters.
    if uri.len() > 4096 || uri.contains('#') || uri.chars().any(char::is_control) {
        return None;
    }
    let (scheme, rest) = uri.split_once("://")?;
    let (host, label_and_query) = rest.split_once('/')?;
    let (_, query) = label_and_query.split_once('?')?;
    if !scheme.eq_ignore_ascii_case("otpauth") || !host.eq_ignore_ascii_case("totp") {
        return None;
    }
    let mut secret = None;
    let mut digits = None;
    let mut period = None;
    let mut algorithm = None;
    for (index, (name, value)) in url::form_urlencoded::parse(query.as_bytes()).enumerate() {
        // Percent-decoded Cow strings may own allocations. Move each directly
        // into its wiping owner, including unknown/invalid parameters.
        let name = Zeroizing::new(name.into_owned());
        let value = Zeroizing::new(value.into_owned());
        if index >= 32 {
            return None;
        }
        let slot = match name.as_str() {
            "secret" => &mut secret,
            "digits" => &mut digits,
            "period" => &mut period,
            "algorithm" => &mut algorithm,
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return None; // Ambiguous authentication parameters are not last-wins.
        }
    }
    let secret = secret?;
    let mut raw = Zeroizing::new(String::with_capacity(secret.len()));
    for character in secret.chars().filter(|character| *character != ' ') {
        if !character.is_ascii() {
            return None;
        }
        raw.push(character.to_ascii_uppercase());
    }
    let unpadded = raw.trim_end_matches('=').len();
    raw.truncate(unpadded);
    let encoding = data_encoding::BASE32_NOPAD;
    let mut key = Zeroizing::new(vec![0; encoding.decode_len(raw.len()).ok()?]);
    // Own the destination before decoding so a partial failure also wipes it.
    encoding.decode_mut(raw.as_bytes(), &mut key).ok()?;
    drop(raw);
    drop(secret);
    if key.is_empty() {
        return None;
    }
    let digits = match digits {
        Some(value) => value.parse::<u32>().ok()?,
        None => 6,
    };
    let period = match period {
        Some(value) => value.parse::<u64>().ok()?,
        None => 30,
    };
    if !(6..=10).contains(&digits) || period == 0 {
        return None;
    }
    let counter = at / period;
    // The returned expiry must be representable, including at u64::MAX.
    let expires = counter.checked_add(1)?.checked_mul(period)?;
    let msg = counter.to_be_bytes();
    let algorithm = algorithm
        .as_deref()
        .map(|value| value.as_str())
        .unwrap_or("SHA1");
    let mut mac = Zeroizing::new([0_u8; 64]);
    macro_rules! compute_mac {
        ($digest:ty) => {{
            let output = Zeroizing::new(
                Hmac::<$digest>::new_from_slice(&key)
                    .ok()?
                    .chain_update(msg)
                    .finalize()
                    .into_bytes(),
            );
            mac[..output.len()].copy_from_slice(&output);
            output.len()
        }};
    }
    let mac_len = if algorithm.eq_ignore_ascii_case("SHA1") {
        compute_mac!(Sha1)
    } else if algorithm.eq_ignore_ascii_case("SHA256") {
        compute_mac!(Sha256)
    } else if algorithm.eq_ignore_ascii_case("SHA512") {
        compute_mac!(Sha512)
    } else {
        return None;
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
    fn generated_codes_are_redacted_in_debug_output() {
        let code = generate("otpauth://totp/test?secret=MZXW6", 59)
            .unwrap_or_else(|| panic!("valid config"));
        assert!(!format!("{code:?}").contains(&code.code));
    }
}
