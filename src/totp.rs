#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedCode {
    pub code: String,
    pub expires: u64,
    pub period: u64,
}

pub fn generate(uri: &str, at: u64) -> Option<GeneratedCode> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    use sha2::{Sha256, Sha512};

    let url = url::Url::parse(uri).ok()?;
    if url.scheme() != "otpauth" || url.host_str() != Some("totp") {
        return None;
    }
    let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let raw = params
        .get("secret")?
        .replace(' ', "")
        .trim_end_matches('=')
        .to_ascii_uppercase();
    let key = data_encoding::BASE32_NOPAD.decode(raw.as_bytes()).ok()?;
    if key.is_empty() {
        return None;
    }
    let digits = params
        .get("digits")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(6)
        .clamp(6, 10);
    let period = params
        .get("period")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30)
        .max(1);
    let counter = at / period;
    let msg = counter.to_be_bytes();
    let algorithm = params
        .get("algorithm")
        .map(|s| s.to_ascii_uppercase())
        .unwrap_or_else(|| "SHA1".into());
    let mac = match algorithm.as_str() {
        "SHA1" => Hmac::<Sha1>::new_from_slice(&key)
            .ok()?
            .chain_update(msg)
            .finalize()
            .into_bytes()
            .to_vec(),
        "SHA256" => Hmac::<Sha256>::new_from_slice(&key)
            .ok()?
            .chain_update(msg)
            .finalize()
            .into_bytes()
            .to_vec(),
        "SHA512" => Hmac::<Sha512>::new_from_slice(&key)
            .ok()?
            .chain_update(msg)
            .finalize()
            .into_bytes()
            .to_vec(),
        _ => return None,
    };
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    if offset + 4 > mac.len() {
        return None;
    }
    let value = u32::from_be_bytes(mac[offset..offset + 4].try_into().ok()?) & 0x7fff_ffff;
    let modulus = 10_u64.pow(digits);
    let code = u64::from(value) % modulus;
    Some(GeneratedCode {
        code: format!("{code:0width$}", width = digits as usize),
        expires: (counter + 1) * period,
        period,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6238_sha1_vector() {
        let code = generate(
            "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1",
            59,
        )
        .unwrap_or_else(|| panic!("valid code"));
        assert_eq!(code.code, "94287082");
        assert_eq!(code.expires, 60);
    }

    #[test]
    fn malformed_uri_is_rejected() {
        assert!(generate("not a uri", 0).is_none());
    }

    #[test]
    fn accepts_standard_padded_base32() {
        let padded = generate("otpauth://totp/test?secret=MZXW6===&digits=6&period=30", 59);
        assert!(padded.is_some());
    }
}
