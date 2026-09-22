use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use reqwest::blocking::{Client, RequestBuilder, Response};
use reqwest::header::{HeaderName, HeaderValue};
use sha1::{Digest, Sha1};

use super::anisette::AnisetteProvider;
use super::ckks;
use super::cuttlefish::encode_function_invoke_request;
use super::http::apple_client;
use crate::model::{AccountState, DeviceIdentity};
use crate::proto::{
    Fields, Writer, decode_fields, encode_varint, first_bytes, first_string, first_u64,
};
use crate::{Error, Result};

pub const CKCODE_INVOKE_URL: &str =
    "https://gateway.icloud.com/ckcoderouter/api/client/code/invoke";
pub const CKDATABASE_SYNC_URL: &str =
    "https://gateway.icloud.com/ckdatabase/api/client/record/sync";
pub const CK_APP_INIT_URL: &str = "https://gateway.icloud.com/setup/setup/ck/v1/ckAppInit";
pub const CUTTLEFISH_CONTAINER: &str = "com.apple.security.keychain";
pub const CUTTLEFISH_BUNDLE: &str = "com.apple.security.cuttlefish";
pub const SECURITYD_BUNDLE: &str = "com.apple.securityd";
const CUTTLEFISH_SERVICE: &str = "Cuttlefish";
const CK_MME_CLIENT_INFO: &str = concat!(
    "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> ",
    "<com.apple.cloudkit.CloudKitDaemon/1970 (com.apple.cloudd/1970)>"
);
const MAX_RESPONSE: u64 = 64 * 1024 * 1024;
const MAX_DELIMITED_MESSAGES: usize = 4_096;
const RESULT_SUCCESS: u64 = 1;
const OP_TYPE_FUNCTION_INVOKE: u64 = 1101;

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub device_uuid: String,
    pub serial: String,
    pub name: String,
}

impl From<&DeviceIdentity> for DeviceConfig {
    fn from(device: &DeviceIdentity) -> Self {
        Self {
            device_uuid: device.device_id.clone(),
            serial: device.serial.clone(),
            name: "Mac".into(),
        }
    }
}

fn identifier(name: &str, kind: u64) -> Vec<u8> {
    Writer::new().string(1, name).uint64(2, kind).finish()
}

pub fn build_header(config: &DeviceConfig, container: &str, bundle: &str) -> Vec<u8> {
    Writer::new()
        .string(2, container)
        .string(3, bundle)
        .message(7, &identifier(&config.device_uuid, 2))
        .string(8, "Mac OS X;13.4.1;22F8")
        .string(9, "MacBookPro18,3")
        .string(10, "com.apple.cloudkit.CloudKitDaemon")
        .string(11, "1970")
        .string(18, "5.0")
        .uint64(19, 1)
        .string(21, &config.name)
        .string(22, &config.device_uuid)
        .uint64(23, 1)
        .uint64(25, 1)
        .uint64(29, 0)
        .string(
            32,
            &hex::encode(Sha1::digest(config.device_uuid.as_bytes())),
        )
        .string(33, &config.serial)
        .uint64(34, 0)
        .uint64(35, 1)
        .finish()
}

pub fn build_request_operation(
    header: &[u8],
    operation_type: u64,
    request_field: u32,
    request: &[u8],
) -> Vec<u8> {
    let operation = Writer::new()
        .string(
            1,
            &uuid::Uuid::new_v4()
                .hyphenated()
                .to_string()
                .to_ascii_uppercase(),
        )
        .uint64(2, operation_type)
        .bool(4, true)
        .finish();
    Writer::new()
        .message(1, header)
        .message(2, &operation)
        .message(request_field, request)
        .finish()
}

fn container_headers(bundle: &str, container: &str) -> BTreeMap<String, String> {
    let operation_id = || {
        let value = uuid::Uuid::new_v4().simple().to_string();
        value[..16].to_ascii_uppercase()
    };
    BTreeMap::from([
        ("accept".into(), "application/x-protobuf".into()),
        ("accept-encoding".into(), "gzip".into()),
        ("accept-language".into(), "en-US,en;q=0.9".into()),
        ("cache-control".into(), "no-transform".into()),
        ("content-encoding".into(), "gzip".into()),
        (
            "content-type".into(),
            concat!(
                "application/x-protobuf; desc=\"https://gateway.icloud.com:443",
                "/static/protobuf/CloudDB/CloudDBClient.desc\"; ",
                "messageType=RequestOperation; delimited=true"
            )
            .into(),
        ),
        ("user-agent".into(), "CloudKit/1970 (19H384)".into()),
        ("x-apple-c2-metric-triggers".into(), "0".into()),
        ("x-apple-operation-group-id".into(), operation_id()),
        ("x-apple-operation-id".into(), operation_id()),
        (
            "x-apple-request-uuid".into(),
            uuid::Uuid::new_v4()
                .hyphenated()
                .to_string()
                .to_ascii_uppercase(),
        ),
        ("x-cloudkit-bundleid".into(), bundle.into()),
        ("x-cloudkit-containerid".into(), container.into()),
        ("x-cloudkit-databasescope".into(), "Private".into()),
        ("x-cloudkit-duetpreclearedmode".into(), "None".into()),
        ("x-cloudkit-environment".into(), "Production".into()),
        ("x-mme-client-info".into(), CK_MME_CLIENT_INFO.into()),
    ])
}

pub fn ensure_cloudkit_user_id(
    account: &mut AccountState,
    anisette: &dyn AnisetteProvider,
) -> Result<bool> {
    if account.mobileme.cloudkit_user_id.is_some() {
        return Ok(false);
    }
    let mut headers = container_headers(CUTTLEFISH_BUNDLE, CUTTLEFISH_CONTAINER);
    headers.insert(
        "Authorization".into(),
        format!(
            "Basic {}",
            B64.encode(format!(
                "{}:{}",
                account.mobileme.dsid, account.mobileme.auth_token
            ))
        ),
    );
    headers.extend(anisette.headers()?);
    let client = apple_client(Duration::from_secs(30))?;
    let response = apply_headers(
        client
            .post(CK_APP_INIT_URL)
            .query(&[("container", CUTTLEFISH_CONTAINER)]),
        &headers,
    )?
    .body(Vec::new())
    .send()?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err(Error::AuthenticationRequired(
            "ckAppInit rejected the iCloud token; run `keychain login`".into(),
        ));
    }
    if !response.status().is_success() {
        return Err(Error::Apple(format!(
            "ckAppInit returned HTTP {}",
            response.status()
        )));
    }
    let body = response_bytes(response)?;
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    let user_id = value
        .get("cloudKitUserId")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| Error::InvalidData("ckAppInit returned no cloudKitUserId".into()))?;
    account.mobileme.cloudkit_user_id = Some(user_id.into());
    Ok(true)
}

pub struct CloudKitResult {
    pub code: u64,
    pub error_description: Option<String>,
    pub fields: Fields,
}

impl CloudKitResult {
    pub fn field(&self, field: u32) -> Option<&[u8]> {
        first_bytes(&self.fields, field)
    }
}

pub fn parse_response_operation(raw: &[u8]) -> Result<CloudKitResult> {
    let fields = decode_fields(raw)?;
    let mut code = RESULT_SUCCESS;
    let mut error_description = None;
    if let Some(result) = first_bytes(&fields, 3) {
        let result = decode_fields(result)?;
        code = first_u64(&result, 1).unwrap_or(RESULT_SUCCESS);
        if let Some(error) = first_bytes(&result, 2) {
            error_description = first_string(&decode_fields(error)?, 4)?;
        }
    }
    Ok(CloudKitResult {
        code,
        error_description,
        fields,
    })
}

pub struct CloudKitTransport<'a> {
    token: String,
    user_id: String,
    device: DeviceConfig,
    anisette: &'a dyn AnisetteProvider,
    client: Client,
}

impl Drop for CloudKitTransport<'_> {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
    }
}

impl<'a> CloudKitTransport<'a> {
    pub fn new(
        account: &AccountState,
        device: &DeviceIdentity,
        anisette: &'a dyn AnisetteProvider,
    ) -> Result<Self> {
        let token = account
            .mobileme
            .tokens
            .get("cloudKitToken")
            .cloned()
            .ok_or_else(|| {
                Error::AuthenticationRequired(
                    "account has no cloudKitToken; run `keychain login`".into(),
                )
            })?;
        let user_id = account
            .mobileme
            .cloudkit_user_id
            .clone()
            .ok_or_else(|| Error::Config("cloudKitUserId has not been initialized".into()))?;
        Ok(Self {
            token,
            user_id,
            device: device.into(),
            anisette,
            client: apple_client(Duration::from_secs(45))?,
        })
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    fn headers(
        &self,
        bundle: &str,
        routing_hint: Option<&str>,
    ) -> Result<BTreeMap<String, String>> {
        let mut headers = container_headers(bundle, CUTTLEFISH_CONTAINER);
        headers.insert("x-cloudkit-userid".into(), self.user_id.clone());
        headers.insert("x-cloudkit-authtoken".into(), self.token.clone());
        if let Some(routing_hint) = routing_hint {
            headers.insert("x-cloudkit-functionroutinghint".into(), routing_hint.into());
        }
        headers.extend(self.anisette.headers()?);
        Ok(headers)
    }

    fn perform(
        &self,
        url: &str,
        operation_type: u64,
        request_field: u32,
        request: &[u8],
        bundle: &str,
        routing_hint: Option<&str>,
    ) -> Result<CloudKitResult> {
        let header = build_header(&self.device, CUTTLEFISH_CONTAINER, bundle);
        let operation = build_request_operation(&header, operation_type, request_field, request);
        let mut delimited = encode_varint(operation.len() as u64);
        delimited.extend_from_slice(&operation);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&delimited)
            .map_err(|error| Error::Apple(format!("could not gzip CloudKit request: {error}")))?;
        let body = encoder
            .finish()
            .map_err(|error| Error::Apple(format!("could not finish CloudKit request: {error}")))?;
        let response = apply_headers(self.client.post(url), &self.headers(bundle, routing_hint)?)?
            .body(body)
            .send()?;
        let status = response.status();
        let body = response_bytes(response)?;
        if !status.is_success() {
            return Err(if status == reqwest::StatusCode::UNAUTHORIZED {
                Error::AuthenticationRequired(
                    "CloudKit rejected the account token; run `keychain login`".into(),
                )
            } else {
                Error::Apple(format!("CloudKit returned HTTP {status}"))
            });
        }
        let body = maybe_gunzip(&body)?;
        let messages = undelimit(&body)?;
        let raw = messages
            .first()
            .ok_or_else(|| Error::InvalidData("CloudKit returned no response operation".into()))?;
        let result = parse_response_operation(raw)?;
        if result.code != RESULT_SUCCESS {
            return Err(Error::Apple(format!(
                "CloudKit operation failed (code {}): {}",
                result.code,
                result
                    .error_description
                    .as_deref()
                    .unwrap_or("unknown error")
            )));
        }
        Ok(result)
    }

    pub fn invoke(&self, operation_name: &str, parameters: &[u8]) -> Result<Vec<u8>> {
        let request =
            encode_function_invoke_request(CUTTLEFISH_SERVICE, operation_name, parameters);
        let result = self.perform(
            CKCODE_INVOKE_URL,
            OP_TYPE_FUNCTION_INVOKE,
            1101,
            &request,
            CUTTLEFISH_BUNDLE,
            Some(&format!("{CUTTLEFISH_SERVICE}/{operation_name}")),
        )?;
        let Some(invoke) = result.field(1101) else {
            return Ok(Vec::new());
        };
        Ok(first_bytes(&decode_fields(invoke)?, 1)
            .unwrap_or_default()
            .to_vec())
    }

    pub fn fetch_records(&self, request: &[u8]) -> Result<Vec<u8>> {
        let result = self.perform(
            CKDATABASE_SYNC_URL,
            ckks::OP_RETRIEVE_CHANGES,
            ckks::FIELD_RETRIEVE_CHANGES,
            request,
            SECURITYD_BUNDLE,
            None,
        )?;
        Ok(result
            .field(ckks::FIELD_RETRIEVE_CHANGES)
            .unwrap_or_default()
            .to_vec())
    }
}

fn maybe_gunzip(payload: &[u8]) -> Result<Vec<u8>> {
    if !payload.starts_with(&[0x1f, 0x8b]) {
        return Ok(payload.to_vec());
    }
    let decoder = GzDecoder::new(payload);
    let mut decoded = Vec::new();
    decoder
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut decoded)
        .map_err(|error| Error::InvalidData(format!("invalid CloudKit gzip response: {error}")))?;
    if decoded.len() as u64 > MAX_RESPONSE {
        return Err(Error::InvalidData(
            "CloudKit response exceeds size limit".into(),
        ));
    }
    Ok(decoded)
}

fn undelimit(data: &[u8]) -> Result<Vec<&[u8]>> {
    let mut messages = Vec::new();
    let mut position = 0_usize;
    while position < data.len() {
        if messages.len() >= MAX_DELIMITED_MESSAGES {
            return Err(Error::InvalidData(
                "CloudKit response contains too many messages".into(),
            ));
        }
        let mut length = 0_u64;
        let mut shift = 0_u32;
        loop {
            let byte = *data
                .get(position)
                .ok_or_else(|| Error::InvalidData("truncated CloudKit length".into()))?;
            position += 1;
            if shift >= 64 && byte & 0x7f != 0 {
                return Err(Error::InvalidData("CloudKit length overflow".into()));
            }
            length |= u64::from(byte & 0x7f) << shift.min(63);
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 70 {
                return Err(Error::InvalidData("CloudKit length is too long".into()));
            }
        }
        let length = usize::try_from(length)
            .map_err(|_| Error::InvalidData("CloudKit message length overflow".into()))?;
        let end = position
            .checked_add(length)
            .ok_or_else(|| Error::InvalidData("CloudKit message offset overflow".into()))?;
        messages.push(
            data.get(position..end)
                .ok_or_else(|| Error::InvalidData("truncated CloudKit message".into()))?,
        );
        position = end;
    }
    Ok(messages)
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
            "CloudKit response exceeds size limit".into(),
        ));
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::Apple(format!("could not read CloudKit response: {error}")))?;
    if bytes.len() as u64 > MAX_RESPONSE {
        return Err(Error::InvalidData(
            "CloudKit response exceeds size limit".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delimiter_round_trip() {
        let mut stream = encode_varint(3);
        stream.extend_from_slice(b"one");
        stream.extend_from_slice(&encode_varint(3));
        stream.extend_from_slice(b"two");
        assert_eq!(
            undelimit(&stream).unwrap_or_else(|e| panic!("split: {e}")),
            [b"one", b"two"]
        );
    }

    #[test]
    fn delimiter_rejects_too_many_messages() {
        assert!(undelimit(&vec![0; MAX_DELIMITED_MESSAGES + 1]).is_err());
    }

    #[test]
    fn header_uses_sha1_hardware_id() {
        let config = DeviceConfig {
            device_uuid: "device".into(),
            serial: "serial".into(),
            name: "Mac".into(),
        };
        let header = decode_fields(&build_header(
            &config,
            CUTTLEFISH_CONTAINER,
            CUTTLEFISH_BUNDLE,
        ))
        .unwrap_or_else(|e| panic!("header: {e}"));
        assert_eq!(
            first_string(&header, 32).unwrap_or_else(|e| panic!("string: {e}")),
            Some("f3a929b3364b471a481f4f7cda0b4559ecde9aba".into())
        );
    }
}
