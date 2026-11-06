//! Restricted CKKS create + unchanged-current-key save adapter. The framing is
//! independently implemented from published schema facts; live atomicity and
//! Apple acceptance remain explicit validation gates. No browser/CLI path
//! enables these writes yet. See docs/CLOUDKIT-WRITE-PROTOCOL.md for provenance.

use super::*;
use crate::apple::ckks::upload::{Binding, SaveOutcome, Snapshot, UploadIo};
use crate::apple::ckks::{FieldValue, Record, ZoneIdentity};
use crate::apple::pipeline::RecoveredTlk;
use crate::model::{OctagonState, OctagonTrustState};
use crate::proto::Value;
use uuid::Uuid;

const SAVE_URL: &str = "https://gateway.icloud.com/ckdatabase/api/client/record/save";
const SAVE: u32 = 210;
const MAX_SAVE_BODY: usize = 2 * 1024 * 1024;

/// Account/peer/zone/record scope fixed before any network operation. Networking
/// stays outside the privileged biometric broker; callers supply roots from
/// verified Octagon shares, never from an unauthenticated CloudKit record.
pub struct AppleUploadIo<'a, 'provider> {
    transport: &'a CloudKitTransport<'provider>,
    binding: Binding,
    tlks: Vec<RecoveredTlk>,
    client: Client,
}
impl<'a, 'provider> AppleUploadIo<'a, 'provider> {
    pub(crate) fn for_worker(
        transport: &'a CloudKitTransport<'provider>,
        binding: Binding,
    ) -> Result<Self> {
        binding.validate()?;
        if binding.zone.owner != transport.user_id
            || binding.account_fingerprint != transport.account_fingerprint
        {
            return Err(Error::Security(
                "worker scope differs from authenticated account".into(),
            ));
        }
        Ok(Self {
            transport,
            binding,
            tlks: vec![],
            client: crate::apple::http::apple_write_client(Duration::from_secs(45))?,
        })
    }
    pub fn new(
        transport: &'a CloudKitTransport<'provider>,
        peer: &OctagonState,
        binding: Binding,
        authenticated_tlks: Vec<RecoveredTlk>,
    ) -> Result<Self> {
        binding.validate()?;
        if binding.zone.owner != transport.user_id
            || binding.account_fingerprint != transport.account_fingerprint
            || peer.account_fingerprint != binding.account_fingerprint
            || peer.peer_id != binding.peer_id
            || !matches!(peer.trust_state, OctagonTrustState::Joined)
            || authenticated_tlks.len() > 4096
        {
            return Err(Error::Security(
                "upload scope does not match the authenticated account and joined peer".into(),
            ));
        }
        Ok(Self {
            transport,
            binding,
            tlks: authenticated_tlks,
            client: crate::apple::http::apple_write_client(Duration::from_secs(45))?,
        })
    }
}
impl UploadIo for AppleUploadIo<'_, '_> {
    fn fetch_zone(
        &mut self,
        zone: &ZoneIdentity,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<Snapshot> {
        check()?;
        if zone != &self.binding.zone {
            return Err(invalid("fetch differs from the fixed upload scope"));
        }
        let snapshot = Snapshot::fetch_with(zone.clone(), self.tlks.clone(), |body| {
            check()?;
            let response = self.transport.fetch_records(body)?;
            check()?;
            Ok(response)
        })?;
        check()?;
        Ok(snapshot)
    }
    fn create_atomic(
        &mut self,
        attempt: Uuid,
        zone: &ZoneIdentity,
        record: &Record,
        unchanged_pointer: &Record,
        check: &dyn Fn() -> Result<()>,
    ) -> Result<SaveOutcome> {
        check()?;
        if zone != &self.binding.zone || record.name != self.binding.transaction.to_string() {
            return Err(invalid("save differs from the fixed upload scope"));
        }
        let save = AtomicSave::new(
            &self.transport.device,
            attempt,
            zone,
            record,
            unchanged_pointer,
        )?;
        let response = self.send_prepared_save(&save.body)?;
        check()?;
        let outcome = save.parse_response(&response)?;
        check()?;
        Ok(outcome)
    }
}

impl AppleUploadIo<'_, '_> {
    pub(crate) fn worker_binding(&self) -> &Binding {
        &self.binding
    }
    pub(crate) fn fetch_recoverable_shares(&self, body: &[u8]) -> Result<Vec<u8>> {
        if body
            != crate::apple::cuttlefish::encode_fetch_recoverable_tlkshares_request(
                &self.binding.peer_id,
            )
        {
            return Err(invalid(
                "recoverable-share request differs from enrolled peer",
            ));
        }
        self.transport.invoke("fetchRecoverableTLKShares", body)
    }
    pub(crate) fn fetch_page(&self, body: &[u8]) -> Result<Vec<u8>> {
        validate_worker_fetch(&self.binding, body)?;
        self.transport.fetch_records(body)
    }
    /// Only an authenticated broker channel may supply this prepared stream.
    pub(crate) fn send_prepared_save(&self, body: &[u8]) -> Result<Vec<u8>> {
        if body.is_empty() || body.len() > MAX_SAVE_BODY {
            return Err(invalid("prepared save stream exceeds bounds"));
        }
        AtomicSave::validate_prepared(&self.transport.device, &self.binding, body)?;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(body)
            .map_err(|e| Error::io("CloudKit save compression", e))?;
        let compressed = encoder
            .finish()
            .map_err(|e| Error::io("CloudKit save compression", e))?;
        let headers = self.transport.headers(SECURITYD_BUNDLE, None)?;
        let response = apply_headers(self.client.post(SAVE_URL), &headers)?
            .body(compressed)
            .send()?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::AuthenticationRequired("CloudKit rejected the upload token; refresh authentication before reconciling this attempt".into()));
        }
        if !status.is_success() {
            // No HTTP status proves that an earlier/partial write did not
            // commit. Return an error, retaining the journal's Attempted state.
            return Err(Error::Apple(format!(
                "CloudKit save returned HTTP {status}; reconcile before retrying"
            )));
        }
        let bytes = response_bytes(response)?;
        maybe_gunzip(&bytes)
    }
}

pub(crate) struct AtomicSave {
    pub(crate) body: Vec<u8>,
    operations: [Uuid; 2],
    zone: ZoneIdentity,
    item: Record,
    pointer: Record,
}
struct SaveReply {
    code: u64,
    client_error: Option<u64>,
    record: Option<Record>,
}
impl AtomicSave {
    pub(crate) fn new(
        device: &DeviceConfig,
        attempt: Uuid,
        zone: &ZoneIdentity,
        item: &Record,
        pointer: &Record,
    ) -> Result<Self> {
        Self::with_operations(device, [attempt, Uuid::new_v4()], zone, item, pointer)
    }

    fn with_operations(
        device: &DeviceConfig,
        operations: [Uuid; 2],
        zone: &ZoneIdentity,
        item: &Record,
        pointer: &Record,
    ) -> Result<Self> {
        let [attempt, compare_id] = operations;
        if attempt.get_version_num() != 4
            || compare_id.get_version_num() != 4
            || attempt == compare_id
            || zone.name != "Passwords"
            || zone.owner.is_empty()
            || zone.owner.len() > 512
            || pointer.name != "classA"
            || pointer.record_type != "currentkey"
            || item.server.is_some()
            || item.record_type != "item"
            || item.fields.len() != 5
            || item.integer("gen") != Some(0)
            || item.integer("encver") != Some(2)
            || !matches!(
                item.fields.get("parentkeyref"),
                Some(FieldValue::Reference(_))
            )
            || item.string("parentkeyref") != pointer.string("parentkeyref")
        {
            return Err(invalid(
                "only a new Passwords item and its unchanged class-A pointer may be saved",
            ));
        }
        crate::paths::validate_record_id(&item.name)?;
        let id = Uuid::parse_str(&item.name).map_err(|_| invalid("item UUID"))?;
        if id.get_version_num() != 4 {
            return Err(invalid("new item UUID must be v4"));
        }
        Uuid::parse_str(
            item.string("parentkeyref")
                .ok_or_else(|| invalid("parent key"))?,
        )
        .map_err(|_| invalid("parent key UUID"))?;
        let wrapped = item
            .string("wrappedkey")
            .and_then(|value| B64.decode(value).ok())
            .ok_or_else(|| invalid("wrapped item key"))?;
        if wrapped.len() != 80
            || item
                .bytes("data")
                .is_none_or(|data| !(32..=1024 * 1024 + 128).contains(&data.len()))
        {
            return Err(invalid("item ciphertext or wrapped-key bounds"));
        }
        let metadata = pointer.server_precondition(zone)?;
        validate_pointer_reference(
            &metadata.encoded_record,
            zone,
            item.string("parentkeyref")
                .ok_or_else(|| invalid("parent key"))?,
        )?;
        let tag = metadata
            .change_tag
            .as_deref()
            .ok_or_else(|| invalid("pointer change tag"))?;
        let create = Writer::new()
            .message(1, &encode_item(item, zone)?)
            .bool(2, true)
            .uint64(6, 2)
            .finish(); // FAIL_IF_EXISTS
        let compare = Writer::new()
            .message(1, &metadata.encoded_record)
            .bool(2, true)
            .string(4, tag)
            .uint64(6, 1)
            .finish(); // FAIL_IF_OUTDATED, never OVERRIDE=3
        // Same framed stream and ZONE isolation, with a header only on its first
        // request and an explicit final marker. Group 26 is an operation label.
        let mut header = build_header(device, CUTTLEFISH_CONTAINER, SECURITYD_BUNDLE);
        header.extend(Writer::new().string(26, "EphemeralGroup").finish());
        let mut body = Vec::new();
        for (index, request) in [create, compare].iter().enumerate() {
            let operation = Writer::new()
                .string(1, &operations[index].to_string().to_ascii_uppercase())
                .uint64(2, u64::from(SAVE))
                .bool(4, index == 1)
                .finish();
            let mut envelope = Writer::new();
            if index == 0 {
                envelope = envelope.message(1, &header);
            }
            let envelope = envelope
                .message(2, &operation)
                .message(SAVE, request)
                .finish();
            body.extend(encode_varint(envelope.len() as u64));
            body.extend(envelope);
        }
        if body.len() > MAX_SAVE_BODY {
            return Err(invalid("save stream exceeds its size bound"));
        }
        Ok(Self {
            body,
            operations,
            zone: zone.clone(),
            item: item.clone(),
            pointer: pointer.clone(),
        })
    }

    /// The worker independently restricts raw broker requests to this exact
    /// create/CAS shape, device, item UUID and zone. Re-encoding also detects
    /// fields/duplicates which the historical record reader would ignore.
    fn validate_prepared(device: &DeviceConfig, binding: &Binding, body: &[u8]) -> Result<()> {
        binding.validate()?;
        let messages = undelimit(body)?;
        if messages.len() != 2 {
            return Err(invalid("worker save must contain exactly two operations"));
        }
        let mut operations = [Uuid::nil(); 2];
        let mut records = Vec::with_capacity(2);
        for (index, message) in messages.iter().enumerate() {
            let envelope = decode_fields(message)?;
            let operation = decode_fields(required_bytes(&envelope, 2)?)?;
            operations[index] = Uuid::parse_str(&required_string(&operation, 1)?)
                .map_err(|_| invalid("worker operation UUID"))?;
            let save = decode_fields(required_bytes(&envelope, SAVE)?)?;
            records.push(ckks::parse_record(required_bytes(&save, 1)?)?);
        }
        if records[0].name != binding.transaction.to_string() {
            return Err(invalid("worker save item differs from transaction"));
        }
        records[0].server = None;
        let expected =
            Self::with_operations(device, operations, &binding.zone, &records[0], &records[1])?;
        if body != expected.body {
            return Err(invalid(
                "worker save differs from canonical scoped create/CAS request",
            ));
        }
        Ok(())
    }

    pub(crate) fn parse_response(&self, body: &[u8]) -> Result<SaveOutcome> {
        let messages = undelimit(body)?;
        if messages.len() != 2 {
            return Err(invalid(
                "save response must identify both operations exactly once",
            ));
        }
        let mut results: [Option<SaveReply>; 2] = [None, None];
        for raw in messages {
            let fields = decode_fields(raw)?;
            if fields.keys().any(|field| *field >= 200 && *field != SAVE) {
                return Err(invalid("unexpected operation payload in save response"));
            }
            let operation = decode_fields(required_bytes(&fields, 2)?)?;
            let id = Uuid::parse_str(&required_string(&operation, 1)?)
                .map_err(|_| invalid("response operation UUID"))?;
            let index = self
                .operations
                .iter()
                .position(|expected| expected == &id)
                .ok_or_else(|| invalid("unmatched save operation UUID"))?;
            if results[index].is_some() || required_u64(&operation, 2)? != u64::from(SAVE) {
                return Err(invalid("duplicate or wrong-type save operation"));
            }
            let result = decode_fields(required_bytes(&fields, 3)?)?;
            let code = required_u64(&result, 1)?;
            let client_code = if let Some(error) = optional_bytes(&result, 2)? {
                let error = decode_fields(error)?;
                if let Some(client) = optional_bytes(&error, 1)? {
                    Some(required_u64(&decode_fields(client)?, 1)?)
                } else {
                    None
                }
            } else {
                None
            };
            let record = if code == 1 {
                if optional_bytes(&result, 2)?.is_some() {
                    return Err(invalid("save success also contains an error"));
                }
                let save = decode_fields(required_bytes(&fields, SAVE)?)?;
                let record = ckks::parse_record(required_bytes(&save, 4)?)?;
                let metadata = record.server_precondition(&self.zone)?;
                if let Some(tag) = optional_bytes(&save, 2)? {
                    if Some(tag) != metadata.change_tag.as_deref().map(str::as_bytes) {
                        return Err(invalid("save response has contradictory change tags"));
                    }
                }
                let expected = if index == 0 {
                    &self.item
                } else {
                    &self.pointer
                };
                if record.name != expected.name
                    || record.record_type != expected.record_type
                    || expected
                        .fields
                        .iter()
                        .any(|(key, value)| record.fields.get(key) != Some(value))
                {
                    return Err(invalid(
                        "saved record differs from the requested identity or contents",
                    ));
                }
                Some(record)
            } else {
                if optional_bytes(&fields, SAVE)?.is_some() {
                    return Err(invalid("failed save also contains a record payload"));
                }
                None
            };
            results[index] = Some(SaveReply {
                code,
                client_error: client_code,
                record,
            });
        }
        let [Some(item), Some(pointer)] = results else {
            return Err(invalid("save response is incomplete"));
        };
        if item.code == 1 && pointer.code == 1 {
            return Ok(SaveOutcome::Accepted(
                item.record.ok_or_else(|| invalid("missing saved item"))?,
            ));
        }
        if [item.client_error, pointer.client_error]
            .iter()
            .any(|code| matches!(code, Some(11 | 12)))
        {
            return Err(Error::AuthenticationRequired(
                "CloudKit save requires renewed account authentication".into(),
            ));
        }
        // A mixed success/failure, partial or indeterminate response cannot prove
        // rejection of the entire batch. Retain Attempted and fetch/reconcile.
        if item.code == 3
            && pointer.code == 3
            && [item.client_error, pointer.client_error]
                .iter()
                .all(|code| matches!(code, Some(9 | 15 | 16)))
        {
            return Ok(SaveOutcome::PreconditionFailed);
        }
        Err(invalid(
            "save outcome is incomplete, mixed or indeterminate; reconcile before retrying",
        ))
    }
}

fn validate_worker_fetch(binding: &Binding, body: &[u8]) -> Result<()> {
    let fields = decode_fields(body)?;
    let cursor = optional_bytes(&fields, 1)?;
    if cursor.is_some_and(|cursor| cursor.len() > 16 * 1024)
        || body
            != ckks::build_retrieve_changes_request(
                &ckks::record_zone_identifier(&binding.zone.name, &binding.zone.owner),
                cursor,
                500,
            )
    {
        return Err(invalid("worker fetch differs from the fixed zone request"));
    }
    Ok(())
}

pub(crate) fn validate_pointer_reference(
    raw: &[u8],
    zone: &ZoneIdentity,
    parent: &str,
) -> Result<()> {
    fn check_zone(raw: &[u8], zone: &ZoneIdentity) -> Result<()> {
        let fields = decode_fields(raw)?;
        for (field, name, kind) in [(1, &zone.name, 6), (2, &zone.owner, 7)] {
            let id = decode_fields(required_bytes(&fields, field)?)?;
            if required_string(&id, 1)? != *name || required_u64(&id, 2)? != kind {
                return Err(invalid("pointer reference crosses zone/account boundaries"));
            }
        }
        if fields.contains_key(&3) && required_u64(&fields, 3)? != 1 {
            return Err(invalid(
                "pointer reference does not use the private database",
            ));
        }
        Ok(())
    }
    let fields = decode_fields(raw)?;
    let id = decode_fields(required_bytes(&fields, 2)?)?;
    check_zone(required_bytes(&id, 2)?, zone)?;
    let mut found = false;
    for value in fields.get(&7).into_iter().flatten() {
        let Value::Bytes(raw) = value else {
            return Err(invalid("invalid pointer field"));
        };
        let field = decode_fields(raw)?;
        let name = decode_fields(required_bytes(&field, 1)?)?;
        if required_string(&name, 1)? != "parentkeyref" {
            continue;
        }
        if found {
            return Err(invalid("duplicate pointer target"));
        }
        found = true;
        let value = decode_fields(required_bytes(&field, 2)?)?;
        let reference = decode_fields(required_bytes(&value, 9)?)?;
        let target = decode_fields(required_bytes(&reference, 2)?)?;
        let identifier = decode_fields(required_bytes(&target, 1)?)?;
        if required_string(&identifier, 1)? != parent || required_u64(&identifier, 2)? != 1 {
            return Err(invalid("pointer reference targets another key"));
        }
        check_zone(required_bytes(&target, 2)?, zone)?;
    }
    if !found {
        return Err(invalid("pointer has no reference target"));
    }
    Ok(())
}

fn record_id(name: &str, zone: &ZoneIdentity) -> Vec<u8> {
    Writer::new()
        .message(1, &identifier(name, 1))
        .message(2, &ckks::record_zone_identifier(&zone.name, &zone.owner))
        .finish()
}
fn encode_item(item: &Record, zone: &ZoneIdentity) -> Result<Vec<u8>> {
    let mut wire = Writer::new()
        .message(2, &record_id(&item.name, zone))
        .message(3, &Writer::new().string(1, &item.record_type).finish());
    for (name, value) in &item.fields {
        let value = match value {
            FieldValue::Bytes(data) => Writer::new().uint64(1, 1).bytes(2, data).finish(),
            FieldValue::String(text) => Writer::new().uint64(1, 3).string(7, text).finish(),
            FieldValue::Integer(value) => {
                Writer::new().uint64(1, 7).uint64(4, *value as u64).finish()
            }
            FieldValue::Reference(parent) => Writer::new()
                .uint64(1, 5)
                .message(
                    9,
                    &Writer::new()
                        .uint64(1, 3)
                        .message(2, &record_id(parent, zone))
                        .finish(),
                )
                .finish(), // VALIDATING
            _ => return Err(invalid("unsupported new-item field type")),
        };
        wire = wire.message(
            7,
            &Writer::new()
                .message(1, &Writer::new().string(1, name).finish())
                .message(2, &value)
                .finish(),
        );
    }
    Ok(wire.finish())
}
fn optional_bytes(fields: &Fields, field: u32) -> Result<Option<&[u8]>> {
    match fields.get(&field).map(Vec::as_slice) {
        None => Ok(None),
        Some([Value::Bytes(value)]) => Ok(Some(value)),
        _ => Err(invalid("ambiguous singular response field")),
    }
}
fn required_bytes(fields: &Fields, field: u32) -> Result<&[u8]> {
    optional_bytes(fields, field)?.ok_or_else(|| invalid("missing response field"))
}
fn required_string(fields: &Fields, field: u32) -> Result<String> {
    std::str::from_utf8(required_bytes(fields, field)?)
        .map(str::to_owned)
        .map_err(|_| invalid("invalid response string"))
}
fn required_u64(fields: &Fields, field: u32) -> Result<u64> {
    match fields.get(&field).map(Vec::as_slice) {
        Some([Value::Varint(value)]) => Ok(*value),
        _ => Err(invalid("missing or ambiguous integer response field")),
    }
}
fn invalid(message: &str) -> Error {
    Error::InvalidData(format!("CloudKit atomic save: {message}"))
}

#[cfg(test)]
mod tests;
