use crate::proto::{Fields, Value, Writer, decode_fields, first_bytes, first_string};
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBlob {
    pub info: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedBlob {
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .bytes(1, &self.info)
            .bytes(2, &self.signature)
            .finish()
    }

    pub fn parse(raw: &[u8]) -> Result<Self> {
        let fields = decode_fields(raw)?;
        Ok(Self {
            info: first_bytes(&fields, 1).unwrap_or_default().to_vec(),
            signature: first_bytes(&fields, 2).unwrap_or_default().to_vec(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub peer_id: String,
    pub permanent: Option<SignedBlob>,
    pub stable: Option<SignedBlob>,
    pub dynamic: Option<SignedBlob>,
    pub voucher: Option<SignedBlob>,
}

pub fn encode_peer(
    peer_id: &str,
    permanent: &SignedBlob,
    stable: &SignedBlob,
    dynamic: &SignedBlob,
    voucher: Option<&SignedBlob>,
) -> Vec<u8> {
    let mut writer = Writer::new()
        .string(1, peer_id)
        .message(2, &permanent.encode())
        .message(3, &stable.encode())
        .message(4, &dynamic.encode());
    if let Some(voucher) = voucher {
        writer = writer.message(5, &voucher.encode());
    }
    writer.finish()
}

pub fn parse_peer(raw: &[u8]) -> Result<Peer> {
    let fields = decode_fields(raw)?;
    Ok(Peer {
        peer_id: first_string(&fields, 1)?.unwrap_or_default(),
        permanent: parse_optional_signed(&fields, 2)?,
        stable: parse_optional_signed(&fields, 3)?,
        dynamic: parse_optional_signed(&fields, 4)?,
        voucher: parse_optional_signed(&fields, 5)?,
    })
}

fn parse_optional_signed(fields: &Fields, field: u32) -> Result<Option<SignedBlob>> {
    first_bytes(fields, field)
        .map(SignedBlob::parse)
        .transpose()
}

pub fn encode_voucher(reason: u64, beneficiary: &str, sponsor: &str) -> Vec<u8> {
    Writer::new()
        .uint64(1, reason)
        .string(2, beneficiary)
        .string(3, sponsor)
        .finish()
}

pub fn encode_fetch_changes_request(sync_token: Option<&str>) -> Vec<u8> {
    match sync_token {
        Some(token) => Writer::new().string(1, token).finish(),
        None => Vec::new(),
    }
}

#[derive(Clone, Debug)]
pub struct Changes {
    pub sync_token: Option<String>,
    pub peers: Vec<Peer>,
}

pub fn parse_fetch_changes_response(raw: &[u8]) -> Result<Changes> {
    let outer = decode_fields(raw)?;
    let Some(changes_raw) = first_bytes(&outer, 1) else {
        return Ok(Changes {
            sync_token: None,
            peers: Vec::new(),
        });
    };
    let fields = decode_fields(changes_raw)?;
    let mut peers = Vec::new();
    for change in repeated_bytes(&fields, 2) {
        let change = decode_fields(change)?;
        if let Some(add) = first_bytes(&change, 3) {
            peers.push(parse_peer(add)?);
        }
    }
    Ok(Changes {
        sync_token: first_string(&fields, 1)?,
        peers,
    })
}

pub fn encode_serialized_key(uuid: &str, zone_name: &str, keyclass: &str, key: &[u8]) -> Vec<u8> {
    Writer::new()
        .string(1, uuid)
        .string(2, zone_name)
        .string(3, keyclass)
        .bytes(4, key)
        .finish()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlkShare {
    pub service: String,
    pub curve: u64,
    pub epoch: u64,
    pub key_id: String,
    pub receiver: String,
    pub receiver_public_encryption_key: String,
    pub sender: String,
    pub signature: String,
    pub wrapped_key: String,
}

impl TlkShare {
    pub fn encode(&self) -> Vec<u8> {
        Writer::new()
            .string(1, &self.service)
            .uint64(2, self.curve)
            .uint64(3, self.epoch)
            .string(4, &self.key_id)
            .string(6, &self.receiver)
            .string(7, &self.receiver_public_encryption_key)
            .string(8, &self.sender)
            .string(9, &self.signature)
            .string(11, &self.wrapped_key)
            .finish()
    }
}

pub fn tlkshare_signing_data(
    receiver: &str,
    sender: &str,
    wrapped_key: &[u8],
    curve: u64,
    epoch: u64,
    poisoned: u64,
    version: u64,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + receiver.len() + sender.len() + wrapped_key.len());
    data.extend_from_slice(&version.to_le_bytes());
    data.extend_from_slice(receiver.as_bytes());
    data.extend_from_slice(sender.as_bytes());
    data.extend_from_slice(wrapped_key);
    data.extend_from_slice(&curve.to_le_bytes());
    data.extend_from_slice(&epoch.to_le_bytes());
    data.extend_from_slice(&poisoned.to_le_bytes());
    data
}

pub fn encode_join_with_voucher_request(
    peer: &[u8],
    restore_point: Option<&str>,
    shares: &[Vec<u8>],
) -> Vec<u8> {
    let mut writer = Writer::new();
    if let Some(point) = restore_point {
        writer = writer.string(1, point);
    }
    writer = writer.message(2, peer);
    for share in shares {
        writer = writer.message(4, share);
    }
    writer.finish()
}

pub fn encode_update_trust_request(
    peer_id: &str,
    restore_point: Option<&str>,
    shares: &[Vec<u8>],
) -> Vec<u8> {
    let mut writer = Writer::new();
    if let Some(point) = restore_point {
        writer = writer.string(1, point);
    }
    writer = writer.string(2, peer_id);
    for share in shares {
        writer = writer.message(5, share);
    }
    writer.finish()
}

pub fn encode_fetch_recoverable_tlkshares_request(peer_id: &str) -> Vec<u8> {
    Writer::new().string(1, peer_id).finish()
}

#[derive(Clone, Debug)]
pub struct RecoverableShares {
    pub share_records: Vec<Vec<u8>>,
    pub synckey_records: Vec<Vec<u8>>,
}

pub fn parse_recoverable_tlkshares_response(raw: &[u8]) -> Result<RecoverableShares> {
    let fields = decode_fields(raw)?;
    let mut shares = Vec::new();
    let mut synckeys = Vec::new();
    for group_raw in repeated_bytes(&fields, 1) {
        let group = decode_fields(group_raw)?;
        if let Some(record) = first_bytes(&group, 3).and_then(inner_record).transpose()? {
            shares.push(record);
        }
        if let Some(keys_raw) = first_bytes(&group, 2) {
            let keys = decode_fields(keys_raw)?;
            for field in [1_u32, 2, 3] {
                if let Some(record) = first_bytes(&keys, field)
                    .and_then(inner_record)
                    .transpose()?
                {
                    synckeys.push(record);
                }
            }
        }
    }
    Ok(RecoverableShares {
        share_records: shares,
        synckey_records: synckeys,
    })
}

fn inner_record(raw: &[u8]) -> Option<Result<Vec<u8>>> {
    Some(decode_fields(raw).and_then(|fields| {
        first_bytes(&fields, 2)
            .map(ToOwned::to_owned)
            .ok_or_else(|| Error::InvalidData("missing inner Cuttlefish record".into()))
    }))
}

pub fn encode_function_invoke_request(service: &str, name: &str, parameters: &[u8]) -> Vec<u8> {
    Writer::new()
        .string(1, service)
        .string(2, name)
        .bytes(3, parameters)
        .finish()
}

fn repeated_bytes(fields: &Fields, field: u32) -> impl Iterator<Item = &[u8]> {
    fields
        .get(&field)
        .into_iter()
        .flatten()
        .filter_map(|value| match value {
            Value::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_blob_round_trip() {
        let blob = SignedBlob {
            info: vec![1, 2],
            signature: vec![3, 4],
        };
        assert_eq!(
            SignedBlob::parse(&blob.encode()).unwrap_or_else(|e| panic!("parse: {e}")),
            blob
        );
    }

    #[test]
    fn voucher_fields() {
        let raw = encode_voucher(1, "new", "old");
        let fields = decode_fields(&raw).unwrap_or_else(|e| panic!("decode: {e}"));
        assert_eq!(
            first_string(&fields, 2).unwrap_or_else(|e| panic!("string: {e}")),
            Some("new".into())
        );
    }

    #[test]
    fn join_and_update_trust_encode_tlkshares_in_their_distinct_fields() {
        let shares = vec![b"share-one".to_vec(), b"share-two".to_vec()];
        let join = encode_join_with_voucher_request(b"peer", Some("token"), &shares);
        let join = decode_fields(&join).unwrap_or_else(|e| panic!("decode join: {e}"));
        assert_eq!(
            repeated_bytes(&join, 4).collect::<Vec<_>>(),
            [&b"share-one"[..], &b"share-two"[..]]
        );

        let update = encode_update_trust_request("peer-id", Some("token"), &shares);
        let update = decode_fields(&update).unwrap_or_else(|e| panic!("decode update: {e}"));
        assert_eq!(
            repeated_bytes(&update, 5).collect::<Vec<_>>(),
            [&b"share-one"[..], &b"share-two"[..]]
        );
        assert_eq!(
            first_string(&update, 2).unwrap_or_else(|e| panic!("peer: {e}")),
            Some("peer-id".into())
        );
    }

    #[test]
    fn serialized_key_uses_cuttlefish_fields() {
        let raw = encode_serialized_key("uuid", "Passwords", "tlk", &[7; 64]);
        let fields = decode_fields(&raw).unwrap_or_else(|e| panic!("decode: {e}"));
        assert_eq!(
            first_string(&fields, 1).unwrap_or_else(|e| panic!("uuid: {e}")),
            Some("uuid".into())
        );
        assert_eq!(
            first_string(&fields, 2).unwrap_or_else(|e| panic!("zone: {e}")),
            Some("Passwords".into())
        );
        assert_eq!(
            first_string(&fields, 3).unwrap_or_else(|e| panic!("class: {e}")),
            Some("tlk".into())
        );
        assert_eq!(first_bytes(&fields, 4), Some(&[7; 64][..]));
    }

    #[test]
    fn tlkshare_signature_input_uses_little_endian_counters() {
        let data = tlkshare_signing_data("receiver", "sender", &[1, 2], 4, 1, 0, 0);
        assert_eq!(&data[..8], &[0; 8]);
        assert_eq!(&data[8..16], b"receiver");
        assert_eq!(&data[16..22], b"sender");
        assert_eq!(&data[22..24], &[1, 2]);
        assert_eq!(&data[24..32], &4_u64.to_le_bytes());
        assert_eq!(&data[32..40], &1_u64.to_le_bytes());
        assert_eq!(&data[40..48], &[0; 8]);
    }

    #[test]
    fn fetch_changes_parses_added_peer() {
        let peer = encode_peer(
            "SHA256:peer",
            &SignedBlob {
                info: b"permanent".to_vec(),
                signature: b"p-sig".to_vec(),
            },
            &SignedBlob {
                info: b"stable".to_vec(),
                signature: b"s-sig".to_vec(),
            },
            &SignedBlob {
                info: b"dynamic".to_vec(),
                signature: b"d-sig".to_vec(),
            },
            None,
        );
        let change = Writer::new().message(3, &peer).finish();
        let changes = Writer::new()
            .string(1, "new-token")
            .message(2, &change)
            .finish();
        let response = Writer::new().message(1, &changes).finish();
        let parsed = parse_fetch_changes_response(&response)
            .unwrap_or_else(|error| panic!("parse: {error}"));
        assert_eq!(parsed.sync_token.as_deref(), Some("new-token"));
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(parsed.peers[0].peer_id, "SHA256:peer");
        assert_eq!(
            parsed.peers[0]
                .permanent
                .as_ref()
                .map(|blob| blob.info.as_slice()),
            Some(b"permanent".as_slice())
        );
    }

    #[test]
    fn recoverable_response_unwraps_share_and_view_keys() {
        let record = |inner: &[u8]| Writer::new().message(2, inner).finish();
        let view_keys = Writer::new()
            .message(2, &record(b"CLASS-A"))
            .message(3, &record(b"CLASS-B"))
            .finish();
        let group = Writer::new()
            .string(1, "Passwords")
            .message(2, &view_keys)
            .message(3, &record(b"SHARE"))
            .finish();
        let response = Writer::new().message(1, &group).message(1, &group).finish();
        let parsed = parse_recoverable_tlkshares_response(&response)
            .unwrap_or_else(|error| panic!("parse: {error}"));
        assert_eq!(parsed.share_records, [b"SHARE".to_vec(), b"SHARE".to_vec()]);
        assert_eq!(
            parsed.synckey_records,
            [
                b"CLASS-A".to_vec(),
                b"CLASS-B".to_vec(),
                b"CLASS-A".to_vec(),
                b"CLASS-B".to_vec()
            ]
        );
    }
}
