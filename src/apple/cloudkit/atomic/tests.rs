//! Offline wire-policy fixtures, not captured Apple traffic or acceptance proof.
use super::*;
use crate::apple::ckks::test_support::server_record;

fn fixture() -> Result<AtomicSave> {
    let zone = ZoneIdentity {
        name: "Passwords".into(),
        owner: "synthetic-owner".into(),
    };
    let parent = Uuid::new_v4().to_string();
    let item = Record {
        name: Uuid::new_v4().to_string(),
        record_type: "item".into(),
        server: None,
        fields: BTreeMap::from([
            ("parentkeyref".into(), FieldValue::Reference(parent.clone())),
            (
                "wrappedkey".into(),
                FieldValue::String(B64.encode([7u8; 80])),
            ),
            ("data".into(), FieldValue::Bytes(vec![8u8; 48])),
            ("gen".into(), FieldValue::Integer(0)),
            ("encver".into(), FieldValue::Integer(2)),
        ]),
    };
    let pointer = server_record(
        &Record {
            name: "classA".into(),
            record_type: "currentkey".into(),
            server: None,
            fields: BTreeMap::from([("parentkeyref".into(), FieldValue::Reference(parent))]),
        },
        &zone,
        "original-pointer",
    )?;
    AtomicSave::new(&device(), Uuid::new_v4(), &zone, &item, &pointer)
}
fn device() -> DeviceConfig {
    DeviceConfig {
        device_uuid: Uuid::new_v4().to_string(),
        serial: "synthetic-serial".into(),
        name: "Test".into(),
    }
}

#[test]
fn worker_checks_raw_request_scope_and_canonical_create_cas_before_http() -> Result<()> {
    let original = fixture()?;
    let device = device();
    let save = AtomicSave::new(
        &device,
        Uuid::new_v4(),
        &original.zone,
        &original.item,
        &original.pointer,
    )?;
    let binding = Binding {
        owner: 1001,
        account_fingerprint: format!("SHA256:{}", B64.encode([1; 32])),
        peer_id: format!("SHA256:{}", B64.encode([2; 32])),
        transaction: Uuid::parse_str(&save.item.name).map_err(|_| invalid("test transaction"))?,
        request_sha256: "ab".repeat(32),
        zone: save.zone.clone(),
    };
    AtomicSave::validate_prepared(&device, &binding, &save.body)?;
    for case in 0..4 {
        let mut scope = binding.clone();
        let mut device = device.clone();
        match case {
            0 => scope.zone.owner = "other-owner".into(),
            1 => scope.zone.name = "Manatee".into(),
            2 => scope.transaction = Uuid::new_v4(),
            _ => device.device_uuid = Uuid::new_v4().to_string(),
        }
        assert!(AtomicSave::validate_prepared(&device, &scope, &save.body).is_err());
    }
    let messages = undelimit(&save.body)?;
    let first = decode_fields(messages[0])?;
    let second = decode_fields(messages[1])?;
    let create = decode_fields(required_bytes(&first, SAVE)?)?;
    let wrong_mode = Writer::new()
        .message(1, required_bytes(&create, 1)?)
        .bool(2, true)
        .uint64(6, 3)
        .finish();
    let first_wrong = Writer::new()
        .message(1, required_bytes(&first, 1)?)
        .message(2, required_bytes(&first, 2)?)
        .message(SAVE, &wrong_mode)
        .finish();
    assert!(
        AtomicSave::validate_prepared(
            &device,
            &binding,
            &frame(&[first_wrong, messages[1].to_vec()])
        )
        .is_err()
    );
    let extra = Writer::new()
        .message(2, required_bytes(&second, 2)?)
        .message(SAVE, required_bytes(&second, SAVE)?)
        .bool(999, true)
        .finish();
    assert!(
        AtomicSave::validate_prepared(&device, &binding, &frame(&[messages[0].to_vec(), extra]))
            .is_err()
    );

    let zone = ckks::record_zone_identifier(&binding.zone.name, &binding.zone.owner);
    for cursor in [None, Some(b"cursor".as_slice())] {
        validate_worker_fetch(
            &binding,
            &ckks::build_retrieve_changes_request(&zone, cursor, 500),
        )?;
    }
    for body in [
        ckks::build_retrieve_changes_request(
            &ckks::record_zone_identifier("Manatee", &binding.zone.owner),
            None,
            500,
        ),
        ckks::build_retrieve_changes_request(&zone, None, 501),
        ckks::build_retrieve_changes_request(&zone, Some(&vec![0; 16385]), 500),
        Writer::new()
            .message(2, &zone)
            .uint64(4, 500)
            .bool(999, true)
            .finish(),
    ] {
        assert!(validate_worker_fetch(&binding, &body).is_err());
    }
    Ok(())
}
fn frame(messages: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for message in messages {
        body.extend(encode_varint(message.len() as u64));
        body.extend(message);
    }
    body
}
fn reply(
    save: &AtomicSave,
    index: usize,
    code: u64,
    client: Option<u64>,
    record: Option<&Record>,
) -> Result<Vec<u8>> {
    let operation = Writer::new()
        .string(1, &save.operations[index].to_string().to_ascii_uppercase())
        .uint64(2, u64::from(SAVE))
        .bool(4, index == 1)
        .finish();
    let mut status = Writer::new().uint64(1, code);
    if let Some(client) = client {
        status = status.message(
            2,
            &Writer::new()
                .message(1, &Writer::new().uint64(1, client).finish())
                .finish(),
        );
    }
    let mut wire = Writer::new()
        .message(2, &operation)
        .message(3, &status.finish());
    if let Some(record) = record {
        let server = server_record(record, &save.zone, "saved-tag")?;
        let server = server
            .server
            .as_ref()
            .ok_or_else(|| invalid("test server record"))?;
        wire = wire.message(
            SAVE,
            &Writer::new()
                .string(2, "saved-tag")
                .message(4, &server.encoded_record)
                .finish(),
        );
    }
    Ok(wire.finish())
}

#[test]
fn request_uses_create_only_and_cas_in_one_zone_stream_without_dropping_opaque_pointer_bytes()
-> Result<()> {
    let save = fixture()?;
    let messages = undelimit(&save.body)?;
    assert_eq!(messages.len(), 2);
    let first = decode_fields(messages[0])?;
    let second = decode_fields(messages[1])?;
    let header = decode_fields(required_bytes(&first, 1)?)?;
    assert_eq!(required_u64(&header, 25)?, 1); // ZONE isolation
    assert_eq!(required_u64(&header, 23)?, 1); // PRIVATE_DB
    assert_eq!(required_string(&header, 2)?, CUTTLEFISH_CONTAINER);
    assert_eq!(required_string(&header, 3)?, SECURITYD_BUNDLE);
    assert!(!second.contains_key(&1));
    let mut seen = BTreeMap::new();
    for (index, message) in [first, second].iter().enumerate() {
        let operation = decode_fields(required_bytes(message, 2)?)?;
        assert_eq!(required_u64(&operation, 2)?, 210);
        assert_eq!(required_u64(&operation, 4)?, u64::from(index == 1));
        let id = required_string(&operation, 1)?;
        assert!(seen.insert(id, index).is_none());
        let request = decode_fields(required_bytes(message, 210)?)?;
        assert_eq!(required_u64(&request, 6)?, if index == 0 { 2 } else { 1 });
        assert_eq!(required_u64(&request, 2)?, 1);
        let record = required_bytes(&request, 1)?;
        if index == 0 {
            assert!(!request.contains_key(&4));
            let parsed = ckks::parse_record(record)?;
            assert_eq!(parsed.name, save.item.name);
            assert_eq!(parsed.fields, save.item.fields);
            assert!(parsed.server.is_some_and(|meta| meta.change_tag.is_none()));
            // Validate the discriminants/actions independently of the reader,
            // whose historical parser tolerates their omission in read replies.
            let fields = decode_fields(record)?;
            for raw in fields.get(&7).into_iter().flatten() {
                let Value::Bytes(raw) = raw else {
                    panic!("field wire type");
                };
                let field = decode_fields(raw)?;
                let name = required_string(&decode_fields(required_bytes(&field, 1)?)?, 1)?;
                let value = decode_fields(required_bytes(&field, 2)?)?;
                let expected = match name.as_str() {
                    "data" => 1,
                    "wrappedkey" => 3,
                    "parentkeyref" => 5,
                    _ => 7,
                };
                assert_eq!(required_u64(&value, 1)?, expected);
                if name == "parentkeyref" {
                    assert_eq!(
                        required_u64(&decode_fields(required_bytes(&value, 9)?)?, 1)?,
                        3
                    ); // VALIDATING
                }
            }
        } else {
            assert_eq!(required_string(&request, 4)?, "original-pointer");
            assert_eq!(
                record,
                save.pointer.server_precondition(&save.zone)?.encoded_record
            );
            assert_eq!(
                required_bytes(&decode_fields(record)?, 999)?,
                b"opaque future server metadata"
            );
        }
    }
    Ok(())
}

#[test]
fn save_scope_refuses_existing_items_changed_pointers_and_cross_zone_references() -> Result<()> {
    let save = fixture()?;
    for case in 0..6 {
        let mut item = save.item.clone();
        let mut pointer = save.pointer.clone();
        let mut zone = save.zone.clone();
        match case {
            0 => zone.owner = "another-owner".into(),
            1 => zone.name = "Manatee".into(),
            2 => item = server_record(&item, &zone, "already-exists")?,
            3 => {
                item.fields.insert("gen".into(), FieldValue::Integer(1));
            }
            4 => {
                pointer.fields.insert(
                    "parentkeyref".into(),
                    FieldValue::Reference(Uuid::new_v4().to_string()),
                );
            }
            _ => {
                item.fields.insert(
                    "data".into(),
                    FieldValue::Bytes(vec![0u8; 1024 * 1024 + 129]),
                );
            }
        }
        assert!(AtomicSave::new(&device(), Uuid::new_v4(), &zone, &item, &pointer).is_err());
    }
    let parent = save
        .item
        .string("parentkeyref")
        .ok_or_else(|| invalid("test parent"))?;
    let foreign_zone = ZoneIdentity {
        owner: "another-owner".into(),
        ..save.zone.clone()
    };
    let foreign_parent = Writer::new()
        .message(
            9,
            &Writer::new()
                .uint64(1, 2)
                .message(2, &record_id(parent, &foreign_zone))
                .finish(),
        )
        .finish();
    let pointer = Writer::new()
        .string(1, "original-pointer")
        .message(2, &record_id("classA", &save.zone))
        .message(3, &Writer::new().string(1, "currentkey").finish())
        .message(
            7,
            &Writer::new()
                .message(1, &Writer::new().string(1, "parentkeyref").finish())
                .message(2, &foreign_parent)
                .finish(),
        )
        .finish();
    let pointer = ckks::parse_record(&pointer)?;
    assert_eq!(pointer.fields, save.pointer.fields); // Legacy projection loses target zone.
    assert!(pointer.server_precondition(&save.zone).is_ok());
    assert!(AtomicSave::new(&device(), Uuid::new_v4(), &save.zone, &save.item, &pointer).is_err());
    Ok(())
}

#[test]
fn response_requires_both_matching_successes_and_accepts_out_of_order_replies() -> Result<()> {
    let save = fixture()?;
    let item = reply(&save, 0, 1, None, Some(&save.item))?;
    let pointer = reply(&save, 1, 1, None, Some(&save.pointer))?;
    for messages in [
        [item.clone(), pointer.clone()],
        [pointer.clone(), item.clone()],
    ] {
        let SaveOutcome::Accepted(saved) = save.parse_response(&frame(&messages))? else {
            panic!("not accepted");
        };
        assert_eq!(saved.name, save.item.name);
        assert_eq!(saved.fields, save.item.fields);
    }
    for messages in [
        vec![],
        vec![item.clone()],
        vec![item.clone(), item.clone()],
        vec![item.clone(), pointer.clone(), pointer.clone()],
    ] {
        assert!(save.parse_response(&frame(&messages)).is_err());
    }
    let mut duplicate = item.clone();
    duplicate.extend(
        Writer::new()
            .message(3, &Writer::new().uint64(1, 1).finish())
            .finish(),
    );
    assert!(
        save.parse_response(&frame(&[duplicate, pointer.clone()]))
            .is_err()
    );
    let mut wrong_operation = item.clone();
    wrong_operation.extend(
        Writer::new()
            .message(
                2,
                &Writer::new()
                    .string(1, &Uuid::new_v4().to_string())
                    .uint64(2, 210)
                    .finish(),
            )
            .finish(),
    );
    assert!(
        save.parse_response(&frame(&[wrong_operation, pointer.clone()]))
            .is_err()
    );
    let missing_status = Writer::new()
        .message(
            2,
            &Writer::new()
                .string(1, &save.operations[0].to_string())
                .uint64(2, 210)
                .finish(),
        )
        .message(3, &[])
        .finish();
    assert!(
        save.parse_response(&frame(&[missing_status, pointer]))
            .is_err()
    );
    assert!(save.parse_response(&[0x80]).is_err());
    Ok(())
}

#[test]
fn mixed_partial_indeterminate_and_auth_failures_never_become_definite_rejections() -> Result<()> {
    let save = fixture()?;
    for codes in [(9, 16), (16, 15)] {
        let body = frame(&[
            reply(&save, 0, 3, Some(codes.0), None)?,
            reply(&save, 1, 3, Some(codes.1), None)?,
        ]);
        assert!(matches!(
            save.parse_response(&body)?,
            SaveOutcome::PreconditionFailed
        ));
    }
    let success = reply(&save, 0, 1, None, Some(&save.item))?;
    assert!(
        save.parse_response(&frame(&[success, reply(&save, 1, 3, Some(15), None)?]))
            .is_err()
    );
    for status in [2, 4, 999] {
        assert!(
            save.parse_response(&frame(&[
                reply(&save, 0, status, Some(15), None)?,
                reply(&save, 1, 3, Some(16), None)?
            ]))
            .is_err()
        );
    }
    for code in [5, 11, 12, 999] {
        let result = save.parse_response(&frame(&[
            reply(&save, 0, 3, Some(code), None)?,
            reply(&save, 1, 3, Some(16), None)?,
        ]));
        assert!(result.is_err());
        if matches!(code, 11 | 12) {
            assert!(matches!(result, Err(Error::AuthenticationRequired(_))));
        }
    }
    Ok(())
}

#[test]
fn success_with_wrong_record_contents_or_contradictory_tags_is_refused() -> Result<()> {
    let save = fixture()?;
    let pointer = reply(&save, 1, 1, None, Some(&save.pointer))?;
    for case in 0..3 {
        let mut item = save.item.clone();
        match case {
            0 => item.name = Uuid::new_v4().to_string(),
            1 => item.record_type = "synckey".into(),
            _ => {
                item.fields
                    .insert("data".into(), FieldValue::Bytes(vec![9u8; 48]));
            }
        }
        assert!(
            save.parse_response(&frame(&[
                reply(&save, 0, 1, None, Some(&item))?,
                pointer.clone()
            ]))
            .is_err()
        );
    }
    let item = server_record(&save.item, &save.zone, "tag-one")?;
    let raw = item
        .server
        .as_ref()
        .ok_or_else(|| invalid("test metadata"))?;
    let wrong_tag = Writer::new()
        .message(
            2,
            &Writer::new()
                .string(1, &save.operations[0].to_string())
                .uint64(2, 210)
                .finish(),
        )
        .message(3, &Writer::new().uint64(1, 1).finish())
        .message(
            210,
            &Writer::new()
                .string(2, "tag-two")
                .message(4, &raw.encoded_record)
                .finish(),
        )
        .finish();
    assert!(save.parse_response(&frame(&[wrong_tag, pointer])).is_err());
    Ok(())
}

#[test]
fn upload_adapter_binds_authenticated_account_joined_peer_and_record_without_network_access()
-> Result<()> {
    use crate::model::{AccountState, DeviceIdentity, MobileMeState, SignedInfoState};
    use crate::security::{KeyAlgorithm, KeyRef, KeyUsage};
    struct NoNetwork;
    impl AnisetteProvider for NoNetwork {
        fn headers(&self) -> Result<BTreeMap<String, String>> {
            panic!("scope validation contacted anisette");
        }
    }
    let mut mobileme = MobileMeState::default();
    mobileme.cloudkit_user_id = Some("synthetic-owner".into());
    mobileme
        .tokens
        .insert("cloudKitToken".into(), "synthetic-token".into());
    let account = AccountState {
        schema_version: 1,
        username: "synthetic@example.com".into(),
        adsid: "synthetic-adsid".into(),
        logged_in_at: 0,
        mobileme,
        webservices: BTreeMap::new(),
    };
    let device = DeviceIdentity {
        schema_version: 1,
        device_id: Uuid::new_v4().to_string(),
        serial: "synthetic".into(),
        local_user_uuid: Uuid::new_v4().to_string(),
    };
    let transport = CloudKitTransport::new(&account, &device, &NoNetwork)?;
    let key = KeyRef {
        backend_id: "synthetic".into(),
        key_id: "unused".into(),
        usage: KeyUsage::Signing,
        algorithm: KeyAlgorithm::P384,
    };
    let peer = OctagonState {
        schema_version: 1,
        account_fingerprint: transport.account_fingerprint.clone(),
        peer_id: format!("SHA256:{}", B64.encode([2u8; 32])),
        signing_key: key.clone(),
        encryption_key: key,
        permanent: SignedInfoState {
            data_b64: String::new(),
            signature_b64: String::new(),
        },
        trust_state: OctagonTrustState::Joined,
        created_at: 0,
    };
    let binding = Binding {
        owner: 1001,
        account_fingerprint: peer.account_fingerprint.clone(),
        peer_id: peer.peer_id.clone(),
        transaction: Uuid::new_v4(),
        request_sha256: "a1".repeat(32),
        zone: ZoneIdentity {
            name: "Passwords".into(),
            owner: transport.user_id.clone(),
        },
    };
    let mut adapter = AppleUploadIo::new(&transport, &peer, binding.clone(), vec![])?;
    let save = fixture()?;
    assert!(
        adapter
            .create_atomic(Uuid::new_v4(), &save.zone, &save.item, &save.pointer)
            .is_err()
    );
    let mut changed = peer.clone();
    changed.trust_state = OctagonTrustState::IdentityReady;
    assert!(AppleUploadIo::new(&transport, &changed, binding.clone(), vec![]).is_err());
    for case in 0..3 {
        let mut changed = binding.clone();
        match case {
            0 => changed.zone.owner = "other-owner".into(),
            1 => changed.account_fingerprint = format!("SHA256:{}", B64.encode([9u8; 32])),
            _ => changed.peer_id = format!("SHA256:{}", B64.encode([9u8; 32])),
        }
        assert!(AppleUploadIo::new(&transport, &peer, changed, vec![]).is_err());
    }
    Ok(())
}
