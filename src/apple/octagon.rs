use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use p384::ecdsa::signature::Verifier;
use p384::ecdsa::{Signature, VerifyingKey};
use p384::pkcs8::DecodePublicKey;
use zeroize::Zeroizing;

use super::ckks::{self, Record};
use super::cloudkit::CloudKitTransport;
use super::crypto::ecies_encrypt;
use super::cuttlefish::{
    Changes, SignedBlob, TlkShare, encode_fetch_changes_request,
    encode_fetch_recoverable_tlkshares_request, encode_join_with_voucher_request, encode_peer,
    encode_serialized_key, encode_update_trust_request, parse_fetch_changes_response,
    parse_recoverable_tlkshares_response, tlkshare_signing_data,
};
use super::escrow::{Bottle, RecoveredIdentity};
use super::octagon_keys::{
    DYNAMIC_INFO_SIG_TYPE, PEER_MODEL_ID, PEER_OS_VERSION, PERMANENT_INFO_SIG_TYPE, PeerKeySet,
    build_dynamic_info, build_permanent_info, build_stable_info, prefixed_data, tphash_sha256,
};
use super::pipeline;
use crate::credential;
use crate::model::{
    AccountState, DeviceIdentity, OctagonState, OctagonTrustState, SignedInfoState,
};
use crate::proto::{Value, Writer, decode_fields, first_bytes, first_string, first_u64};
use crate::security::{KeyRef, SecurityBackend};
use crate::{Error, Result};

pub const PASSWORD_ZONES: &[&str] = &["Passwords", "Manatee"];
const ESCROW_RECORD_PREFIX: &str = "com.apple.icdp.record.";
type RecoveredKeys = (Vec<pipeline::RecoveredTlk>, Vec<Record>);

pub enum JoinOutcome {
    SponsorRetirementReady {
        uploaded_tlk_shares: usize,
    },
    AwaitingSelfShareVerification {
        uploaded_tlk_shares: usize,
        reason: String,
    },
}

#[derive(Clone)]
struct SponsorContext {
    peer_id: String,
    escrow_record_label: String,
    signing_key: Option<KeyRef>,
    encryption_key: KeyRef,
}

#[derive(Clone, Debug)]
pub struct ViableBottle {
    pub record_label: String,
    pub encoded: Vec<u8>,
}

pub fn ensure_peer_identity(
    existing: Option<OctagonState>,
    account: &AccountState,
    device: &DeviceIdentity,
    backend: &dyn SecurityBackend,
) -> Result<(OctagonState, bool)> {
    let fingerprint = account_fingerprint(account);
    if let Some(state) = existing {
        if state.account_fingerprint != fingerprint {
            return Err(Error::Security(
                "stored Octagon identity belongs to a different Apple account; log out with --forget-device before switching accounts".into(),
            ));
        }
        return Ok((state, false));
    }
    let keys = PeerKeySet::generate(backend)?;
    let created_at = unix_now();
    let permanent = match build_permanent_info(
        backend,
        &keys,
        &device.device_id,
        PEER_MODEL_ID,
        1,
        created_at as u64,
    ) {
        Ok(permanent) => permanent,
        Err(error) => {
            let _ = backend.destroy_key(&keys.signing);
            let _ = backend.destroy_key(&keys.encryption);
            return Err(error);
        }
    };
    Ok((
        OctagonState {
            schema_version: 1,
            account_fingerprint: fingerprint,
            peer_id: permanent.peer_id,
            signing_key: keys.signing,
            encryption_key: keys.encryption,
            permanent: signed_to_state(&permanent.signed),
            trust_state: OctagonTrustState::IdentityReady,
            created_at,
        },
        true,
    ))
}

pub fn account_fingerprint(account: &AccountState) -> String {
    tphash_sha256(account.adsid.as_bytes())
}

pub fn set_recovered_sponsor(
    state: &mut OctagonState,
    escrow_record_label: &str,
    identity: RecoveredIdentity,
) {
    state.trust_state = OctagonTrustState::SponsorRecovered {
        peer_id: identity.peer_id,
        escrow_record_label: escrow_record_label.into(),
        signing_key: identity.signing_key,
        encryption_key: identity.encryption_key,
    };
}

pub fn parse_viable_bottles(raw: &[u8]) -> Result<Vec<ViableBottle>> {
    let fields = decode_fields(raw)?;
    let mut bottles = Vec::new();
    for value in fields.get(&1).into_iter().flatten() {
        let Value::Bytes(encoded) = value else {
            continue;
        };
        let entry = decode_fields(encoded)?;
        let record_label = first_string(&entry, 1)?.unwrap_or_default();
        let bottle = first_bytes(&entry, 2)
            .map(decode_fields)
            .transpose()?
            .and_then(|bottle| first_bytes(&bottle, 2).map(ToOwned::to_owned));
        if let Some(encoded) = bottle {
            bottles.push(ViableBottle {
                record_label,
                encoded,
            });
        }
    }
    Ok(bottles)
}

pub struct OctagonClient<'a> {
    transport: CloudKitTransport<'a>,
    backend: &'a dyn SecurityBackend,
    device: &'a DeviceIdentity,
}

impl<'a> OctagonClient<'a> {
    pub fn new(
        account: &AccountState,
        device: &'a DeviceIdentity,
        anisette: &'a dyn super::anisette::AnisetteProvider,
        backend: &'a dyn SecurityBackend,
    ) -> Result<Self> {
        Ok(Self {
            transport: CloudKitTransport::new(account, device, anisette)?,
            backend,
            device,
        })
    }

    pub fn fetch_changes(&self) -> Result<Changes> {
        self.transport
            .invoke("fetchChanges", &encode_fetch_changes_request(None))
            .and_then(|raw| parse_fetch_changes_response(&raw))
    }

    pub fn fetch_viable_bottles(&self) -> Result<Vec<ViableBottle>> {
        let request = Writer::new().uint64(1, 1).bytes(2, b"").finish();
        let raw = self.transport.invoke("fetchViableBottles", &request)?;
        parse_viable_bottles(&raw)
    }

    pub fn decode_bottle(&self, viable: &ViableBottle) -> Result<Bottle> {
        decode_viable_bottle(viable)
    }

    pub fn join_with_sponsor(&self, state: &mut OctagonState) -> Result<JoinOutcome> {
        let changes = self.fetch_changes()?;
        let already_registered = changes
            .peers
            .iter()
            .any(|peer| peer.peer_id == state.peer_id);
        if matches!(
            state.trust_state,
            OctagonTrustState::JoinedSponsorRetirementVerified { .. }
        ) {
            if !already_registered {
                return Err(Error::Security(
                    "sponsor retirement was verified locally, but this peer is absent from Octagon"
                        .into(),
                ));
            }
            return Ok(JoinOutcome::SponsorRetirementReady {
                uploaded_tlk_shares: 0,
            });
        }
        let sponsor = sponsor_context(state)?;
        let sponsor_signing_spki = self.sponsor_signing_spki(&sponsor, &changes)?;
        let sponsor_encryption_public = self.backend.public_x963(&sponsor.encryption_key)?;
        let (sponsor_tlks, _) = self.fetch_recoverable_for(
            &sponsor.peer_id,
            &sponsor.peer_id,
            &sponsor_signing_spki,
            &sponsor.encryption_key,
            &sponsor_encryption_public,
        )?;

        let own_signing_spki = self.backend.public_spki(&state.signing_key)?;
        let own_encryption_public = self.backend.public_x963(&state.encryption_key)?;
        let own_tlks = if already_registered {
            self.fetch_recoverable_for(
                &state.peer_id,
                &state.peer_id,
                &own_signing_spki,
                &state.encryption_key,
                &own_encryption_public,
            )?
            .0
        } else {
            Vec::new()
        };
        let missing = missing_tlks(&sponsor_tlks, &own_tlks)?;
        let encoded_shares = self.make_self_tlkshares(state, &missing, &own_encryption_public)?;
        let uploaded_tlk_shares = encoded_shares.len();

        if already_registered {
            self.update_self_tlkshares(state, &changes, &encoded_shares)?;
        } else {
            self.submit_new_peer_join(
                state,
                &changes,
                &sponsor,
                &sponsor_signing_spki,
                &encoded_shares,
            )?;
        }
        self.transition_to_awaiting_verification(state, &sponsor)?;

        let verification = self
            .fetch_recoverable_for(
                &state.peer_id,
                &state.peer_id,
                &own_signing_spki,
                &state.encryption_key,
                &own_encryption_public,
            )
            .and_then(|(own_tlks, _)| tlks_cover(&sponsor_tlks, &own_tlks));
        match verification {
            Ok(true) => {
                state.trust_state = OctagonTrustState::JoinedSponsorRetirementVerified {
                    sponsor_peer_id: sponsor.peer_id,
                    escrow_record_label: sponsor.escrow_record_label,
                    sponsor_encryption_key: sponsor.encryption_key,
                };
                Ok(JoinOutcome::SponsorRetirementReady {
                    uploaded_tlk_shares,
                })
            }
            Ok(false) => Ok(JoinOutcome::AwaitingSelfShareVerification {
                uploaded_tlk_shares,
                reason:
                    "Apple accepted the shares, but they are not visible to this peer yet; rerun `keychain join` to verify and retire the sponsor key"
                        .into(),
            }),
            Err(error) => Ok(JoinOutcome::AwaitingSelfShareVerification {
                uploaded_tlk_shares,
                reason: format!(
                    "the join succeeded, but self-share verification did not complete ({error}); rerun `keychain join`"
                ),
            }),
        }
    }

    fn sponsor_signing_spki(&self, sponsor: &SponsorContext, changes: &Changes) -> Result<Vec<u8>> {
        let recovered = sponsor
            .signing_key
            .as_ref()
            .map(|key| self.backend.public_spki(key));
        let published = changes
            .peers
            .iter()
            .find(|peer| peer.peer_id == sponsor.peer_id)
            .map(validated_peer_signing_spki)
            .transpose()?;
        match (recovered, published) {
            (Some(Ok(recovered)), Some(published)) if recovered != published => Err(Error::Security(
                "the recovered sponsor signing key does not match its Octagon peer".into(),
            )),
            (Some(Ok(recovered)), _) => Ok(recovered),
            (Some(Err(_)), Some(published)) => Ok(published),
            (Some(Err(error)), _) => Err(error),
            (None, Some(published)) => Ok(published),
            (None, None) => Err(Error::Security(
                "the sponsor signing key was discarded and its Octagon peer metadata is unavailable"
                    .into(),
            )),
        }
    }

    fn update_self_tlkshares(
        &self,
        state: &OctagonState,
        changes: &Changes,
        encoded_shares: &[Vec<u8>],
    ) -> Result<()> {
        if encoded_shares.is_empty() {
            return Ok(());
        }
        let request = encode_update_trust_request(
            &state.peer_id,
            changes.sync_token.as_deref(),
            encoded_shares,
        );
        self.transport.invoke("updateTrust", &request)?;
        Ok(())
    }

    fn submit_new_peer_join(
        &self,
        state: &OctagonState,
        changes: &Changes,
        sponsor: &SponsorContext,
        sponsor_signing_spki: &[u8],
        encoded_shares: &[Vec<u8>],
    ) -> Result<()> {
        let sponsor_signing = sponsor.signing_key.as_ref().ok_or_else(|| {
            Error::Config("sponsor signing key is unavailable before join completed".into())
        })?;
        let identity = RecoveredIdentity {
            peer_id: sponsor.peer_id.clone(),
            signing_key: sponsor_signing.clone(),
            encryption_key: sponsor.encryption_key.clone(),
        };
        let voucher = identity.make_voucher(self.backend, &state.peer_id)?;
        let (included, stable_clock, dynamic_clock) =
            trust_from_changes(changes, &sponsor.peer_id, Some(sponsor_signing_spki))?;
        let peer = self.build_join_peer(state, &voucher, &included, stable_clock, dynamic_clock)?;
        let request =
            encode_join_with_voucher_request(&peer, changes.sync_token.as_deref(), encoded_shares);
        self.transport.invoke("joinWithVoucher", &request)?;
        Ok(())
    }

    fn transition_to_awaiting_verification(
        &self,
        state: &mut OctagonState,
        sponsor: &SponsorContext,
    ) -> Result<()> {
        if let Some(signing_key) = &sponsor.signing_key {
            self.backend.destroy_key(signing_key)?;
        }
        state.trust_state = OctagonTrustState::JoinedAwaitingTlkVerification {
            sponsor_peer_id: sponsor.peer_id.clone(),
            escrow_record_label: sponsor.escrow_record_label.clone(),
            sponsor_encryption_key: sponsor.encryption_key.clone(),
        };
        Ok(())
    }

    fn make_self_tlkshares(
        &self,
        state: &OctagonState,
        tlks: &[pipeline::RecoveredTlk],
        recipient_public_x963: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        let receiver_public = B64.encode(recipient_public_x963);
        tlks.iter()
            .map(|tlk| {
                let serialized = Zeroizing::new(encode_serialized_key(
                    &tlk.uuid,
                    &tlk.zone_name,
                    &tlk.keyclass,
                    &tlk.key,
                ));
                let encrypted = ecies_encrypt(recipient_public_x963, &serialized)?;
                let wrapped = super::nska::archive_ies_ciphertext(
                    &encrypted.ephemeral_sender_public,
                    &encrypted.ciphertext,
                    &encrypted.authentication_code,
                )?;
                let signed =
                    tlkshare_signing_data(&state.peer_id, &state.peer_id, &wrapped, 4, 1, 0, 0);
                let signature = self.backend.sign_p384_sha256(&state.signing_key, &signed)?;
                Ok(TlkShare {
                    service: tlk.zone_name.clone(),
                    curve: 4,
                    epoch: 1,
                    key_id: tlk.uuid.clone(),
                    receiver: state.peer_id.clone(),
                    receiver_public_encryption_key: receiver_public.clone(),
                    sender: state.peer_id.clone(),
                    signature: B64.encode(signature),
                    wrapped_key: B64.encode(wrapped),
                }
                .encode())
            })
            .collect()
    }

    pub fn retire_verified_sponsor(&self, state: &mut OctagonState) -> Result<()> {
        let OctagonTrustState::JoinedSponsorRetirementVerified {
            sponsor_encryption_key,
            ..
        } = &state.trust_state
        else {
            return Err(Error::Security(
                "refusing to retire a sponsor key before self-addressed TLKShares are verified"
                    .into(),
            ));
        };
        self.backend.destroy_key(sponsor_encryption_key)?;
        state.trust_state = OctagonTrustState::Joined;
        Ok(())
    }

    fn build_join_peer(
        &self,
        state: &OctagonState,
        voucher: &SignedBlob,
        sponsor_included: &[String],
        stable_clock: u64,
        dynamic_clock: u64,
    ) -> Result<Vec<u8>> {
        let permanent = signed_from_state(&state.permanent)?;
        let stable = build_stable_info(
            self.backend,
            &state.signing_key,
            stable_clock,
            "",
            &self.device.serial,
            PEER_OS_VERSION,
            true,
        )?;
        let mut seen = BTreeSet::new();
        let mut included = Vec::new();
        for peer in sponsor_included
            .iter()
            .chain(std::iter::once(&state.peer_id))
        {
            if seen.insert(peer.clone()) {
                included.push(peer.clone());
            }
        }
        let dynamic = build_dynamic_info(
            self.backend,
            &state.signing_key,
            dynamic_clock,
            &included,
            &[],
            &[],
        )?;
        Ok(encode_peer(
            &state.peer_id,
            &permanent,
            &stable,
            &dynamic,
            Some(voucher),
        ))
    }

    /// Verify recovery without borrowing the sponsor encryption key. A full
    /// successful snapshot is required before that key can be retired.
    pub fn sync_self_credentials(&self, state: &OctagonState) -> Result<credential::Projection> {
        if !matches!(
            state.trust_state,
            OctagonTrustState::JoinedSponsorRetirementVerified { .. } | OctagonTrustState::Joined
        ) {
            return Err(Error::Security(
                "self-share verification has not completed".into(),
            ));
        }
        let mut independent = state.clone();
        independent.trust_state = OctagonTrustState::Joined;
        self.sync_credentials(&independent)
    }

    pub fn sync_credentials(&self, state: &OctagonState) -> Result<credential::Projection> {
        if !state.trust_state.is_joined() {
            return Err(Error::Config(
                "this device has not joined Octagon; run `keychain join`".into(),
            ));
        }
        let (mut tlks, view_sync_keys) = self.fetch_recoverable_tlks(state)?;
        let mut records = self.fetch_password_records()?;
        // Recovery shares are not a complete inventory of the live CKKS zones.
        // Also accept live shares signed by our locally known identity, with
        // exactly the same signature and recipient-key checks as recovery.
        let zone_shares = records
            .get("tlkshare")
            .map(Vec::as_slice)
            .unwrap_or_default();
        let own_signing_spki = self.backend.public_spki(&state.signing_key)?;
        let own_encryption_public = self.backend.public_x963(&state.encryption_key)?;
        let zone_tlks = pipeline::unwrap_authenticated_tlkshares(
            zone_shares,
            &state.peer_id,
            &state.peer_id,
            &own_signing_spki,
            self.backend,
            &state.encryption_key,
            &own_encryption_public,
        )?;
        if std::env::var_os("KEYCHAIN_TRACE_SYNC").is_some() {
            eprintln!(
                "CKKS authenticated live self-shared root keys: {}",
                zone_tlks.len()
            );
        }
        merge_tlks(&mut tlks, zone_tlks)?;
        let tlks = tlks
            .into_iter()
            .map(|tlk| (tlk.uuid, tlk.key))
            .collect::<BTreeMap<_, _>>();
        if std::env::var_os("KEYCHAIN_TRACE_SYNC").is_some() {
            let changes = self.fetch_changes()?;
            let mut including = 0;
            let mut excluding = 0;
            for peer in &changes.peers {
                let Some(dynamic) = &peer.dynamic else {
                    continue;
                };
                let spki = validated_peer_signing_spki(peer)?;
                verify_peer_signed_blob(&spki, DYNAMIC_INFO_SIG_TYPE, dynamic)?;
                let fields = decode_fields(&dynamic.info)?;
                let contains_us = |field| {
                    fields.get(&field).into_iter().flatten().any(
                        |value| matches!(value, Value::Bytes(id) if id == state.peer_id.as_bytes()),
                    )
                };
                including += usize::from(contains_us(2));
                excluding += usize::from(contains_us(3));
            }
            eprintln!(
                "Octagon diagnostic: peers={} own_peer_present={} signed_inclusions={} signed_exclusions={}",
                changes.peers.len(),
                changes
                    .peers
                    .iter()
                    .any(|peer| peer.peer_id == state.peer_id),
                including,
                excluding
            );
            let counts = records
                .iter()
                .map(|(kind, values)| (kind.clone(), values.len()))
                .collect::<BTreeMap<_, _>>();
            let shares = records
                .get("tlkshare")
                .map(Vec::as_slice)
                .unwrap_or_default();
            let addressed = shares
                .iter()
                .filter(|share| share.string("receiver") == Some(state.peer_id.as_str()))
                .count();
            eprintln!(
                "CKKS record counts: {counts:?}; zone shares addressed to this peer={addressed}"
            );
        }
        records
            .entry("synckey".into())
            .or_default()
            .extend(view_sync_keys);
        pipeline::build_credentials(&records, tlks)
    }

    fn fetch_recoverable_tlks(&self, state: &OctagonState) -> Result<RecoveredKeys> {
        let own_signing_spki = self.backend.public_spki(&state.signing_key)?;
        let own_encryption_public = self.backend.public_x963(&state.encryption_key)?;
        let (mut tlks, mut sync_keys) = self.fetch_recoverable_for(
            &state.peer_id,
            &state.peer_id,
            &own_signing_spki,
            &state.encryption_key,
            &own_encryption_public,
        )?;
        if matches!(
            state.trust_state,
            OctagonTrustState::JoinedAwaitingTlkVerification { .. }
                | OctagonTrustState::JoinedSponsorRetirementVerified { .. }
        ) {
            let sponsor = sponsor_context(state)?;
            let changes = self.fetch_changes()?;
            let sponsor_signing_spki = self.sponsor_signing_spki(&sponsor, &changes)?;
            let sponsor_encryption_public = self.backend.public_x963(&sponsor.encryption_key)?;
            let (sponsor_tlks, sponsor_sync_keys) = self.fetch_recoverable_for(
                &sponsor.peer_id,
                &sponsor.peer_id,
                &sponsor_signing_spki,
                &sponsor.encryption_key,
                &sponsor_encryption_public,
            )?;
            merge_tlks(&mut tlks, sponsor_tlks)?;
            sync_keys.extend(sponsor_sync_keys);
        }
        Ok((tlks, sync_keys))
    }

    fn fetch_recoverable_for(
        &self,
        peer_id: &str,
        expected_sender: &str,
        sender_signing_spki: &[u8],
        encryption_key: &KeyRef,
        recipient_public_x963: &[u8],
    ) -> Result<RecoveredKeys> {
        let request = encode_fetch_recoverable_tlkshares_request(peer_id);
        let raw = self
            .transport
            .invoke("fetchRecoverableTLKShares", &request)?;
        let parsed = parse_recoverable_tlkshares_response(&raw)?;
        let shares = parsed
            .share_records
            .iter()
            .map(|record| ckks::parse_record(record))
            .collect::<Result<Vec<_>>>()?;
        let sync_keys = parsed
            .synckey_records
            .iter()
            .map(|record| ckks::parse_record(record))
            .collect::<Result<Vec<_>>>()?;
        let tlks = pipeline::unwrap_authenticated_tlkshares(
            &shares,
            peer_id,
            expected_sender,
            sender_signing_spki,
            self.backend,
            encryption_key,
            recipient_public_x963,
        )?;
        if std::env::var_os("KEYCHAIN_TRACE_SYNC").is_some() {
            let mut zones: BTreeMap<&str, usize> = BTreeMap::new();
            for tlk in &tlks {
                let zone = if ckks::KEYCHAIN_ZONES.contains(&tlk.zone_name.as_str()) {
                    tlk.zone_name.as_str()
                } else {
                    "other"
                };
                *zones.entry(zone).or_default() += 1;
            }
            let for_receiver = shares
                .iter()
                .filter(|s| s.string("receiver") == Some(peer_id))
                .count();
            let from_other = shares
                .iter()
                .filter(|s| {
                    s.string("receiver") == Some(peer_id)
                        && s.string("sender") != Some(expected_sender)
                })
                .count();
            eprintln!(
                "CKKS shares: records={} for_receiver={} other_senders={} authenticated_tlks={} sync_keys={}",
                shares.len(),
                for_receiver,
                from_other,
                tlks.len(),
                sync_keys.len()
            );
            eprintln!("CKKS authenticated root-key zone counts: {zones:?}");
        }
        if !shares.is_empty() && tlks.is_empty() {
            return Err(Error::Security(format!(
                "recoverable TLKShares for {peer_id} contained no authenticated self-signed share"
            )));
        }
        Ok((tlks, sync_keys))
    }

    fn fetch_password_records(&self) -> Result<BTreeMap<String, Vec<Record>>> {
        let mut grouped: BTreeMap<String, Vec<Record>> = BTreeMap::new();
        for zone in PASSWORD_ZONES {
            let zone_id = ckks::record_zone_identifier(zone, self.transport.user_id());
            let mut continuation = None;
            let mut seen_continuations = BTreeSet::new();
            let mut completed = false;
            for _ in 0..1_000 {
                let request =
                    ckks::build_retrieve_changes_request(&zone_id, continuation.as_deref(), 500);
                let raw = self.transport.fetch_records(&request)?;
                let page = ckks::parse_retrieve_changes_response(&raw)?;
                if std::env::var_os("KEYCHAIN_TRACE_SYNC").is_some() {
                    let kinds = page
                        .records
                        .iter()
                        .fold(BTreeMap::new(), |mut counts, record| {
                            *counts.entry(record.record_type.as_str()).or_insert(0_usize) += 1;
                            counts
                        });
                    eprintln!(
                        "CKKS {zone}: status={} records={} continuation={} kinds={kinds:?}",
                        page.status,
                        page.records.len(),
                        page.continuation.is_some()
                    );
                }
                for record in page.records {
                    grouped
                        .entry(record.record_type.clone())
                        .or_default()
                        .push(record);
                }
                if page.status == 3 {
                    completed = true;
                    break;
                }
                let next = page.continuation.unwrap_or_default();
                if !seen_continuations.insert(next.clone()) {
                    return Err(Error::InvalidData(format!(
                        "CKKS zone {zone} repeated a pagination token"
                    )));
                }
                continuation = Some(next);
            }
            if !completed {
                return Err(Error::InvalidData(format!(
                    "CKKS zone {zone} exceeded the 1000-page safety limit"
                )));
            }
        }
        Ok(grouped)
    }
}

fn decode_viable_bottle(viable: &ViableBottle) -> Result<Bottle> {
    let bottle = Bottle::parse(&viable.encoded)?;
    if bottle.peer_id.is_empty() {
        return Err(Error::InvalidData("bottle has no peer id".into()));
    }
    if bottle.bottle_id.is_empty() {
        return Err(Error::InvalidData(
            "bottle has no internal bottle id".into(),
        ));
    }
    let expected_label = format!("{ESCROW_RECORD_PREFIX}{}", bottle.peer_id);
    if viable.record_label != expected_label {
        return Err(Error::Security(format!(
            "escrow record label {} does not match bottle peer id {}",
            viable.record_label, bottle.peer_id
        )));
    }
    Ok(bottle)
}

fn sponsor_context(state: &OctagonState) -> Result<SponsorContext> {
    match &state.trust_state {
        OctagonTrustState::SponsorRecovered {
            peer_id,
            escrow_record_label,
            signing_key,
            encryption_key,
        } => Ok(SponsorContext {
            peer_id: peer_id.clone(),
            escrow_record_label: escrow_record_label.clone(),
            signing_key: Some(signing_key.clone()),
            encryption_key: encryption_key.clone(),
        }),
        OctagonTrustState::JoinedAwaitingTlkVerification {
            sponsor_peer_id,
            escrow_record_label,
            sponsor_encryption_key,
        } => Ok(SponsorContext {
            peer_id: sponsor_peer_id.clone(),
            escrow_record_label: escrow_record_label.clone(),
            signing_key: None,
            encryption_key: sponsor_encryption_key.clone(),
        }),
        OctagonTrustState::JoinedSponsorRetirementVerified {
            sponsor_peer_id,
            escrow_record_label,
            sponsor_encryption_key,
        } => Ok(SponsorContext {
            peer_id: sponsor_peer_id.clone(),
            escrow_record_label: escrow_record_label.clone(),
            signing_key: None,
            encryption_key: sponsor_encryption_key.clone(),
        }),
        OctagonTrustState::IdentityReady | OctagonTrustState::Joined => Err(Error::Config(
            "no recovered sponsor identity is stored".into(),
        )),
    }
}

fn trust_from_changes(
    changes: &Changes,
    sponsor: &str,
    sponsor_signing_spki: Option<&[u8]>,
) -> Result<(Vec<String>, u64, u64)> {
    let mut stable_clock = 0_u64;
    let mut dynamic_clock = 0_u64;
    let mut included = Vec::new();
    for peer in &changes.peers {
        if let Some(stable) = &peer.stable {
            stable_clock =
                stable_clock.max(first_u64(&decode_fields(&stable.info)?, 1).unwrap_or_default());
        }
        if peer.peer_id == sponsor {
            if let Some(dynamic) = &peer.dynamic {
                if let Some(spki) = sponsor_signing_spki {
                    verify_peer_signed_blob(spki, DYNAMIC_INFO_SIG_TYPE, dynamic)?;
                }
                let fields = decode_fields(&dynamic.info)?;
                dynamic_clock = first_u64(&fields, 1).unwrap_or_default();
                included = fields
                    .get(&2)
                    .into_iter()
                    .flatten()
                    .filter_map(|value| match value {
                        Value::Bytes(value) => std::str::from_utf8(value).ok().map(str::to_owned),
                        _ => None,
                    })
                    .collect();
            }
        }
    }
    if included.is_empty() {
        included.push(sponsor.into());
    }
    Ok((included, stable_clock + 1, dynamic_clock + 1))
}

fn validated_peer_signing_spki(peer: &super::cuttlefish::Peer) -> Result<Vec<u8>> {
    let permanent = peer.permanent.as_ref().ok_or_else(|| {
        Error::InvalidData(format!(
            "Octagon peer {} has no permanent info",
            peer.peer_id
        ))
    })?;
    let mut peer_input = Vec::with_capacity(permanent.info.len() + permanent.signature.len());
    peer_input.extend_from_slice(&permanent.info);
    peer_input.extend_from_slice(&permanent.signature);
    if tphash_sha256(&peer_input) != peer.peer_id {
        return Err(Error::Security(format!(
            "Octagon peer {} does not match its permanent-info hash",
            peer.peer_id
        )));
    }
    let fields = decode_fields(&permanent.info)?;
    let spki = first_bytes(&fields, 2)
        .filter(|spki| !spki.is_empty())
        .ok_or_else(|| Error::InvalidData("Octagon permanent info has no signing key".into()))?
        .to_vec();
    verify_peer_signed_blob(&spki, PERMANENT_INFO_SIG_TYPE, permanent)?;
    Ok(spki)
}

fn verify_peer_signed_blob(spki: &[u8], kind: &str, blob: &SignedBlob) -> Result<()> {
    let key = VerifyingKey::from_public_key_der(spki)
        .map_err(|_| Error::InvalidData("Octagon peer has an invalid P-384 signing key".into()))?;
    let signature = Signature::from_der(&blob.signature)
        .map_err(|_| Error::InvalidData("Octagon peer has an invalid P-384 signature".into()))?;
    key.verify(&prefixed_data(kind, &blob.info), &signature)
        .map_err(|_| Error::Security(format!("{kind} signature did not verify")))
}

fn same_tlk(left: &pipeline::RecoveredTlk, right: &pipeline::RecoveredTlk) -> bool {
    left.uuid == right.uuid
        && left.zone_name == right.zone_name
        && left.keyclass == right.keyclass
        && left.key.as_slice() == right.key.as_slice()
}

fn merge_tlks(
    destination: &mut Vec<pipeline::RecoveredTlk>,
    incoming: Vec<pipeline::RecoveredTlk>,
) -> Result<()> {
    for tlk in incoming {
        if let Some(existing) = destination
            .iter()
            .find(|existing| existing.uuid == tlk.uuid)
        {
            if !same_tlk(existing, &tlk) {
                return Err(Error::Security(format!(
                    "conflicting authenticated TLKs exist for {}",
                    tlk.uuid
                )));
            }
        } else {
            destination.push(tlk);
        }
    }
    Ok(())
}

fn missing_tlks(
    required: &[pipeline::RecoveredTlk],
    available: &[pipeline::RecoveredTlk],
) -> Result<Vec<pipeline::RecoveredTlk>> {
    let mut missing = Vec::new();
    for tlk in required {
        match available
            .iter()
            .find(|candidate| candidate.uuid == tlk.uuid)
        {
            Some(candidate) if same_tlk(tlk, candidate) => {}
            Some(_) => {
                return Err(Error::Security(format!(
                    "this peer has a conflicting TLK for {}",
                    tlk.uuid
                )));
            }
            None => missing.push(tlk.clone()),
        }
    }
    Ok(missing)
}

fn tlks_cover(
    required: &[pipeline::RecoveredTlk],
    available: &[pipeline::RecoveredTlk],
) -> Result<bool> {
    Ok(missing_tlks(required, available)?.is_empty())
}

fn signed_to_state(signed: &SignedBlob) -> SignedInfoState {
    SignedInfoState {
        data_b64: B64.encode(&signed.info),
        signature_b64: B64.encode(&signed.signature),
    }
}

fn signed_from_state(state: &SignedInfoState) -> Result<SignedBlob> {
    Ok(SignedBlob {
        info: B64
            .decode(&state.data_b64)
            .map_err(|_| Error::InvalidData("stored Octagon data is not base64".into()))?,
        signature: B64
            .decode(&state.signature_b64)
            .map_err(|_| Error::InvalidData("stored Octagon signature is not base64".into()))?,
    })
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
    use crate::paths::AppPaths;
    use crate::security::SoftwareFileBackend;

    #[test]
    fn viable_bottle_parser_drops_entries_without_bottle() {
        let bottle = Writer::new().bytes(2, b"OTBottle").finish();
        let entry = Writer::new().string(1, "b1").message(2, &bottle).finish();
        let raw = Writer::new().message(1, &entry).finish();
        let parsed = parse_viable_bottles(&raw).unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].record_label, "b1");
        assert_eq!(parsed[0].encoded, b"OTBottle");
    }

    #[test]
    fn viable_record_label_matches_peer_id_not_internal_bottle_id() {
        let peer_id = "SHA256:old-peer=";
        let internal_bottle_id = "11111111-2222-4333-8444-555555555555";
        let bottle = Bottle {
            peer_id: peer_id.into(),
            bottle_id: internal_bottle_id.into(),
            escrowed_signing_spki: Vec::new(),
            escrowed_encryption_spki: Vec::new(),
            ciphertext: Vec::new(),
            authentication_code: Vec::new(),
            iv: Vec::new(),
        };
        let viable = ViableBottle {
            record_label: format!("{ESCROW_RECORD_PREFIX}{peer_id}"),
            encoded: bottle.encode(),
        };

        let parsed = decode_viable_bottle(&viable).unwrap_or_else(|e| panic!("decode: {e}"));
        assert_eq!(parsed.peer_id, peer_id);
        assert_eq!(parsed.bottle_id, internal_bottle_id);
    }

    #[test]
    fn viable_record_label_rejects_a_different_peer() {
        let bottle = Bottle {
            peer_id: "SHA256:old-peer=".into(),
            bottle_id: "bottle-uuid".into(),
            escrowed_signing_spki: Vec::new(),
            escrowed_encryption_spki: Vec::new(),
            ciphertext: Vec::new(),
            authentication_code: Vec::new(),
            iv: Vec::new(),
        };
        let viable = ViableBottle {
            record_label: "com.apple.icdp.record.SHA256:other-peer=".into(),
            encoded: bottle.encode(),
        };

        assert!(matches!(
            decode_viable_bottle(&viable),
            Err(Error::Security(_))
        ));
    }

    #[test]
    fn peer_signing_key_is_bound_to_permanent_info_and_peer_id() {
        let temp = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let paths =
            AppPaths::for_test(temp.path()).unwrap_or_else(|error| panic!("paths: {error}"));
        let backend = SoftwareFileBackend::new(paths);
        let keys = PeerKeySet::generate(&backend).unwrap_or_else(|error| panic!("keys: {error}"));
        let permanent = build_permanent_info(&backend, &keys, "machine", "model", 1, 123)
            .unwrap_or_else(|error| panic!("permanent: {error}"));
        let mut peer = super::super::cuttlefish::Peer {
            peer_id: permanent.peer_id,
            permanent: Some(permanent.signed),
            stable: None,
            dynamic: None,
            voucher: None,
        };
        assert_eq!(
            validated_peer_signing_spki(&peer).unwrap_or_else(|error| panic!("validate: {error}")),
            backend
                .public_spki(&keys.signing)
                .unwrap_or_else(|error| panic!("SPKI: {error}"))
        );
        peer.peer_id.push('x');
        assert!(validated_peer_signing_spki(&peer).is_err());
    }

    #[test]
    fn missing_tlks_rejects_same_uuid_with_different_key_material() {
        let material = |byte| pipeline::RecoveredTlk {
            uuid: "tlk-id".into(),
            zone_name: "Passwords".into(),
            keyclass: "tlk".into(),
            key: Zeroizing::new(vec![byte; 64]),
        };
        assert!(missing_tlks(&[material(1)], &[material(1)]).is_ok_and(|v| v.is_empty()));
        assert!(missing_tlks(&[material(1)], &[material(2)]).is_err());
    }
}
