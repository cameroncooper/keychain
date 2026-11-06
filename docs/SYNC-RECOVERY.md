# Incomplete sync and recovery

`keychain sync` reads encrypted Apple records and replaces the local snapshot only
after all requested zones have completed and every downloaded CKKS item has been
decrypted. A failed request, missing response payload, incomplete pagination, or
undecryptable item is an error. It must not become a successful empty snapshot.
An account may legitimately contain no credentials, so an empty result is allowed
only after these checks succeed.

Before replacing a nonempty vault, the store authenticates the existing file and
keeps its encrypted bytes in `vault.previous.enc`, alongside `vault.enc` in the
profile's state directory. Repeated empty snapshots do not replace that last
nonempty backup. Loading never silently falls back to it; recovery must be
explicit so an outdated snapshot cannot masquerade as current data. Logout
removes both vault files. A backup cannot recover data overwritten before this
protection was installed.

## Authentication and trust are separate

Successful Apple service authentication does not establish that the Octagon peer
still has access to every keychain view. Missing key shares can prevent decryption
even when Apple returns successful responses containing encrypted items.
`keychain status` reports locally stored join state, not a fresh server trust check.

The 2026-11-05 investigation found:

- Apple accepted authentication and returned successful responses for both zones.
- Passwords returned six encrypted items whose class key could not be recovered.
- Manatee returned 21 items, all decryptable, with no projected user credentials.
- Recovery returned three authenticated self-shared root keys, none for Passwords.
  The live zone's self-share added no missing root key.
- Server peer metadata included this client's identity and a cryptographically
  verified peer statement excluding it. This supports a trust problem; it does
  not establish why or when the exclusion happened.

The earlier implementation skipped item decryption failures and saved the empty
projection. This erased the local snapshot, not Apple's records. The guarded
implementation fails and preserves the existing snapshot. In this incident the
snapshot had already been overwritten before the guard and backup existed.
Recovering it requires trusted access to the Passwords key again; another ordinary
login alone is not sufficient. Use the explicit repair flow below rather than
logging out or deleting local state. Escrow recovery requires the user's device
passcode and must never be retried automatically.

## Explicit trust repair

Run this in a terminal where you can enter the Apple Account password and the
selected recovery device's unlock password/passcode:

```sh
./target/release/keychain join --repair
```

This is an explicit Apple trust write and escrow recovery, distinct from read-only
sync. It prepares a new Octagon peer with a separate encrypted journal at
`octagon-repair.enc`, using the TrustRepair encryption purpose. Existing account,
device, anisette, passkey references and active peer are retained. It presents the
usual recovery-device choice and attempt warning. It does not change fingerprints,
SEP keybags, or xART state, or upload/delete password or passkey items.

1. Prepared: retain the original peer and create a replacement. Persist recovered
   sponsor references before joining; later invocations resume without spending
   another escrow attempt. Join, upload authenticated self-addressed shares and
   verify their exact coverage. The original remains active.
2. Snapshot verified: fetch/decrypt a complete snapshot with only the replacement
   peer, with sponsor fallback disabled. Save the reconciled vault, then checkpoint
   success in the journal. If key access is still incomplete, fail here without
   promoting the peer or destroying its recovery sponsor.
3. Commit: promote the replacement, retire its verified escrow sponsor, save the
   joined state and mark the journal committed. Each interrupted file transition
   resumes, including a sponsor already deleted before the next state rename.
   Previous peer keys remain in the software backend and in the journal's retained
   references. A later explicit repair retains that history as well.

Resume an interrupted operation with `keychain join --repair` (or `keychain join`
while a repair is pending). A successful repair includes sync; no separate sync
is required to restore the cache. Running `--repair` after a completed repair
explicitly begins a new replacement transaction. `status` reports pending repair;
logout removes its journal and associated local peer keys. Account changes,
unexpected active identities, corrupted journals and missing roots fail closed.
No implicit repair happens during sync, SEP authorization, or startup.

Ordinary first-run joins now also require a complete independent snapshot before
retiring the recovered sponsor. Self-share coverage alone is insufficient if the
recovered sponsor lacked the desired Passwords key.

Software tests exercise preparation/checkpoint retention, account/identity
mismatch, purpose binding and interruption before retirement, after retirement,
and after active-state commit. These do not establish that Apple accepts a live
repair or that another device will retain the new peer indefinitely. The affected
real account has not yet completed this repair; its cache remains empty pending recovery.

## Diagnostics

`KEYCHAIN_TRACE_SYNC=1 keychain sync` adds counts, protocol field numbers,
decryption failure stages, and verified peer inclusion/exclusion counts. It does
not print passwords, decrypted item fields, key material, tokens, or response
bodies. Trace mode also reads peer metadata to diagnose trust; it does not change
membership or spend escrow recovery attempts.

Recovery and live self-shares use the same sender signature and recipient-key
checks. Unwrapping class keys follows authenticated parent keys regardless of
record order, rejects conflicting material, and does not accept orphan keys.
Do not bypass those checks to recover a partial list.


## Recovery-record identifier compatibility — 2026-11-06

The user's renewed sign-in completed password proof and SMS verification, then
escrow recovery saved the sponsor in the retained Prepared repair journal. The
subsequent join stopped at `zone identity has the wrong identifier kind` while
reading `fetchRecoverableTLKShares`, before the new peer join. This was not a
passcode rejection. A read-only journal check confirms a saved sponsor, and
`keychain status` now prints its fixed-label recovery checkpoint without keys or
secret contents.

A read-only CloudKit probe validated zone/tag/opaque metadata for 14 Passwords
records using the fresh service token. A separate read-only recovery-metadata
probe reproduced the decoder failure: zone component 1 omitted its optional type
enum. Full CloudKit records carried explicit enums; recovery records need not.
The decoder now infers an omitted enum only from the enclosing zone/owner field.
Explicit conflicting, zero, duplicate or wrong-wire-type enums still fail, as do
missing/invalid names. Exact zone/owner comparison and opaque bytes are retained;
no record is reassigned to a caller's expected scope. The optional identifier
field is documented in the pinned
[CloudKit schema](https://github.com/doug-leith/ios-protobuf-decoding/blob/231b2467e61d741fdd39e1c99229e90d7e93d4c9/ios_decoder/protos/CloudKitDaemon/ckdp.proto).

The fixed read-only recovery probe decoded 20 encrypted share records and 60
sync-key records. It did not unwrap a TLK, join a peer, spend an escrow attempt or
save an account/vault snapshot. A regression fixture covers omitted/mixed enum
presence, exact server-encoding retention, cross-owner rejection and malformed
explicit identifiers. The ignored developer probe is:

```sh
cargo test --lib apple::octagon::tests::live_saved_repair_sponsor_metadata_decodes_without_recovery -- --exact --ignored --nocapture
```

Resume the existing repair with `./target/release/keychain join --repair`. The
saved sponsor branch skips new password/2FA/escrow recovery; it retains the same
candidate and previous peer. Full replacement-peer join, independent complete
snapshot validation and promotion remain unverified until that continuation
succeeds. No peer/recipient/root reset or automatic recovery retry was introduced.
