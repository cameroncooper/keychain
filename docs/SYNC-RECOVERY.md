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
real account has not yet run this repair; its cache remains empty pending recovery.

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
