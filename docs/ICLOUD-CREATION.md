# iCloud passkey creation progress

This implements part of milestone 6 in [the SEP completion plan](../SEP-IMPLEMENTATION.md).
The browser iCloud choice is connected behind a default-off deployment flag;
the installed service still offers device-only creation. No Apple record writes
were proven accepted. One scoped negative save attempt completed biometric unlock
and local encryption but remains uncertain; its key/journal are retained and an
independent fetch showed absence. The positive gate remains closed. See
[live-test evidence](LIVE-ICLOUD-TEST.md). Local preparation and staging do not
access the network.

`passkey::encode_sync_item` prepares a synchronizable P-256 software-key plist
from a trusted caller's credential and X9.63 private representation. It preserves
the RP label, credential alias and CBOR user tag, records public-key SHA-1 as the
application label, encodes key attributes/timestamps and checks that the scalar
matches its public point. Device-bound provenance/native references and invalid
key usage, IDs, handles or timestamps are refused. The result is an owned
`DecryptedItem` whose data fields are zeroized on drop; callers must keep it
inside the privileged creation path. This adds no raw-key browser IPC endpoint.
Apple/WebKit's [local authenticator schema](https://github.com/WebKit/WebKit/blob/main/Source/WebKit/UIProcess/WebAuthentication/Cocoa/LocalAuthenticator.mm)
and Security's [key item schema](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/securityd/SecItemSchema.c)
are the protocol references; actual import on another Apple device remains unverified.

`apple::ckks::write::CurrentKey` takes a complete single-zone snapshot and
authenticated TLKs. It requires the current `classA`/`classC` pointer, verifies
the target class and unwraps its ancestry from roots for that zone. It rejects
missing, duplicate, conflicting and wrong-zone material; a decryptable old class
key is not a substitute for the current pointer. `ak` uses class A and `ck` uses
class C, following Apple's [outgoing key selection](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSOutgoingQueueEntry.m).

`seal_new_item` requires an unused UUID v4, explicit sync intent and matching
protection/view hint. It serializes bounded binary-plist plaintext, omitting the
local `sync`/`UUID` attributes that Apple's sync projection excludes. It generates
a fresh 64-byte item key, wraps it with the current class key, and encrypts the
item with a fresh 16-byte nonce, sorted v2 AAD and ISO-7816 padding to 20-byte
blocks (plus an extra block for short secrets). Plaintext and temporary keys use
zeroizing buffers; the returned CKKS record holds ciphertext and wrapped key.
The existing v2 decryption/AAD implementation is reused, with unknown reference
values now omitted to match Apple's metadata projection. References:
[item encryption/padding](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSItemEncrypter.m),
[SIV framing](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSSIV.m),
[authenticated metadata](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSItem.m).

Four offline tests cover padding/key wrapping, authenticated current-key
selection, rejection/tampering and complete passkey encode/encrypt/decrypt/import.
The latter uses the existing sync pipeline and checks unchanged credential ID,
account metadata, timestamps and imported public point. These tests use synthetic
keys. They do not prove CloudKit accepts the record, that another Apple device
imports it, or that any new biometric creation operation has run.

The upload coordinator in `apple::ckks::upload` is now implemented against an
explicit `UploadIo` interface. A concrete Apple adapter is now implemented but
not invoked by CLI/browser operations; live acceptance and atomicity are not
yet validated. `Snapshot::fetch` uses the existing authenticated
CloudKit transport and collects every page with cursor/count/size bounds before
absence can enable a send or retry. The decoder retains each record's zone,
owner, change tag and original encoding; unchanged-record checks reject edited
projections rather than discard unknown server fields.

`PreparedUpload` can only be built by validating a new item against the current
key and a complete authenticated snapshot, decrypting it and checking the
credential/public identity. It is not deserializable from browser IPC. The
broker registry exposes private upload-journal storage, separated from credential
inventory and encrypted with the dedicated `SyncUpload` purpose. Journals contain
account/peer/owner/request/transaction binding, exact ciphertext, public identity,
current-pointer precondition and attempt history; no raw private key, account
token, biometric result or reusable authorization grant is persisted.

The coordinator checkpoints Attempted before invoking the write adapter, records
acceptance separately, then fetches and decrypts before reaching FetchVerified.
A lost response reopens as uncertain and does not automatically resend. Explicit
retry requires a fresh complete snapshot reporting absence and the unchanged key
pointer; it reuses identical ciphertext/identity. Pointer changes and atomic
rejections retain the key for later reconciliation, without silently choosing a
new key or re-encrypting an unresolved upload. Any checkpoint error poisons the
in-memory session until reopening, since rename/fsync failure can leave either
old or new durable bytes. The broker also refuses root regeneration after an
initialized root disappears, including in a running process.

Explicit re-encryption after a rejected precondition is now implemented. The
coordinator first fetches complete absence, then invokes the selected-secret
preparation callback with that snapshot. `PreparedUpload::encrypt_from_snapshot`
uses its authenticated current class-A key; the coordinator independently
revalidates ciphertext, public point, immutable metadata and owner/account/peer/
request/transaction binding before checkpointing. Preparation never sends. An
uncertain, accepted or verified upload cannot enter this path. Failed fetch,
canceled preparation, wrong identity or stale key leaves the original journal
unchanged; a failed checkpoint requires reopening rather than trusting RAM.

Every superseded ciphertext/pointer stays in the encrypted journal. A timed-out
request can commit late even after a subsequent retry is rejected. Fetch
reconciliation therefore checks the current and retained exact ciphertexts,
then independently decrypts and verifies the matching credential before issuing
backup evidence. A same-identity record with unrecognized ciphertext is refused,
and no existing record is overwritten. Re-encryption is bounded to eight superseded
plans plus the current plan and sixteen send attempts; exhausting a budget stops before the secret
callback while keeping reconciliation available. No raw scalar or reusable UV
grant is added to the journal.

Seventeen offline coordinator tests cover acceptance/fetch separation, independent
decryption/public-point checks, pagination, changed bindings, locks/tampering,
lost responses, explicit retries, precondition failures and checkpoint faults.
These include real synthetic class-key rotation, late superseded commits,
changed archived identity, bounded history and re-encryption checkpoint failure.
A privileged upload-only registry test checks namespace isolation and missing-root
refusal. These tests use synthetic roots and a simulated server, and are not live
Apple upload evidence.

The root registry now prepares a syncable key in a separate encrypted draft
namespace. An owner/account/peer/zone/exact-request-bound intent is fsynced before
randomness is generated. The scalar is generated into checked locked,
dump-excluded, non-inherited memory, then sealed to the existing SEP item
recipient. Temporary library key objects zeroize on drop; this does not claim
every cryptographic temporary is locked. The primary sealing buffer is now also
protected before plaintext copying. Only the sealed scalar and public metadata
are persisted. A retry reopens the same identity; an intent with no durable key
refuses silent regeneration. Native creation and generic imports cannot take
over the transaction. Missing recipients are never regenerated by preparation.

Uncommitted drafts are hidden from credential inventory and generic `VerifyProtected` use.
Sync sees a draft as staged and refuses software fallback. On first sync or after
user-cache loss, sync now checks the broker for every recovered passkey, retaining
verified protected references and checking identity/public point before metadata
refresh. The metadata operations do not require enabling the decrypt extension;
actual key import/authorization still require the explicit compatible deployment.
Two disposable root-registry tests passed, using a synthetic recipient and
independent software decryption, including restart, intent interruption,
namespace collisions and changed account/request refusal. These are not hardware
key-generation or biometric tests.

A healthy durable FetchVerified upload now produces a non-deserializable
`VerifiedUpload` receipt. Shared registration encoding checks this receipt against
the current account/peer/request/transaction, exact credential and public point
before setting BE/BS. It separately requires a fresh, exact-message/key-bound
SEP-protected software signature with UV. The receipt is backup evidence, never
a biometric grant. Prepared, accepted-but-unverified and poisoned sessions cannot
supply it. Offline tests cover these refusals, changed bindings and registration
flags. The iCloud browser choice remains disabled.

The registry now has a receipt-checked registration/promotion operation. It
reopens the frozen draft, verifies a fresh exact-message SEP-protected UV
signature, rechecks the draft under the update lock and runs the caller's
session/cancel/deadline guard before promotion and response delivery. The durable
sequence is Activating, protected-record write, inventory inclusion, then
Committed. Until Committed, even an already-written protected record is hidden
and cannot be loaded or activated through generic import verification. Errors
and restart reopen the same identity and require fresh signing; no signature or
reusable biometric grant is persisted. Late cancellation suppresses the response
even after commit. A committed record missing from disk is an error, not an
invitation to recreate it from the old draft. Subsequent metadata refreshes and
same-public-key rewraps work without changing the immutable registration identity.

Three additional root tests passed for wrong receipts/protection/UV, cancellation
before and after commit, interrupted durable transitions, changed drafts during
signing, fresh-process delivery retry, normal post-creation sync updates and
missing committed records. Their upload receipts come from the real coordinator
and CKKS encoder/encryptor with a simulated server; signing/decryption uses
disposable software fixtures. The APIs are connected to the production worker and browser behind an explicit
deployment flag; these synthetic tests are not hardware or Apple acceptance evidence.

The [broker operation coordinator](ICLOUD-BROKER-COORDINATION.md) now joins these
stages inside one selected-scalar lifetime, with no second biometric decrypt
between upload and registration signing. It resumes before preparing ciphertext,
checks the selected identity against the saved plan, requires explicit uncertain/
rejected recovery choices and discards canceled network results. Five synthetic
root integration tests passed. The authenticated cancellable network-worker bridge
and protected encoder buffers are implemented. Production owner IPC is connected
but requires the explicit creation flag and account enrollment; remaining
library/scratch memory review is still required.

The [atomic write implementation](CLOUDKIT-WRITE-PROTOCOL.md) now encodes the new
item with fail-if-exists and the exact retained current-key record with
fail-if-outdated plus request change tag. It fixes account/peer/zone/record scope,
validates raw reference targets and strictly correlates both replies. Mixed or
incomplete responses remain uncertain; the dedicated HTTP client follows no
redirect and performs no automatic retry. Six wire-policy tests and two loopback
HTTP tests passed. The protocol sources, strict acknowledgement-format limit and
required live negative/positive tests are documented there. The actual Apple
save path was not executed, and the browser still offers device-only creation.

The updated release service binaries were installed on 2026-11-06. The existing
disposable profile passed the installed broker/native-host availability check
with `--availability-only`; it did not start biometric capture or perform a
registration, assertion or Apple write. The full workspace has 201 passing
tests with twenty-one intentionally ignored tests. Seventeen privileged library
tests (registry, coordination, account, systemd startup and separate-UID worker)
passed separately; eleven browser service-worker tests pass. Strict Clippy and
the release build passed.

Remaining integration work:

1. Finish the remaining library/scratch memory audit for the connected
   selected-scalar coordinator. Never activate a draft
   through generic import verification or convert a native key to exportable storage.
2. Validate the implemented atomic save/current-key wire protocol against live
   rejection and acceptance, using the retained server identity and tags.
   An ordinary create request alone is insufficient.
3. Complete real account bootstrap after fresh authentication and validate
   the connected broker/browser path. Preserve the default-off write gate until
   live testing is explicitly authorized. Explicit recovery-policy UI remains
   separate work; normal browser resume only reconciles uncertain writes.
4. Verify Apple acceptance and subsequent authenticated fetch/decryption before
   reporting an iCloud save or enabling normal backed-up use. A local round trip
   or HTTP success alone is insufficient. Browser BE/BS flags must follow the
   actual lifecycle state rather than a client-selected boolean.
5. Test with an explicitly scoped disposable Apple write, then use the passkey
   on another trusted device. Only after these gates should the browser offer
   **Save to iCloud** alongside **This device**.

The public descriptor URL in the request header did not provide a usable schema
during this investigation. The new ignored read-only metadata test received
HTTP 401 using the cached CloudKit token on 2026-11-05. No record was decrypted,
no vault/account snapshot was saved and no password, escrow or write request was
sent. The response establishes an authentication refusal, not its cause; it does
not prove token expiry versus provider/session binding. After fresh local sign-in
through `keychain join --repair`, rerun the metadata check:

```sh
cargo test --lib apple::cloudkit::tests::live_record_metadata_preserves_server_zone_and_tags -- --ignored --nocapture
```

The actual metadata encoding and implemented atomic-save framing still need live validation;
the coordinator or the existing joined Octagon identity cannot substitute for it.
