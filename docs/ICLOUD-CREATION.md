# iCloud passkey creation progress

This implements part of milestone 6 in [the SEP completion plan](../SEP-IMPLEMENTATION.md).
The browser still offers device-only creation. No Apple record writes or live
uploads were performed. Preparation and staging do not access the network.

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
explicit `UploadIo` interface. There is no production implementation of its
atomic-write method yet. `Snapshot::fetch` uses the existing authenticated
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

Ten offline coordinator tests cover acceptance/fetch separation, independent
decryption/public-point checks, pagination, changed bindings, locks/tampering,
lost responses, explicit retries, precondition failures and checkpoint faults.
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

Drafts are hidden from credential inventory and generic `VerifyProtected` use.
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
flags. There is still no production draft authorization/upload/promotion path,
and the iCloud browser choice remains disabled.

The updated release service binaries were installed on 2026-11-06. The existing
disposable profile passed the installed broker/native-host availability check
with `--availability-only`; it did not start biometric capture or perform a
registration, assertion or Apple write. The full workspace has 159 passing
tests with ten intentionally ignored tests; the six disposable registry tests
also passed separately as root. Strict Clippy and the release build passed.

Remaining integration work:

1. Connect the implemented broker draft preparation to fresh biometric
   authorization, upload preparation and final promotion. Never activate a draft
   through generic import verification or convert a native key to exportable storage.
2. Implement the atomic save/current-key wire protocol using the retained server
   identity and tags. Apple's [outgoing operation](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSOutgoingQueueOperation.m)
   saves items with current-key pointers atomically under the unchanged-record
   policy. The private protobuf framing for those safeguards is not yet verified;
   an ordinary create request alone is insufficient.
3. Connect the durable coordinator to the broker/browser creation path and add
   reconciled re-encryption for a rejected stale-key attempt. An uncertain
   attempt must not lose its existing identity or prepared ciphertext.
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

The actual metadata encoding and atomic-save semantics still need live validation;
the coordinator or the existing joined Octagon identity cannot substitute for it.
