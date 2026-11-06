# iCloud passkey creation progress

This implements part of milestone 6 in [the SEP completion plan](../SEP-IMPLEMENTATION.md).
The browser still offers device-only creation. No Apple record writes or live
uploads were performed, and the new preparation functions have no network API.

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

The upload coordinator still needs to:

1. Generate and durably stage the exportable scalar in the broker, bind it to
   the frozen creation request/storage choice, and protect local use with a
   fresh biometric transaction. Never convert a native key to exportable storage.
2. Retain server identity/change tags in zone snapshots and implement the atomic
   save/current-key precondition. Apple's [outgoing operation](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSOutgoingQueueOperation.m)
   saves items with current-key pointers atomically under the unchanged-record
   policy. The private protobuf framing for those safeguards is not yet verified;
   an ordinary create request alone is insufficient.
3. Persist account/peer/request binding, exact prepared ciphertext, transaction
   and expected public identity before sending. After an ambiguous response,
   fetch/reconcile the same UUID rather than generate another key or blindly
   retry. A key rotation may require explicit re-encryption before a new attempt.
4. Verify Apple acceptance and subsequent authenticated fetch/decryption before
   reporting an iCloud save or enabling normal backed-up use. A local round trip
   or HTTP success alone is insufficient. Browser BE/BS flags must follow the
   actual lifecycle state rather than a client-selected boolean.
5. Test with an explicitly scoped disposable Apple write, then use the passkey
   on another trusted device. Only after these gates should the browser offer
   **Save to iCloud** alongside **This device**.

The current CloudKit decoder drops record change tags/zone identity, so it must
be extended before upload. The public descriptor URL in the request header did
not provide a usable schema during this investigation. These are remaining
implementation tasks; none of the safeguards above are replaced by the offline
encryption helper or by the existing joined Octagon identity.
