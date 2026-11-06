# CloudKit atomic save implementation and validation

Implemented 2026-11-06 in `apple::cloudkit::atomic`. The concrete `AppleUploadIo`
adapter implements the upload coordinator's read/write interface. The broker's
creation path is connected behind a default-off deployment flag; the installed
production service leaves that flag off. No live Apple write has been performed.
This is implemented framing and policy validation, with Apple acceptance and
atomicity still requiring the live gates below.

The wire constants are independently implemented from these pinned references:

- The [extracted CloudKitDaemon schema](https://github.com/doug-leith/ios-protobuf-decoding/blob/231b2467e61d741fdd39e1c99229e90d7e93d4c9/ios_decoder/protos/CloudKitDaemon/ckdp.proto)
  identifies RecordSaveRequest's change tag as field 4 and its save mode as field
  6: fail-if-outdated = 1, fail-if-exists = 2, override = 3. The item reference's
  validating action is 3; field-value discriminants identify bytes/string/int64/
  reference. These fields are unflagged in the extractor's output. Its
  [limitations and verification description](https://github.com/doug-leith/ios-protobuf-decoding/blob/231b2467e61d741fdd39e1c99229e90d7e93d4c9/apple_protobuf_extractor/README.md)
  still apply; a published extraction is not our own binary or server validation.
- The [published Rust client](https://github.com/OpenBubbles/rustpush/blob/b3c96c23e1aae78d1229ebaccb12027624f1eaff/src/icloud/cloudkit.rs)
  uses the record/save endpoint, gzip over length-delimited operations, a header
  on the first operation, an explicit final-operation marker and zone isolation.
  This establishes a concrete framing reference, not proof of our atomic batch.
- Apple's [outgoing CKKS operation](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSOutgoingQueueOperation.m)
  saves items and current-key pointers together with atomic and unchanged-record
  policies. Its [item encoder](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/keychain/ckks/CKKSItem.m)
  uses a validating parent-key reference. These supply the application semantics.

No external implementation, schema or Apple binary is vendored or linked by
this change. Earlier read-focused references omit the request change-tag field
and use override for updates; that does not supply our required compare-and-save.

The adapter fixes the account fingerprint, CloudKit owner, joined Octagon peer,
Passwords zone and credential UUID before use. A save permits only a new v4 item
with the expected five encrypted CKKS fields and its existing class-A pointer.
Both operations use the same zone-isolated stream. The item is create-only; the
pointer is merge + fail-if-outdated with the retained tag in request field 4.
Its original server record is sent byte-for-byte, including unknown fields.
Raw pointer references are checked for the selected key, private database, zone
and owner: the legacy read projection alone loses the reference's target zone.

Responses must identify both operation UUIDs exactly once with explicit status.
Both successful acknowledgements must carry consistent tags and matching server
records. Only two recognized explicit precondition failures become a definite
rejection. Missing, duplicate, mixed, partial, indeterminate or unknown responses
remain errors; the coordinator retains Attempted and reconciles by fresh fetch.
HTTP errors do not imply rejection. The write client disables redirects and all
automatic protocol retries. An acknowledgement still does not establish backup;
the coordinator independently fetches/decrypts before producing VerifiedUpload.

The parser currently requires full server-record acknowledgements. Apple's
schema also permits other optional response fields; if live replies provide
only partial server fields, this parser deliberately returns uncertainty. That
format must be observed and validated before adding a narrowly defined merge;
do not invent an acknowledged record from an HTTP success.

Six offline tests cover request policies, typed references, exact pointer bytes,
cross-zone refusal, response matching, incomplete/error results and account/
peer/record scope. Two loopback HTTP tests verify no redirect and no resend after
a lost response. These are synthetic fixtures, not captured Apple wire evidence.

Remaining gates:

1. Read-only account validation is complete for the staged candidate: after fresh
   authentication, the isolated root/worker check fetched all 16 Passwords records,
   authenticated one TLK and resolved the current class-A key. This proves token
   acceptance at that check, not future validity or write acceptance.
2. Prepare a concrete disposable creation/upload plan and obtain explicit
   authorization for that account, zone and new record UUID. Inspect the exact
   pointer/tag and encrypted item before sending any write.
3. Validate whole-batch rejection for a deliberately invalid precondition and
   independently fetch complete absence; this must never modify a real key's
   target or rotate account keys. Scope the test to disposable item creation.
4. Validate one accepted save, both acknowledgements, independent authenticated
   fetch/decryption and use on another trusted device. Then connect the broker's
   bounded biometric lifetime, network agent and browser's iCloud storage choice.

No software signing result, simulated server, retained journal or successful
HTTP status substitutes for these gates. No root/peer/ADI regeneration, escrow
retry, enrollment change or existing credential overwrite belongs to this work.


Read gate update, 2026-11-06: after user-operated fresh authentication, the
read-only metadata probe successfully validated 14 Passwords records' zone/owner,
change tags and opaque server encoding. Octagon's recovery records separately
exposed omitted optional identifier enums; the decoder now accepts omission in
its typed context and still rejects conflicting explicit values. The recovery
metadata probe subsequently decoded 20 encrypted shares and 60 sync-key records.
These are read/format observations only: no atomic save, absence reconciliation,
TLK unwrap, broker account enrollment or other-device acceptance was performed.
Live negative/positive writes still require the concrete scoped authorization
and verification gates above.

The [disposable live-test scope](LIVE-ICLOUD-TEST.md) now fixes the account review,
new UUID, RP and username. Its isolated read-only review confirms UUID absence
and validates/fingerprints the raw current pointer and change tag. The separate
administrator example has default inspection and one-send negative/positive
modes, with offline replay/uncertainty/scope tests. It saves the exact diagnostic
ciphertext and altered pointer before a send; the normal encrypted coordinator
journal also retains the staged credential and upload state. Scope approval and
fresh biometric readiness remain pending. No write mode has been executed.
