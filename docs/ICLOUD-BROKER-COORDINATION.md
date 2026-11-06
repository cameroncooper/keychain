# Syncable creation: broker operation and network boundary

The broker now has a trusted in-process creation coordinator. It is not exposed
through browser/owner IPC, and the browser still offers device-only creation.
No Apple write or biometric capture was performed to validate this addition.

`Broker::create_synced_registration` checks the configured owner, exact frozen
request and explicit decrypt deployment, serializes the operation and validates
the active local session. It fetches the initial hierarchy before presenting
the desktop prompt or holding a scalar. Exclusion disclosure shares the native
registration path's verified-presence policy. The registry durably stages the
key before a selected biometric decrypt begins.

The existing protected-signing path and creation now share one selected-scalar
lifetime. The driver result and exact item binding are checked before creating
a private borrowed `SelectedScalar`. That value has no plaintext accessor,
serialization or reusable grant. It can prepare encrypted CKKS data and sign
only the selected record. The primary decrypted scalar and assembled X9.63
input use checked locked, dump-excluded, non-inherited memory. They are wiped
when the operation returns, including errors. Creation serializes a zero-filled
private-data placeholder directly into a bounded 64-KiB protected allocation.
A strict flat binary-plist locator identifies that data object; only after the
serializer has finished are the real bytes inserted and encrypted in place.
Fresh item keys and key-wrapping plaintext also use protected allocations.
Fetch verification unwraps/decrypts directly into protected memory, checks the
key, and erases private data before the owned plist parser sees the metadata.
Decryption errors wipe the entire destination, including authentication failures.

AES key-schedule and CMAC state cleanup features are explicitly enabled;
AES-SIV also zeroizes its retained encryption key on drop. This does not prove
erasure or locking of every cryptographic/compiler stack copy. Existing account
TLK/class-key resolution still uses zeroizing heap buffers; this change does not
implement protected root unsealing or harden every legacy software/read path.
No secrets enter the plist writer's owned event table on this creation path.
Tests cover the encoder/reader round trip, bounded and malformed binary plists,
mapping protections at both buffer sizes, an isolated memlock-failure process,
and in-place cryptographic compatibility/error erasure.

Within that lifetime, the coordinator:

1. Reopens an existing upload journal under its transaction lock before calling
   any encryption factory. Corruption or missing roots cannot trigger replacement.
2. Checks the journal against the selected key, complete credential and frozen
   account/peer/request binding. A new journal gets ciphertext prepared from the
   initial authenticated snapshot; the scalar never enters the IO interface.
3. Reconciles/fetches and, where appropriate, sends the prepared upload. A normal
   resume does not resend an uncertain attempt or re-encrypt a rejected one.
   Explicit recovery choices enable confirmed-absence retry or rejected-upload
   re-encryption with the same key and retained ciphertext history.
4. Obtains a typed VerifiedUpload from independent fetch/decrypt verification,
   signs the exact WebAuthn registration using the still-selected scalar, and
   commits through the registry's durable activation sequence. No second decrypt
   or persisted UV result is used to bridge upload and signing.

The desktop status changes to saving after the driver completes, so the prompt
does not keep asking for a finger during upload. Session/cancel/deadline guards
surround preparation, worker calls, signing, commit and delivery. A result received
after cancellation is discarded even if the server saved the record. A new
authorized operation can reconcile that attempt without another send.

Five disposable root integration tests passed with a synthetic recipient and
server: complete creation/fresh-process delivery retry, lost upload reply,
cancellation before and after acknowledgement, explicit recovery policies and
changed selected key/expired-operation refusal. These tests simulate biometric
completion; they do not prove one-fingerprint behavior on hardware or browser
acceptance. The journal factory/resume behavior has an additional offline test.

The [network-worker transport](APPLE-NETWORK-WORKER.md) now supplies a separate-UID,
scope/step-bound, bounded and cancellable socket implementation of UploadIo.
Raw CloudKit messages cross this boundary; roots stay local to the broker and
reply validation/fetch verification still run there. The worker independently
checks canonical request scope before HTTP. A disposable different-UID process
test verifies the real kernel peer checks and handshake. The production worker
service and selective credential export now exist; its actual systemd startup
test passed with synthetic data. The separate [broker account bootstrap](BROKER-ACCOUNT-BOOTSTRAP.md)
now pins the existing signed identity, imports its agreement key and authenticates
recoverable/live self-shares before constructing the initial complete snapshot.
Worker startup, coordinator connection and browser integration remain unfinished. The UploadIo
supplied to this coordinator is still a trusted internal dependency, not an owner
RPC. Direct AppleUploadIo inside the privileged broker remains prohibited; its
installed AF_UNIX-only restrictions are retained. Start/authenticate the worker
before capture; never fork/exec with the selected scalar live.

UploadIo requires the current operation check on every fetch/save. The coordinator
passes preflight checks before capture and NativeAuthorization checks throughout
upload/reconciliation/retry. WorkerUploadIo polls that borrowed check during
partial reads/writes and permanently closes on failure. This replaces the
outer-only GuardedIo wrapper. The journal independently checks replies before
acceptance/verification checkpoints, so late results remain uncertain. Session
validation uses a fresh exact login1 snapshot with a 250-ms timeout and fails
closed on errors; it does not cache authorization. No deserialize shortcut
constructs VerifiedUpload, and no automatic replay was added.
Production service/bootstrap integration, remaining library/scratch memory review,
scoped live Apple tests, real biometric creation
and browser/other-device validation remain gates before enabling iCloud creation.
