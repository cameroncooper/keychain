# Syncable creation: broker operation and network boundary

The broker connects browser creation to the isolated network worker and the
selected-secret coordinator. This path is disabled by default and remains disabled
on the development machine. No Apple write or biometric capture was performed
to validate this wiring.

`Broker::create_synced_registration` checks the configured owner, exact frozen
request and explicit decrypt/creation deployment flags, serializes the operation and validates
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
The production owner action derives account/peer/zone exclusively from the root
enrollment and binds them to the frozen browser transaction/request. It starts
the fixed systemd unit with StartUnit (never RestartUnit), observes startup state
and authenticates its kernel UID/socket before fetching roots or opening a prompt.
Only missing/refused sockets during startup are retried; a failed handshake or
interrupted command closes the channel without replay. Startup/readiness polls
cancellation, the current session and a bounded deadline. The transient readiness
guard is not retained as authorization after capture; each upload still receives
the current NativeAuthorization guard. The root systemd test also exercises
uncached active-session checks and proves that starting an active service keeps
the same PID. Direct AppleUploadIo inside the privileged broker remains prohibited;
its installed AF_UNIX-only restrictions are retained. No broker child is launched
with the selected scalar live.

The browser offers iCloud only when both `--allow-item-decrypt` and
`--allow-synced-creation` are configured and a valid root account is enrolled.
Missing enrollment hides the choice; corrupt/incomplete enrollment fails closed.
When both storage locations are offered, the application chooser requires an
explicit choice before the OS fingerprint prompt. It freezes the choice and
transaction before starting creation and never falls back from iCloud to this
device on failure. The native host accepts only the two known storage values; it
cannot supply roots, snapshots or upload receipts. Production units/installers do
not enable the new write flag.

UploadIo requires the current operation check on every fetch/save. The coordinator
passes preflight checks before capture and NativeAuthorization checks throughout
upload/reconciliation/retry. WorkerUploadIo polls that borrowed check during
partial reads/writes and permanently closes on failure. This replaces the
outer-only GuardedIo wrapper. The journal independently checks replies before
acceptance/verification checkpoints, so late results remain uncertain. Session
validation uses a fresh exact login1 snapshot with a 250-ms timeout and fails
closed on errors; it does not cache authorization. No deserialize shortcut
constructs VerifiedUpload, and no automatic replay was added.
Real account bootstrap, remaining library/scratch memory review,
scoped live Apple tests, real biometric creation
and browser/other-device validation remain gates before enabling iCloud creation.

## Installed validation (2026-11-06)

The release binaries were installed with the existing decrypt-only configuration;
ExecStart has no `--allow-synced-creation`. A synthetic owner Create request with
`storage: synced` returned Unsupported at the deployment gate, and the actual
network worker remained inactive. The installed broker/native-host availability
check passed with `--availability-only`, without capture. The separate disposable
systemd worker check passed credential delivery, kernel UID, scope refusal,
handshake and idle cleanup with no Apple/SEP IO. Seventeen privileged library
tests passed separately; the workspace has 201 passing tests and 21 ignored,
and all 11 browser flow tests pass. Format, strict Clippy and release build pass.
These checks do not establish live account acceptance, biometric creation,
registration in Chromium or synchronization to another device.

The subsequent [memory source review](SEP-MEMORY-REVIEW.md) enabled missing
AES-GCM/GHASH/POLYVAL cleanup features and identifies remaining RFC6979/HMAC and
compiler scratch limits. Protected main buffers do not establish complete scratch
erasure. The write flag remains disabled.
