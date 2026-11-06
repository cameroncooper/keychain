# Broker / Apple network worker boundary

`src/apple/worker.rs` implements the socket protocol and broker-side `UploadIo`.
The separate worker executable/service and minimal credential export now exist;
the broker account enrollment path exists but its browser path is not enabled.
The broker keeps its AF_UNIX-only service restriction. No Apple write or biometric
capture was used to validate this transport.

The broker constructs CloudKit requests and validates the replies. A worker
performs HTTP using its authenticated account context. The worker channel carries
raw CloudKit request/response protobufs, encrypted item data and public metadata.
There is no wire representation for a plaintext passkey, plaintext TLK, account token,
biometric grant, Snapshot or VerifiedUpload. The broker supplies authenticated
Octagon roots locally, assembles complete snapshots from individually fetched
pages and independently decrypts/verifies the item before promotion.

`WorkerClient::connect` requires root, an absolute socket path and a dedicated
nonzero worker UID different from the paired owner. Every path component must be
owned by root or that worker, without symlinks or group/other write permission.
SO_PEERCRED must report the configured worker UID. The worker's `serve` entry point
requires a nonroot service process and a root peer before reading any frame.
This authenticates service UIDs, not arbitrary applications sharing those UIDs;
the worker UID must have no owner-controlled executable/configuration or unrelated
programs. The worker must bind/listen itself: do not assume a socket activated by
root will report the worker UID to clients. A private worker-owned runtime
directory below a root-controlled parent is supported.

Every frame contains the exact owner/account/peer/transaction/browser-request/zone
Binding, protocol version and monotonically increasing operation step. Headers
are bounded at 16 KiB, raw page/reply bodies at 64 MiB, fetch requests at 64 KiB
and saves at 2 MiB. Unknown JSON fields, ambiguous scope, invalid sizes, unexpected
message types and mismatched steps fail closed. A binary payload follows the
header without JSON/base64 expansion. There is no generic URL/header RPC.

The Apple backend independently checks outgoing fetches against the canonical
bound-zone/cursor request. For saves it parses the two operations, checks the
transaction UUID, and reconstructs the canonical device/zone/create-only/CAS
stream with those operation IDs. Exact byte comparison rejects changes to modes,
zone, headers, operation flags and ignored/duplicate fields. Opaque fetched pointer
encoding is retained. The worker returns the raw response; the broker correlates
both operation UUIDs, validates saved records, and subsequently fetches/decrypts
the exact journaled ciphertext. Neither an HTTP success nor a worker reply makes
a credential eligible by itself.

The client checks a caller-supplied cancellation/session guard and a monotonic
deadline before/after IO, including each partial read/write. Socket timeouts are
40 ms; partial frames continue at their original offset. Cancellation, expiry,
disconnect, protocol failure, worker failure or raw response parse failure closes
the channel permanently. There is no reconnect or resend. An attempted write
remains uncertain in the durable upload journal, including a request which Apple
accepts after the broker cancels. A new authorized operation must reconcile it.
The worker's synchronous HTTP operation may continue until its network timeout;
the broker does not wait for it after canceling. Connect/start/handshake must
finish before capture and before any selected scalar exists. The Unix connect
syscall itself is synchronous; deployment must make readiness a preflight step.
Do not create the worker or invoke a subprocess with a live scalar.

UploadIo requires a borrowed current operation check for every fetch and save.
The journal passes it through reconciliation, explicit retry and re-encryption;
it rechecks responses before checkpointing acceptance or verified backup. The
coordinator supplies preflight session/cancel/expiry checks before capture, then
the same NativeAuthorization check used by selected-scalar signing. WorkerUploadIo
combines that per-call check with its connection check inside the frame loop.
The callback is never stored past the call. This replaces the former outer-only
GuardedIo wrapper, which could not interrupt a wait.

Active-session validation uses one fresh login1 GetAll call for the exact owner,
session ID, type, local/active state and lock hint. The entire snapshot query has
a 250-ms timeout, and timeout/error/missing/wrongly typed fields fail closed.
No successful session snapshot is cached as authorization. Cancellation and expiry
are checked again after the query. These are bounded waits under normal process
scheduling, not hard real-time latency guarantees. Tests cover malformed session
snapshots and cancellation/drop of an unresponsive query. A journal test cancels
after server acceptance, retains Attempted, and reconciles without another send.

Nine offline transport/adapter tests cover binary round trips, actual fragmented
frames across socket timeouts, wrong scope/version/step/type, unknown fields,
oversize/truncated frames, stalled-read/write cancellation and deadlines,
UID refusal, complete paginated fetches, terminal worker failures, and per-call
cancellation/expiry/session loss with an independently valid constructor check. A separate
wire test checks canonical worker request scope. A privileged disposable-process
test binds a private socket under a different UID, exercises both real kernel
peer checks and the production handshake/server loop, and exchanges synthetic
raw data only. These tests do not establish live Apple atomicity or browser UV.

## Remaining production connection

The [worker executable/service and credential bootstrap](../contrib/NETWORK-WORKER.md)
now support a dedicated UID, encrypted systemd credential package and private
local Mac anisette state. The export selects only the CloudKit token and existing
ADI seed, not PET/passwords or account private keys. Startup refuses missing,
changed or unsafe state and validates root-controlled helper/image inputs.
An actual disposable systemd service has passed credential delivery, different-UID
socket authentication, wrong owner/peer refusal and idle exit with synthetic data
and non-loopback traffic denied. No real account package has been exported or
applied, and live Apple authentication remains unverified.

The broker's [account enrollment and authenticated root bootstrap](BROKER-ACCOUNT-BOOTSTRAP.md)
now verify and pin the existing agreement identity through an administrator pipe.
The worker has a canonical enrolled-peer read-only recoverable-share operation;
recoverable and live self-shares are verified/unwrapped in the broker before
constructing its complete initial snapshot. No real account has been enrolled.
Worker start/connect and coordinator/browser configuration remain unfinished. Do not grant the worker the owner's home,
reuse the owner socket or accept owner-submitted snapshots/roots. Keep account
HTTP credentials in the worker and authenticated Octagon roots in the broker.

Connect/handshake and perform the authenticated initial fetch before showing
the biometric prompt. Use the coordinator's operation check throughout the
selected-scalar lifetime; do not bypass it with a no-op guard in production.
Then route the existing creation coordinator through WorkerUploadIo. The existing
trusted in-process seam accepts arbitrary UploadIo and is not a safe owner RPC.
Only expose the iCloud browser option after this service/bootstrap integration,
scoped live Apple validation, real biometric creation and other-device checks.
