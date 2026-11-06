# Broker / Apple network worker boundary

`src/apple/worker.rs` implements the socket protocol and broker-side `UploadIo`.
It is not yet an installed production worker service or an enabled browser path.
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

Eight offline transport/adapter tests cover binary round trips, actual fragmented
frames across socket timeouts, wrong scope/version/step/type, unknown fields,
oversize/truncated frames, stalled-read/write cancellation and deadlines,
UID refusal, complete paginated fetches and terminal worker failures. A separate
wire test checks canonical worker request scope. A privileged disposable-process
test binds a private socket under a different UID, exercises both real kernel
peer checks and the production handshake/server loop, and exchanges synthetic
raw data only. These tests do not establish live Apple atomicity or browser UV.

## Remaining production connection

Implement the separate worker executable/service and explicit account bootstrap.
Its identity/configuration and credential sources must be root controlled and
scoped to the selected account/peer. Do not grant it the owner's home directory,
reuse the ordinary owner socket, or accept owner-submitted snapshots/roots.
Keep account authentication material in the worker and authenticated Octagon
roots in the broker. Use the selected local Asahi Mac anisette helper; no remote
provider or provisioning reset is authorized by this implementation.

Connect/handshake and perform the authenticated initial fetch before showing
the biometric prompt. Bind the channel's guard to cancellation, the active local
session and the operation deadline throughout the selected-scalar lifetime.
Then route the existing creation coordinator through WorkerUploadIo. The existing
trusted in-process seam accepts arbitrary UploadIo and is not a safe owner RPC.
Only expose the iCloud browser option after this service/bootstrap integration,
scoped live Apple validation, real biometric creation and other-device checks.
