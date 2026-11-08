# SEP provider migration to the blocking application-key API

The MacBook now runs the hardware-tested blocking module from
[PR 407](https://github.com/omacom/linux-aurora/pull/407), source commit
`56800a8bf`. The packaged kernel is `7.2.11-15-1-ARCH`; native boot, existing
enrollments, provisioning settings and xART policy are unchanged. USB proxy
hardware is not required. This module is installed for normal boot, not hot-loaded.

**Application keys now use `/dev/sep-keys`, interface version 1.**
`/dev/sep-bio` remains the fingerprint/enrollment interface, version 4. Its info
reserved fields no longer advertise application-key capabilities. The previous
application-key START/POLL ioctls are absent. An old provider reporting that the
key API is unavailable must be migrated; restarting it cannot add those ioctls.

This document supersedes the transport descriptions in `docs/sep-driver/README.md`,
`DECRYPTION.md`, `sep-key.py` and `sep-bio.h`. Those files describe the old polling
prototype. Keep historical failure reports as evidence, not the current ABI.

## Exact reference material on this machine

The following are source-only copies from the tested PR, outside the application:

```text
/home/cameron/.local/share/aurora-sep/application-keys/
    README.md
    sep_key.py
    sep_envelope.py
    include/linux/apple-sep.h
```

The canonical source is
[`include/uapi/linux/apple-sep.h`](https://github.com/cameroncooper/linux-aurora/blob/56800a8bf/include/uapi/linux/apple-sep.h).
Use its `SEP_KEY_*` structures and macros for Rust FFI layout/ABI assertions.
The distro's installed headers may predate these additions; the isolated include
directory above supplies the matching header without changing system headers.
`sep_key.py` is importable and uses direct libc ioctl calls. It requires Python
3.11+ and `cryptography`. The existing test interpreter is
`/home/cameron/.cache/sep-pr-review/venv/bin/python`.

Read the reference README for policy/security limits and the header for exact
layouts. Do not retain a second independently maintained table of ioctl numbers.

## Provider changes

Start in `crates/sep-driver/src/lib.rs`, then adapt its callers in
`src/broker/native.rs`. No application implementation was changed by the driver
installation or this documentation handoff.

1. Open `/dev/sep-keys` read/write with close-on-exec in the privileged broker.
   Query `SEP_KEY_INFO`, require version 1 and zero reserved fields, and check
   the requested capability. Signing is capability 1, decryption is capability
   2. Zero capabilities mean unavailable, including a credential-cleanup poison
   latch. INFO is not a sensor health test. Keep device access privileged.
2. Creation uses `SEP_KEY_CREATE`, with flags 0 for the signing policy or
   `SEP_KEY_CREATE_DECRYPT` for combined signing/decryption. Supply the header's
   full blob capacity and zero reserved fields. Persist the returned wrapped
   blob and public point atomically in authenticated application storage.
   Creation needs no scan and has no private-request cancellation ID.
3. Signing uses one blocking `SEP_KEY_SIGN` call with a nonzero request ID,
   32-byte prehashed SHA-256 digest and timeout of 1..120000 ms. Initialize the
   output length/signature and flags to zero. The result is a DER ECDSA signature.
   WebAuthn signs SHA256(authenticatorData || clientDataHash), exactly once.
4. Decryption uses one blocking `SEP_KEY_DECRYPT` call with the existing wrapped
   blob, sealed envelope, output pointer/capacity, timeout and zero flags/reserved.
   Validate the returned length and trusted expected item context before use.
   The envelope's cryptography and native key policy did not change with this
   transport migration; do not rotate or rewrite existing items just to port it.
   Validate an existing disposable key before migrating real records.
5. Remove START/POLL/result-retention handling for application keys. There is no
   result-retrieval ioctl, unread-result timer or guidance poll on the new node.
   Show a generic touch prompt while a dedicated caller thread blocks.

## Cancellation and request lifetime

Allocate the request ID **before** dispatching that caller thread. IDs start at
1, strictly increase per open file, never wrap and must not be reused, including
after failed submissions. Keep one logical request active on each open file.

The UI/broker cancellation path must remain able to issue `SEP_KEY_CANCEL(id)`
on the **same open file** concurrently. Do not hold a provider-wide mutex around
the blocking ioctl if CANCEL needs that mutex. Share an owned file context safely;
opening another key device file does not cancel the original file's request.

On Escape, prompt disconnect, session revocation or timeout:

1. Revoke application delivery immediately in the broker's own request state.
2. Call CANCEL for the allocated ID from the cancellation/control thread.
3. Join the waiting caller before releasing its file context and buffers.
4. Discard and wipe any result belonging to a revoked application request,
   including a success that raced cancellation.

CANCEL before acceptance retires not-yet-accepted IDs through that ID. It does
not cancel a different active request. `EALREADY` means the result was already
claimed; `ENOENT` means no cancellable accepted request remains. Neither permits
delivery of an application-revoked result. Closing a descriptor from another
thread does not interrupt an ioctl already using it. The hardware worker may
still be cleaning up after its waiting caller returns.

Do not depend on periodic progress callbacks to notice Escape; the application
must send CANCEL while its blocking caller is asleep. Cancellation revokes
delivery, not a signature/decryption operation already submitted to firmware.
Preserve the original driver errno when a failure wins the race: a canceled UI
does not prove firmware cancellation. Log cancellation receipt, ioctl entry/exit,
errno and timing separately, never payloads or credentials.

## Errors and plaintext ownership

Issue each private-key ioctl **once**. Audit the syscall wrapper for automatic
EINTR retry. Direct `libc::ioctl` with explicit errno handling is suitable; generic
"retry interrupted syscall" helpers are not. An accepted operation's `EINTR` is
final. A fresh explicit user request needs a new ID and fresh authorization.

- `EBUSY`: refused before hardware submission. A bounded, cancelable wait before
  a new attempt with a new ID is permitted. Idle BIO files can coexist; active
  sensor/firmware operations are serialized by the driver. Do not stop fprintd
  just to open the key node.
- `ECANCELED`, `ETIMEDOUT`, `EACCES`: canceled delivery, expired request or
  authentication refusal. Return no secret; do not silently resubmit.
- `EIO`: transport/protocol/decryption/cleanup failure, possibly uncertain
  completion. Preserve that uncertainty and do not automatically repeat it.
  A bad ciphertext tag also receives a generic failure.
- `EOPNOTSUPP`: unsupported profile or key API failed closed. Failed firmware
  credential disposal disables key operations until reboot, rather than returning
  an otherwise successful result. An application restart does not reset it.
- `EFAULT`, `ENOSPC`: the result is consumed. Wipe the whole destination even
  when only descriptor copyout failed: plaintext may already have been copied.
  A larger buffer does not permit fetching the same result again.
- `EROFS`: required persistence is disabled. Do not change provisioning or
  secure-state policy from the provider to work around it.

The caller owns successful plaintext and must wipe it after use. Cancellation
cannot recall a copy already in progress. Request deadlines do not bound a
fault-stalled user copy or erase application memory. Continue the existing
zeroizing-buffer, core-dump, memory-locking and plaintext-lifetime work in
`docs/sep-driver/SECRET-HANDLING.md` and `docs/SEP-MEMORY-REVIEW.md`.

## Key policies and password fallback

Every private-key operation obtains a fresh kernel-owned biometric credential;
that credential never reaches userspace. Any enrolled finger currently qualifies.
Enrollment changes do not invalidate existing keys. A trusted broker must still
enforce user/session identity, item ownership, operation restrictions and WebAuthn
RP/origin rules. A touch does not authenticate what the host displays.

Native keys sign internally; unsealing an imported/synced software passkey returns
its plaintext to the host, which then signs. Private-key import into SEP's native
signing format is not implemented. Combined keys enable both signing and
decryption; the broker must enforce its narrower per-item usage rules.

There is no SEP-enforced human passphrase fallback. The driver's identity-bag
secret is machine-held setup data, not a user factor. For password-or-Touch-ID
recovery of encrypted items, a broker can wrap the same random item key through
independent SEP and passphrase-derived recipients. That password path is enforced
in software, not SEP. It does not unlock the same native SEP signing key.
Do not change the device keybag secret or add a passcode-OR-biometric ACL here.

## Focused application validation

Use throwaway records and do not alter existing protected items during the port.
Driver-level tests already cover key-node-only initialization, signing,
decryption, tag rejection, cancellation, real signal interruption, copy faults,
no-finger refusal, idle BIO coexistence, fprintd matching and first signing after
suspend/resume. Do not repeat that entire hardware campaign in the application.

The application-specific checks are:

- One disposable existing blob and envelope work through the migrated provider.
- Escape and prompt disconnect send CANCEL promptly while the caller blocks;
  raced success cannot release a secret or signature to a revoked request.
- Cancel/no-finger/failure paths wipe output and never replay a private operation.
- Successful decrypt validates trusted context and wipes after consumer use.

For an independent smoke test, run `sep_key.py selftest-decrypt` with a disposable
combined-key JSON from its reference directory. It requires a fresh scan and
uses random throwaway plaintext. Do not use a real keychain record as test input.
