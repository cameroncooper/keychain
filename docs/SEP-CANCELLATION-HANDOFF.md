# Escape cancellation versus SEP failure — 2026-11-07

**Attribution is unresolved.** Escape reached the desktop agent, but we have not
proved when the kernel received CANCEL. Calling this a confirmed driver bug was
premature.

Environment: Asahi/M1, kernel `7.2.11-15-1-ARCH`, SEP ABI 4, two enrolled prints.
After the OS/driver update, both saved-key biometric signing and synthetic item
decryption passed. Software tests and a read-only authenticated CloudKit fetch
also passed.

## Observed failure

The user agreed to keep their finger off the reader and press Escape during the
disposable broker cancellation check. No signature was delivered. Times below
are America/Chicago:

- `15:22:17.162603`: agent logged `prompt presented`.
- `15:22:18.365533`: agent logged `prompt canceled by Escape`.
- `15:22:18.421425`: broker logged `SEP driver completion uncertain: errno=5`.
- `15:22:18.422190` onward: kernel logged sensor session reply `ETIMEDOUT`,
  failure 1254 ms after power-on, sequence-counter session setup failure, and
  `verify: the sensor did not come back online`.

The application returned “SEP operation completion is unknown,” not a clean
Canceled result. GET_INFO still worked afterward; that does not prove sensor
health. The timestamps alone cannot establish causality or exact syscall order.

## Relevant application path

- `src/desktop/auth.rs`: Escape removes the window; its channel sends Cancel
  and shuts down the prompt connection.
- `src/prompt.rs`, `PromptSession::from_visible`: the reader sets a cancellation
  flag on any subsequent message/disconnection. It does not directly issue a
  driver ioctl.
- `src/broker/native.rs`: `NativeAuthorization::progress/check` observes that flag.
- `crates/sep-driver/src/lib.rs`, `Device::sign_digest`: START, then POLL and
  terminal/error processing, then the progress/cancellation callback for a
  pending result. Poll waiting is bounded to 100 ms. A driver error can therefore
  win before the next cancellation callback.
- `Operation::drop` issues CANCEL for unfinished operations but ignores its
  return value. Current logs do not show CANCEL entry, return or cleanup timing.

Investigate whether CANCEL reached the driver before the failure, whether
START/POLL blocked during bring-up, and whether cancellation interrupted sensor
setup or merely raced an independent timeout. Instrument monotonic timestamps
for flag receipt, START/POLL/CANCEL entry/exit and worker cleanup; log stages and
errno only, not ioctl payloads or credentials. Preserve uncertainty rather than
masking EIO as successful cancellation.

## Retained diagnostic state

Registry: `/var/lib/keychain-os-check-20261107/registry`; disposable record:
`24cc9dd4-abb5-4a84-b4ad-5ef1d64162b9`. It references the existing disposable
signing key, not a real passkey. The test service was
`keychain-os-cancel-check-20261107.service` and has been stopped; its journal and
the user agent's journal retain the evidence. No module reload, secure-state
reset or automatic retry was performed. Any live reproduction needs fresh user
readiness.
