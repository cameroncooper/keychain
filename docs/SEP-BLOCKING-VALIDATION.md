# Blocking SEP application-key migration — 2026-11-08

The provider now uses `/dev/sep-keys`, interface version 1, as specified by
[the migration handoff](SEP-BLOCKING-MIGRATION.md). No key, protected item,
record identity, enrollment, keybag or recovery copy is rewritten by this port.
Historical polling failure reports remain evidence, not current ABI guidance.

## Implementation

- Pinned canonical UAPI header from tested source `56800a8bf`; build-time C probe
  generates constants and compile-time Rust size/offset assertions. No second
  ioctl-number table, START/POLL or application-key BIO capability interpretation.
- INFO validates version and reserved fields. Requested signing/decryption
  capabilities are checked separately; zero capabilities prohibit operations.
  INFO and browser capability advertisement do not establish sensor health.
- CREATE sends full blob capacity and explicit policy without a scan or request
  ID. Existing application storage/version and authenticated envelopes stay intact.
- SIGN and DECRYPT allocate strictly increasing nonzero per-file IDs before
  dispatch. A scoped caller makes one direct libc blocking ioctl, with no EINTR
  retry or automatic EBUSY replay. The control thread independently checks
  application authorization and deadline every 25 ms (plus bounded session/IPC
  checks); it never waits for driver progress or polls for retained results.
- Cancellation revokes local delivery before issuing CANCEL on the same File.
  The caller is joined before descriptor/buffer release, including callback
  unwind. EALREADY/ENOENT cannot authorize raced success. Driver errors preserve
  their errno even if UI cancellation races them. Timing logs contain request ID,
  stage and numeric errno only, not credentials or ioctl payloads.
- DECRYPT writes directly into the existing caller-owned protected mapping.
  Failure, partial copy, cancellation and unwind wipe its whole capacity; success
  still requires trusted item-context validation and consumer-controlled wiping.
- Broker checks prompt disconnect before the bounded session query and again
  afterward. Unchanged generic touch text is not resent on every control check.
  There is no sensor guidance API in this transport.
- CLI defaults and the systemd device allowlist use only `/dev/sep-keys`.
  Production iCloud-write policy remains separately disabled.

## Evidence and remaining live checks

Software tests cover same-file cancellation while a fake caller blocks,
pre-dispatch retirement, caller joining, deadline revocation, fast/raced success,
original errno preservation, no private-operation replay, partial-output wiping
and callback panic cleanup. Existing workspace tests exercise envelope context,
protected memory and broker policy. These tests do not replace a real scan.

Default-feature workspace/all-target tests passed (234 library tests, 26
explicitly ignored live/privileged tests, all executed binary/example tests and
12 driver tests). Driver Clippy with warnings denied, desktop-agent/all-target
compilation and 11 Chromium extension tests passed. Build-time C assertions
verified the pinned header's structures and ioctl constants.

Hardware/application evidence, America/Chicago:

- INFO: version 1, signing and decryption advertised. Both disposable key files
  retain their 2026-11-05 timestamps; no replacement key was created.
- 08:37:53: existing combined key decrypted a new synthetic envelope, checked its
  trusted context and rejected the wrong context. Output used the existing
  16384-byte locked/dump-excluded mapping. No plaintext was printed.
- 08:39:26: initial cancellation attempt completed a verified signature internally,
  which the diagnostic broker withheld. No Escape was logged. The user initially
  reported no touch, then said they could be mistaken and requested a repeat.
  This attempt is not counted as cancellation or no-finger evidence, and no
  cause or fresh-touch claim is inferred from the return value alone.
- 08:41:09.064635: repeat logged Escape. At 08:41:09.098179 the broker observed
  prompt revocation and issued CANCEL on the same file; CANCEL returned zero and
  blocking SIGN returned ECANCELED (125). The caller joined with revocation true;
  no signature was delivered. Escape-to-CANCEL was approximately 34 ms.
- 08:41:35–37: a separately approved fingerprint signed a distinct diagnostic
  message with the same existing key. Independent signature verification passed,
  without module reload, secure-state changes or driver reset after cancellation.
- The release broker and `/dev/sep-keys`-only systemd allowlist were installed.
  Normal socket activation reported the active paired session and available key
  API. Existing item-decrypt opt-in remains; iCloud creation remains disabled.
  Previous binary/unit: `/var/lib/keychain-service-backups/blocking-api.ubFgVGfi`.

The retained diagnostic registry is `/var/lib/keychain-os-check-20261107/registry`,
record `24cc9dd4-abb5-4a84-b4ad-5ef1d64162b9`. Its transient unit is
`keychain-blocking-cancel-check-20261108.service`; the unit and desktop-agent
journals hold timing evidence. Before the actual checks, a stale agent socket and
incorrect temporary-service sandbox paths caused setup failures; these stopped
before any private operation. No uncertain ioctl was replayed automatically.

Logs: `/tmp/keychain-blocking-migration-tests.log`,
`/tmp/keychain-blocking-clippy.log`, `/tmp/keychain-blocking-desktop-check.log`,
`/tmp/keychain-blocking-browser-tests.log` and `/tmp/keychain-blocking-release.log`.
Live prompt-disconnect validation is pending separate readiness. Broader browser
and cross-device gates in [the integration plan](../SEP-IMPLEMENTATION.md) remain
open until verified. Historical failure attribution has not been rewritten.
