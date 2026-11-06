# Rust SEP application integration evidence

Date: 2026-11-05. These are application-side runs against the loaded local driver,
separate from the maintainer's [driver validation](sep-driver/VALIDATION.md).
The sections below record successive stages. Earlier temporary-service limits are
superseded only where the installed-service evidence at the end explicitly says so.

Latest registration update: the deployed release broker and native host passed
creation inspection with no key creation/capture, both in the installed profile
and a separate empty root registry with no account state. The isolated service
is `keychain-native-create-check.service`, registry
`/var/lib/keychain-native-create-check`, private owner socket
`/run/keychain-native-create-check/broker.sock`. Actual biometric registration,
subsequent signing with that native credential, and Chromium/RP acceptance remain
pending. See [registration test commands and limits](SEP-REGISTRATION.md).

## Implemented path

`keychain-sep` -> `NativeSepProvider` -> `keychain-sep-driver` -> `/dev/sep-bio`.
The driver crate contains the unsafe ABI/memory operations; the main crate keeps
`unsafe_code = "deny"`. Neither Python nor kernel-log parsing is on this path.

The diagnostic is privileged and operates only on explicitly named disposable
application keys. It is not the production broker or a passkey registration flow.
It does not read the current account/vault or change fingerprint enrollments.

## Hardware observations

1. GET_INFO: ABI 4; biometric signing advertised; sensor present; two enrollments.
2. CREATE: a fresh signing-only application key was created and its wrapped blob
   and expected P-256 public point stored privately.
3. SIGN: a real fingerprint produced a DER signature on the first diagnostic
   message. Independent RustCrypto verification against the saved public point
   and SHA-256 of the exact message passed.
4. A fresh process signed a distinct message with another fingerprint and the same
   saved key. Verification passed. This was initially intended as a finger-off
   check, but the user reported touching the reader; it counts as positive evidence.
5. A repeated fresh request with finger explicitly off expired in five seconds;
   no signature was returned.
6. Explicit callback cancellation at 300 ms returned Canceled without a signature.
   A following fresh exclusive open/GET_INFO succeeded. This demonstrates delivery
   cancellation and subsequent device availability, not independent inspection of
   internal SEP context deletion.
7. CREATE with decrypt policy: a separate fresh application key was stored.
8. Rust seal_item encrypted synthetic data and its expected item context. Real
   biometric decrypt wrote it into a dedicated locked/dump-excluded allocation.
   The item matched exactly; substituting a different expected context was rejected.
   No plaintext was printed. The mapping was 16384 bytes (runtime page size), while
   the driver's output capacity remained 4096 bytes. Process nondumpability was
   installed before decrypt; failure to install protections aborts the diagnostic.

Disposable records are retained for same-key reboot checks:

```text
state/sep-check-20261105/disposable.json
state/sep-check-20261105/disposable-decrypt.json
```

These root-owned private files are in the checkout's ignored state directory;
their original temporary copies remain under /tmp/keychain-sep-check.Vy5cx4/.
They are not portable backups or production credentials. Do not substitute the
maintainer's keys or revive old secure-state artifacts. No system reboot was
performed by this work.

## Software checks

- C-header executable confirms all ioctl constants, structure sizes and relevant
  pointer offsets against the vendored header; also checked by Rust size assertions.
- Invalid input bounds, impossible states/status combinations and signature sizes
  fail closed. No operation automatically retries ambiguous completion.
- Existing fake-provider tests check exact-message signatures, missing verification,
  wrong request IDs, metadata mismatch, cancellation and replay/expiry handling.
- Rust item envelope tests cover software round-trip, wrong context, tag mutation,
  truncated envelope and size limits. The positive hardware run additionally
  confirms the Rust ciphertext profile against the real decrypt primitive.
- `/proc/self/smaps` test confirms the dedicated synthetic-secret mapping has
  `lo`, `dd` and `dc` flags (locked, dump-excluded, not inherited across fork).
- Workspace tests: 95 passed, one Apple-network test ignored. Strict workspace
  Clippy passes. Hardware tests above are manual integration evidence, not unit tests.

## Broker and desktop-agent integration

A temporary privileged systemd service (`keychain-broker-check.service`) uses an
encrypted root-owned disposable registry at `/tmp/keychain-broker-registry.zE7Skz`
and a root-controlled socket at `/run/keychain-check/broker.sock`. The enrolled
diagnostic record is `4483ffdc-53e4-4107-aa12-4cdad504c03a`. This is not a website
registration or a migrated vault record. The GTK agent runs as UID 1001 and has
no device access; its private runtime socket authenticates the root peer.

Observed results:

- Normal-user broker Status validated UID 1001's active local desktop via logind.
- Normal-user broker Sign returned an independently verified native signature
  through the root broker and unprivileged desktop prompt.
- A prompt-only test received cancellation with no SEP operation started.
- The first attempted real cancellation checks instead returned signatures; the
  user clarified they touched the reader because the normal UI instructed them
  to. These are positive signing observations, not cancellation evidence.
- A dedicated test changed both title and status to explicitly request Cancel
  and no touch. The real SEP operation then returned typed Canceled with no
  signature delivered through the broker.

Source checks additionally cover bounded messages, kernel peer identity, no
agent-success protocol variant, caller disconnect/cancellation, backup flags for
device-bound versus synced credentials, and cancelable pre-operation device
waiting. A separate root-only temporary-registry test passed wrong-owner/path
rejection, authenticated ciphertext tampering and missing-metadata-root refusal.
Workspace checks now have 101 passing tests and two ignored; the privileged
registry test passed separately. Strict all-feature workspace Clippy is clean.

The installed service templates are prepared but not deployed/validated. Direct
systemd verification reached the expected missing `/usr/libexec/keychain/`
executable check; do not report an installed-service validation pass. The test
service uses explicit debug binaries and enables diagnostics only for disposable
records. The packaged service disables diagnostics.

## Remaining acceptance work

Controlled reboot of the newly migrated broker record's full persistence chain;
wrong-finger testing; hardware rejection
of a mutated Rust ciphertext; decrypt cancellation/timeout/consumed delivery;
protection-setup failure injection; fuller driver mock state-machine tests; and
expanded registry policy/import tests remain. Kernel header guarantees
about cleanup are relied upon, not independently proven by Rust signature checks.

Broker/agent foundations and the normal-user diagnostic path are implemented.
Installed service hardening/activation, actual fprintd coexistence, real browser
flows, real-vault migration/recovery and both creation/sync choices remain pending.
No real vault migration or Apple upload has occurred. These observations do not
establish completion of the full SEP plan.

## Protected synthetic synced passkey

The temporary `keychain-protected-check.service` enables diagnostics and the
compatible item-decrypt extension, using the existing temporary root registry.
The root-created item recipient is `a682f663-e393-4fa4-8afd-dc8df87dd442`.
A normal-user client generated and encrypted a fresh synthetic scalar before
sending it to the broker. Record `dc519d28-540d-4f3f-befb-3f449fd52203` completed
a real biometric decrypt, context/scalar/public-key validation, software signature
and independent verification, returning only revision 1 and verified status.
The synthetic source scalar was discarded by the diagnostic client. No real
credential or Apple state was used.

The subsequent staged-commit implementation has restart tests covering pending
replacement retention and interruption between durable commit and staging
cleanup. Both privileged registry tests pass. Workspace checks now have 106
passing tests and three ignored. Four service-worker tests cover single-account
automatic prompting, multiple-account selection/replay, software presence
approval and website abort disconnection. Rust tests also check broker-only
origin validation/no fallback, cancellation transport, scalar/public mismatch,
exact-message signing and synced assertion flags. These are not a substitute for
a real browser sign-in or power-loss/I/O failure injection.

## Broker idle lifecycle

Serve now defaults to exiting after 120 seconds with no queued/active requests,
configurable with `--idle-timeout`. A privileged temporary-registry integration
test held a partial request open beyond the configured idle interval, verified
the listener stayed alive, disconnected the client, and observed successful idle
exit. No device was opened. The unit test covers queued/active counters and idle
clock reset. Installed socket reactivation is still untested. Current workspace
checks: 107 passed, four ignored; the privileged listener test passed separately.
Strict all-feature Clippy passes. The temporary protected-item test service was
queried and confirmed inactive; no successful restart or new staged hardware run
is claimed from the interrupted tool attempt.

## Restored driver, persistent registry and synthetic migration

After reboot the old `/tmp` registry/profile and session agent were absent, and
GET_INFO initially reported the application-key API unavailable. The user
restored the compatible module; GET_INFO then returned ABI 4, signing available,
sensor present and two enrollments. No system keybag, enrollment or xART changes
were made by this project to restore it.

The new private root diagnostic registry is
`state/sep-broker-check-20261105`, recipient
`deaf8eed-d75b-4520-83ee-8a00ef243f32`. It survives removal of `/tmp`; its temporary
service still uses debug executables, diagnostics enabled and an explicit socket,
so this does not validate installed socket activation.

The disposable user profile `.sep-check-migration-20261105` is private and ignored
by Git. Record `91090a8e-eeac-408f-9a4d-52ed66272e72` first expired without a
completed fingerprint. An explicit resumed CLI invocation then verified the
already-staged scalar, committed revision 1 and broker-only configuration, and
retained the original software recovery copy. The real profile was untouched.

`contrib/check-synthetic-browser.cjs` inspected that credential through a fresh
native-host process, then requested an assertion through another fresh process
and the real desktop/SEP path. Node/OpenSSL independently verified the ES256
signature, RP hash, challenge/origin, unchanged credential ID/user handle and
UP/UV/BE/BS flags. Only metadata and assertion data crossed this native messaging
path. This is synthetic native-host integration, not Chromium/RP registration or
a real website login.

Both older disposable SEP key files have mtime/ctime 1793904657, before current
kernel boot time 1793914418. Native signing again verified after a fingerprint
with `disposable.json`. Rust sealing/decryption again matched plaintext and
context using `disposable-decrypt.json`, with a 16384-byte protected mapping and
desktop prompt. This proves same saved keys working after reboot; the checker
does not independently classify warm reboot versus power cycle. A reboot check
of the newly migrated broker record's complete persistence chain remains pending.

Latest software checks: 116 workspace tests passed, four ignored; the two root
registry tests and root listener test have separately passed. Five browser-flow
tests pass, including backend-driven availability without a dialog. Strict
all-feature Clippy and diff whitespace checks pass.

After rebuilding/restarting the persistent diagnostic broker, a real fresh
native-host capabilities request returned verification available without showing
a prompt. This additionally exercises live metadata, agent peer/liveness and
current device checks; it is not proof of decrypt support inferred from the
signing bit. The positive decrypt/sign run above establishes that separately for
the tested deployment.

## Installed services, fprintd coordination and current repair gate

Release binaries are installed root-owned mode 0755 at
`/usr/libexec/keychain/keychain-broker` and `keychain-auth-agent`. System and user
units are root-owned mode 0644 under `/etc/systemd/`. UID 1001 is explicitly
paired by the private root-owned `/etc/keychain/sep-owner`; the broker socket
`/run/keychain/broker-1001.sock` belongs to that user and is mode 0600. The registry
is `/var/lib/keychain-broker/1001`, with item recipient
`c418d395-b2c9-4af4-951a-87a150820351`. The explicit deployment drop-in enables
the compatible item-decrypt extension. Production diagnostics remain disabled.

Installed units passed `systemd-analyze verify --man=no`. An idle broker exited
cleanly while its socket stayed active; a subsequent normal-user request started
a different process (observed completed PID 32039, then PID 34818). The root-owned
units use the runtime-directory bind and other hardening in
[deployment notes](../contrib/SEP-SERVICES.md). This supersedes earlier statements
that installed activation/reactivation had not been tested.

Disposable profile `.sep-check-installed-20261105`, record
`da294ad0-4110-4487-a95c-52a0236e0f85`, completed selected migration through the
installed broker and user-service agent. A fresh release native host assertion
was independently verified with Node/OpenSSL, checking signature, unchanged
credential identity, RP, challenge/origin and UP/UV/BE/BS flags. It retained its
software recovery copy. This is synthetic native-host evidence, not a real
Chromium website login or a registered device-bound credential.

`keychain-sep fprintd-coexistence-check` held a real fprintd D-Bus Claim, observed
the installed broker report the SEP device busy and its verification request
remain pending for three seconds, then released only that client's claim. A
fingerprint completed broker verification, and the following probe reported the
device available. The diagnostic did not use VerifyStart, enroll/remove prints,
release another client's claim, or restart fprintd. This supersedes the earlier
pending coexistence gate for this deployment.

A later read-only recheck confirmed the user agent active, the installed socket
listening, root ownership/modes unchanged, and
`check-synthetic-browser.cjs ... --availability-only` succeeding without a prompt.

The user's real-profile WebAuthn migration did not start. A user sync exposed a
separate trust/key-access issue: Apple authentication succeeded, but six Passwords
items lacked a readable class key, and signed peer metadata excluded this client.
The old client replaced its cache with an empty projection. No Apple item deletion
or SEP migration caused that loss. Sync now fails closed and preserves/backs up
cache state. Explicit `join --repair` is implemented with encrypted journaling,
old peer-key retention and complete independent replacement-snapshot verification;
the affected account still needs the user to run escrow recovery locally. See
[sync recovery](SYNC-RECOVERY.md). Do not report the real cache or trust as repaired.

Latest workspace checks: 135 passed, five ignored; five browser-flow tests pass
and strict workspace/all-target Clippy is clean. The new repair tests inject
interruption around promotion, sponsor retirement and the final journal rename.
They establish offline transition behavior, not live Apple acceptance. The full
SEP plan remains incomplete: real browser/migration/reboot gates, protected
password/TOTP reveal, retirement/recovery and both registration/storage choices
still require work.

The fresh escrow sign-in gate exposed an obsolete anisette/provider compatibility
failure, separate from SEP. A standalone local Rust Mac-CoreADI emulator helper
has now been built and selected on Asahi. Real-account SRP init passed through the
installed adapter without any password proof, and its 31-second OTP freshness check
passed offline. These are not full login or trust-repair evidence. The Prepared
repair journal and old keys remain; see [authentication details](APPLE-AUTH-COMPATIBILITY.md).


## Selected login/TOTP hardware run — 2026-11-06

The isolated installed broker/desktop agent completed real SEP decrypt for a
published synthetic login: initial verification, all-fields reveal, then revision
2 verification/commit/reveal within one biometric lifetime. The user confirmed the
expected prompts and single-operation update UX. A separately authorized fresh
client process revealed revision 2 again. A separately authorized Cancel/Escape
check returned Canceled, no successful fields and unchanged revision 2; no-prompt
status then reported the reader available. Exact fixture IDs, command and limits
are recorded in [login acceptance](SEP-LOGIN-REVEAL.md#live-synthetic-login-acceptance--2026-11-06).
This supersedes the earlier absence of any hardware login/TOTP reveal evidence,
not the remaining real-account migration, session-lock, browser or reboot gates.
No Apple requests, real credential reveal or source-copy retirement occurred.
