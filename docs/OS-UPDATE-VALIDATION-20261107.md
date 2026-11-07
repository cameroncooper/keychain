# OS/driver update verification — 2026-11-07

Kernel: `7.2.11-15-1-ARCH`; running SEP API reports ABI 4, signing support and two
enrolled prints. Installed broker and agent hashes match the release artifacts.
This is a partial acceptance record, not a claim that all integration gates pass.

| Check | Current evidence |
| --- | --- |
| Existing native key | Fresh user-approved fingerprint signed a new public diagnostic message; independent signature verification passed |
| Existing decrypt key | Separate user-approved fingerprint verified synthetic decryption, exact context and a 16-KiB locked/dump-excluded output mapping |
| Persistence | Both disposable key files predate this update, with unchanged modification times of 2026-11-05; neither key was recreated |
| Main inventory | Metadata-only list loaded two logins and three passkeys; broker status and socket activation worked |
| Native messaging | Default Chromium manifest points to an executable host and allows only the expected extension |
| Software regression | Default-feature workspace/all-target checks and 11 browser tests passed; privileged/live tests were not implicitly counted as passing |
| Privileged fixtures | 21 broker/registry tests, one separate-UID worker test and one broker idle/disconnect test passed independently as root |
| Enforced memory budget | The synthetic selected-scalar creation/upload/signing fixture passed in a transient service with 1-MiB memlock, no capabilities, no hardware devices, hidden homes and AF_UNIX only |
| Apple read path | Dedicated-UID worker and authenticated root-side preflight fetched 18 Passwords records, authenticated one root and resolved the current class-A key; no Apple write |
| Escape during real signing | Agent recorded Escape, no signature delivered, but completion was uncertain with EIO and a sensor initialization timeout; clean cancellation is **unproven** |
| Browser after update | Actual passkey authentication and new native-choice registration remain unverified after the cancellation failure |
| Resume after update | No deliberate suspend/resume validation was performed by this work |

The cancellation timing and possible application/driver race are described in
[the investigation handoff](SEP-CANCELLATION-HANDOFF.md). Its cause remains
unresolved. GET_INFO success does not replace another authorized operational
check. No automatic retry, module reload or secure-state reset was performed.

The additional privileged tests use temporary synthetic registries and fake
authorization/network inputs. The systemd startup test starts only a disposable
sleep service. The memory-budget test exercises the production computation
wrappers with a synthetic selected scalar; it does not establish hardware
cancellation, real cloud upload or universal secret erasure.

Evidence is retained in `/tmp/keychain-os-update-tests.log`,
`/tmp/keychain-os-update-browser-tests.log`,
`/tmp/keychain-broker-fixtures-20261107.log`,
`/tmp/keychain-worker-uid-fixture-20261107.log`, and
`/tmp/keychain-broker-idle-fixture-20261107.log`. The constrained service result
and private read-only account report are under
`/var/lib/keychain-os-check-20261107/`. Temporary test executables were removed
after their processes terminated; existing disposable keys and diagnostic state
were retained.

## Gates still open

- Resolve cancellation timing, then verify clean cancellation and a fresh
  separately authorized operation without resets.
- Complete real native-choice browser registration/login, along with the
  migrated credential's post-boot browser persistence check.
- Verify a Linux-created iCloud passkey is fetched and used on another trusted
  Apple device. The earlier browser creation/login and cloud fetch proof do not
  establish this.
- Complete the plan's remaining live session-lock/expiry and resume checks with
  explicit user readiness. Do not interrupt the desktop to run these implicitly.

Production iCloud creation remains disabled. Root-key protection is still the
explicit follow-up described by the plan; this verification does not migrate it
or retire existing software recovery copies.
