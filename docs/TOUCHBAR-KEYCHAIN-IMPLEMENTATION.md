# Keychain Touch Bar implementation

Date: 2026-11-08

The authentication agent exports the presentation contract specified in
`TOUCHBAR-INTEGRATION-HANDOFF.md`. This is the keychain half of the integration;
the Touch Bar host/plugin is a separate implementation.

## Public contract

- Session bus name: `cameroncooper.keychain.AuthenticationAgent`
- Object: `/cameroncooper/keychain/AuthenticationAgent`
- Interface: `cameroncooper.keychain.AuthenticationAgent.TouchBar1`
- Read-only `Snapshot` string property, accessed with standard Properties.Get.
- Full-value standard PropertiesChanged notifications (`sa{sv}as`).
- `Cancel(s request_id)` returns an empty reply after UI dispatch completes.

Snapshot JSON version 1 starts at generation 0 with a null request. Generations
increase only for changed public snapshots, including retirement, and reset with
an agent/name-owner replacement. The object exists before acquiring the existing
activation name. Observation does not require a running Touch Bar consumer.

The typed projection contains the request UUID, operation, validated site target,
storage destination, typed phase, visibility, cancellation availability, optional
absolute monotonic deadline and bounded status text. It omits account names,
WebAuthn origins, credential IDs, secrets and cryptographic inputs/results. JSON
is limited to 8192 bytes; status text to 512 UTF-8 bytes with control/bidi checks.
Do not log snapshots. Session-bus routing does not provide isolation against
malicious code already running as the same desktop user.

## Lifecycle and cancellation

Private broker/agent protocol 4 requires explicit nullable deadlines and typed
status phases. Upgrade the broker, agent and direct diagnostics together; older
frames fail closed. Existing root-peer checks and desktop Visible requirements
remain the authorization boundary.

Creation starts in choosing-storage. Binding the selected destination resets
visibility and phase before the existing second Visible acknowledgement. Other
requests begin presenting, then preparing after Visible unless newer guidance
already arrived. Guidance maps directly to waiting-for-device, preparing and
place-finger. Saving/finishing maps to processing. Cancellation diagnostics keep
the diagnostic-cancel phase. Finished, EOF and malformed messages retire the
projection without asserting success.

Focus loss immediately withdraws the public request. The existing creation
chooser may remain open and restore its projection on focus return; an already
acknowledged authorization prompt uses its existing cancellation policy. Window
closure, Escape and Cancel retire the projection and invoke Channel::cancel.

Each private socket has an internal connection identity in addition to its root
request UUID. Every transition and queued cancellation checks both, preventing
stale connections or timed-out commands from affecting a replacement prompt.
D-Bus workers never hold GPUI entities: a bounded queue delivers cancellation to
the UI loop, which rechecks identity, retires, cancels and closes before replying.
Malformed/noncanonical/nil IDs return InvalidArgs; valid retired IDs are no-ops.
Queue failure/shutdown/timeout returns bounded Failed. No approval, visibility,
selection or authentication-result method is exported.

Publications use a single serial worker and a one-slot coalescing wakeup queue.
State commits before notification. A missing/slow/disconnected observer cannot
stall the UI or authorize an operation; clients reconcile complete snapshots by
generation within a unique name-owner epoch.

## Deadlines

The broker allocates its existing enforcing Instant deadline once per stage and
transports a checked conversion to Linux CLOCK_MONOTONIC microseconds. The clock
adapter samples CLOCK_MONOTONIC before Instant::now and rounds down, so the
published deadline cannot exceed that enforcing bound. No Instant representation
or wall-clock value crosses the protocol. Repeated guidance preserves the cached
deadline. A legitimate chooser-to-authorization transition can replace it;
unavailable timing is explicitly null, and zero means expired.

The consumer must enforce local expiry, owner-loss cleanup, stage freshness and
its own presentation lifetime. Expiry hides Touch Bar UI without automatically
calling Cancel. These consumer behaviors belong to the separate Touch Bar repo.

## Validation and deployment

Checks completed:

- `cargo fmt --all -- --check` and `git diff --check`.
- `cargo test --workspace --all-targets --features desktop-agent -j 1`: passed;
  main library 256 passed / 27 ignored, with binary and driver tests passing.
  Existing ignored checks require explicit external/live environments.
- `cargo test --lib --features desktop-agent prompt:: -j 1`: 25 passed.
- `cargo clippy --workspace --all-targets --features desktop-agent -j 1 -- -D warnings`:
  passed.

The private-bus test checks exact introspection, standard property reads and
signals, initial export before name acquisition, UI cancellation acknowledgement
and a new owner epoch. Other tests cover projection/privacy bounds, typed phases,
chooser rebinding, focus withdrawal/restoration, stale connection retirement,
canonical IDs, stale/full/disconnected/timed-out cancellation, deadline
rounding/overflow/stability and a slow or absent publication consumer. Routine
tests do not open the SEP device or reveal credentials.

Release build passed:

```sh
cargo build --release --features desktop-agent --bin keychain-broker --bin keychain-auth-agent --bin keychain-sep -j 1
```

Installed the matching broker and agent at `/usr/libexec/keychain/`, with both
services idle during replacement. Restored the broker activation socket; no
service policy or SEP driver changes were made. Previous binaries are retained
in `/var/lib/keychain-service-backups/touchbar-v4.t_qmna2m/`.

Installed SHA-256 values:

- Broker: `bb94af8fef3fb8a66d3319665e430eaaddc09e0169a339160a7bf80758bcd26a`
- Agent: `2c511f8309c21153c332674e703db4555e4417881039dc61cb66aed7c8fb62c9`

The installed agent started through its existing user service and returned initial
idle generation 0 through standard Properties.Get. A live `keychain-sep
prompt-check --desktop-owner 1001` then published a visible diagnostic-cancel
request, with a valid remaining monotonic deadline. Calling the public Cancel
method closed the desktop window, returned its empty acknowledgement, and retired
the snapshot (generation 10). The diagnostic reported “verified desktop
cancellation; no SEP operation was started.” No signing, decryption, enrollment,
credential reveal or cloud write was performed. The live observer harness used
`busctl --json=short` to preserve UTF-8 status text correctly.

## Remaining Touch Bar work

Implement the exact property subscription and read, scoped user-activated Cancel,
owner-appearance/replacement recovery, generation reconciliation and local
deadline expiry described in the handoff. The host also needs privileged
authentication presentation arbitration and restoration. Keep creation selection
on the desktop and require desktop_visible before showing an actionable Cancel.
Only place-finger permits a touch invitation. A later physical end-to-end test
must verify rendering and cancellation; this implementation alone does not prove
physical Touch Bar integration. fprintd integration is outside this change.
