# Explicit local native credential removal

The owner IPC operation `remove-local` accepts `selection.record` and the complete
`selection.signing_key` reference obtained from broker metadata. It currently
applies to native device-bound passkeys and diagnostic native records, including
prepared registrations. Synced passkeys/logins, recovery journals and account
state are outside this operation. There is no browser deletion action or general
Apple Passwords deletion command.

The broker requires its configured owner, root socket peer checks, an active
unlocked local session, the operation mutex, current cancellation checks and a
30-second monotonic deadline. It never accepts an owner or success flag in the
request. A fingerprint is not requested: this is an explicit local management
operation, not key use. As with other owner IPC, processes sharing that UID are
not isolated applications; a trusted frontend must obtain deliberate user intent
before sending a destructive request. The native browser host does not expose it.

Under the registry mutation lock, the service loads and validates the native
record and compares its entire signing reference. It publishes/fsyncs an encrypted
`removed-ID.enc` marker with a separate `RecordRemoval` encryption purpose,
containing owner, record ID and public key reference only. It then removes the
wrapped-key file and retained native creation intent, and fsyncs the directory.

Every record path checks for that marker before loading, importing or preparing
the same ID. Inventory omits a marked native record even if interruption left its
old wrapped-key file in place. Replaying registration cannot issue another CREATE.
A repeated removal must match the marker's owner/reference, re-establishes marker
file/directory durability, then finishes unlinking. Changed, corrupt or missing
metadata roots fail closed. A lone encrypted marker prevents root regeneration.
Markers remain durable and count toward the existing registry file budget; they
are not silently pruned or automatically garbage-collected.

Cancellation before publication leaves the record usable. Once publication
starts, an error can mean removal took effect. Late cancellation/expiry suppresses
the reply after cleanup but cannot restore the record. Explicit retry with the
same selection completes cleanup; no automatic retry or recreation occurs. A
partially written/corrupt marker refuses use and requires administrator diagnosis.

This removes the local wrapped representation. It does not erase SEP firmware
state, revoke a relying-party registration or prove physical erasure from SSDs,
old registry backups or snapshots. Restoring old registry data without the marker
can restore the old representation. Hardware/keybag reset is not part of removal.
Device-only credentials have no iCloud recovery copy; frontends must explain that
consequence before invoking the operation.

Two privileged synthetic tests cover exact owner/reference matching, cancellation
before and after publication, interrupted unlink/reopen, idempotent cleanup,
unchanged unrelated inventory, refusal to recreate/import the removed ID, corrupt
markers and missing-root refusal when only a removal marker remains. They use
temporary root-owned directories and synthetic key blobs, with no SEP, prompt,
Apple IO or deletion of real records. These checks do not establish live UI UX.

Validation on 2026-11-06: 227 workspace tests passed (25 intentionally ignored),
and 21 privileged broker/network-worker library tests passed separately. Formatting,
strict Clippy and the release build passed. Installed service backups are retained
at `/var/lib/keychain-service-backups/update.ncXQmDXP`. Installed native-host/broker
availability passed without a fingerprint prompt; the broker retains its 1-MiB
lock limit and decrypt-only flag. No real record removal, biometric capture,
account recovery or Apple write was performed.
