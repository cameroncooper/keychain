# Selected-passkey migration

`keychain protect ID [--socket /run/keychain/broker-UID.sock]` preserves an
existing synced passkey's identity while switching its local signing reference
to the biometric broker. The desktop requests a fingerprint. The account and
Octagon encryption root remain separate. No Apple writes or replacement keys are
created. Installed services and the compatible driver must already be available.

## Durable transaction

The CLI holds StateLock. Before any broker mutation it atomically writes an
authenticated encrypted journal under `state/protection/ID.enc`, using the
ProtectionMigration purpose. It contains source/public identity, owner, socket,
phase and destination revision/reference, never a scalar. A missing root with
migration journals present refuses regeneration.

1. Prepared: query authenticated broker state. Resume matching staging, or ask
   the source backend for a recipient-encrypted import. The backend returns no
   raw scalar. The source remains the active vault reference.
2. Broker verified: biometric decrypt/sign verifies the credential. Query committed
   state again and compare identity, point, revision and reference. Journal that
   verified destination before changing the local vault.
3. Local commit: atomically save the broker reference in the vault, configure
   broker-only browser mode, then mark the journal committed. If config fails,
   the software signer refuses the protected reference. Repeating the command
   resumes the remaining transitions.

Ambiguous results return errors without automatic retry. A later explicit call
queries durable broker state rather than reimporting. A previously verified
journal with a missing destination refuses replacement. Changed identities,
hardware refusal and unsupported interfaces never cause software fallback,
root replacement, escrow recovery or an Apple rejoin.

Tests inject ambiguous replies after staging and server commit, and an actual
configuration rename failure after the local reference update. They verify
resumption, identity/source retention and software-signing refusal. These do not
establish reboot/power-loss behavior or real browser interoperability.

## Sync and logout

Sync checks recovered public identity against broker metadata, refreshes only
matching labels/timestamps and retains protected references. It does not reimport
those scalars into software storage. Local device-bound records survive a synced
snapshot. Changed keys, missing protected records and pending staging fail closed.

An authenticated atomic synced-inventory manifest excludes deleted/account-signed-
out synced records from assertions without deleting their encrypted recovery
representation or native local keys. Explicit verified migration includes its
credential again. Logout must disable synced broker use before removing account
state. Full `--forget-device` reset also removes local migration journals.

Broker browser mode lists verified broker credentials. Unmigrated software
passkeys remain in the local vault but need migration before appearing there.

## Recovery copies and remaining gates

The source scalar intentionally remains in the software keystore. Anyone able to
read that copy and its software encryption root can recover it without a
fingerprint. Old backups retain the same exposure. Normal CLI/browser operations
use the protected reference after commit; they cannot fall back to this copy.

Source retirement is not automatic and is not implemented yet. Verify the
committed representation from a fresh process and after warm reboot before
retiring old copies, with a tested unavailable/erased-SEP recovery choice. Cold
boot, suspend/resume and enrollment invalidation remain separate gates. Root
protection is a follow-up.

Real-profile migration and browser validation remain pending. Synthetic profiles
are private, ignored and separate from the user's vault; temporary-profile and
module losses across reboot are not treated as successful migration evidence.
The persistent `.sep-check-migration-20261105` profile completed migration and a
fresh-process native-host assertion with independent signature/identity/flags
verification. See the [hardware evidence](SEP-APPLICATION-VALIDATION.md) for exact
record IDs and remaining reboot/retirement gates.

The installed hardened services also completed migration for disposable profile
`.sep-check-installed-20261105`, record `da294ad0-4110-4487-a95c-52a0236e0f85`.
A fresh release native host independently verified the assertion through that
deployment. The real-profile WebAuthn migration was initially held by lost Passwords-key
access and the earlier empty-cache overwrite. The [explicit trust repair](SYNC-RECOVERY.md)
subsequently committed and restored the original inventory; the selected real
migration below then completed. That earlier incident did not justify removing
source keys or treating the SEP integration as its cause.


## Main-profile WebAuthn migration — 2026-11-06

With the user's prior WebAuthn-only scope and renewed fingerprint readiness,
`keychain protect 89B32928-CAAE-44A0-8255-AFDBD822C7EE` completed against the
installed `/run/keychain/broker-1001.sock` at revision 1. It used the existing
webauthn.io credential and retained the software recovery copy. No Apple records
were changed and no new passkey identity was generated.

Before capture, public metadata for the WebAuthn and Apple.com passkeys was saved
privately in ignored `.sep-check-main-webauthn-20261106/public-before.json`.
After commit, fresh `show --json` metadata matched both baselines exactly,
including their existing credential fingerprints. The unified inventory still
contains all four restored items. The main config now selects the installed
broker; the Apple.com passkey itself remains unchanged and unmigrated. It is
excluded from broker-mode browser use until separately migrated, as agreed.

A fresh main-profile native host then reported biometric availability and exactly
the expected WebAuthn candidate for a required-UV request at
`https://webauthn.io`. This inspection requested no signature or biometric capture.
The Chromium native-host manifest points at the current release executable under
this repository. Actual browser/RP authentication and post-reboot verification
remain separate acceptance gates; no source retirement is justified yet.
