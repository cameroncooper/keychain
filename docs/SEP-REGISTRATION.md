# Device-only passkey registration

The Chromium adapter now handles creation through the SEP broker. Software-only
profiles refuse creation. A broker profile sets `credential_broker` to its paired
socket in the existing private config; pairing and desktop-agent setup are
described in [service deployment](../contrib/SEP-SERVICES.md). Reload the unpacked
extension after updating its service worker.

The application window shows the validated RP/origin, account and storage choice.
Currently it offers **This device** only and explains that the credential is not
saved to iCloud or recoverable on another device. Choosing it closes this window
before the OS fingerprint prompt appears. Canceling/closing the application
window before choosing storage creates no key. The desktop prompt has guidance and Cancel/Escape, with
no additional approval button. Website cancellation disconnects the native host
and broker operation. A restored chooser still routes cancellation through
`completeCreateRequest` after an MV3 worker suspension.

Both the native host and broker validate creation details. Only supported ES256
platform requests are accepted; user handles, challenges, metadata, exclusions,
message sizes and extensions are bounded. `credProps` reports a discoverable
credential. HTTPS origin/RP and Chromium's injected same-origin override are
required. Unsupported PRF/large-blob and enterprise-attestation requests fail
explicitly. No arbitrary client origin, imported scalar or caller-supplied UV
boolean can authorize native creation.

The owner-checked root registry uses the browser's random transaction UUID as the
record ID and binds it to a SHA-256 digest of the exact frozen request. The normal
request replay ID is separate: explicit retry uses a new IPC request ID and the
same registration transaction and details.

1. An encrypted creation intent is saved and fsynced before SEP CREATE. If CREATE
   or persistence is interrupted without a readable saved key, this transaction
   refuses another CREATE. A new registration must be started explicitly; no
   credential response was delivered from the interrupted transaction.
2. The wrapped key, public point, random credential ID, RP/account metadata and
   request binding are durably saved as Prepared. Prepared entries are absent
   from browser and CLI inventory. Reopening this transaction reuses the exact
   saved identity. The encrypted creation intent remains after the key is saved
   and delivered. If that key file disappears, replay refuses another CREATE.
   Reopening an older saved record explicitly backfills a missing intent; it
   cannot reconstruct evidence already lost with both old files before upgrade.
   A changed request, owner, corrupt record or missing metadata root fails closed.
3. A fresh biometric native signature binds `authenticatorData || SHA256(clientDataJSON)`.
   The typed authorization result must match the key/message and require UV.
   Signature verification against the new public point must also pass. The
   response uses none attestation, zero AAGUID and BE/BS=0; it makes no Apple or
   hardware-attestation claim.
4. After the session, deadline, agent and cancellation checks, the encrypted
   record is committed as locally deliverable before returning a response.
   Repeating a committed transaction preserves its key and requires another
   fingerprint; no biometric grant or assertion is persisted.

Locally deliverable does **not** mean the relying party accepted registration.
The proxy observes response delivery, not the site's subsequent account update.
An uncertain delivery therefore retains the key and metadata. An excluded
credential produces distinguishable `InvalidStateError` only after a fresh
verified biometric operation authorizes that disclosure. That operation signs a
private domain-separated consent message, whose signature is never returned.
These behaviors follow the [WebAuthn creation procedure](https://www.w3.org/TR/webauthn-3/#sctn-op-make-cred).

General `list`, `show` and direct assertion lookup merge native broker metadata
with the user cache. Native records remain separate from Apple snapshots and
account logout. A configured unavailable broker causes an explicit inventory
error. This is never a reason to erase native credentials or replace their keys.
The broker's metadata root is software-protected by root permissions; native
private keys remain SEP-wrapped. Device-bound recovery requires the original SEP
state and registry; copying wrapped keys to another device is not recovery.

Offline checks cover encoding/signature/UV rejection, native-host routing,
storage selection, selection replay, abort, chooser closure after worker memory
loss and mixed CLI inventory. The root-only synthetic registry test covers
reopening Prepared/Deliverable records, uncertain CREATE, owner/context changes,
exclusions, tampering and survival of empty synced inventory. These are not proof
of live hardware registration or relying-party acceptance.

The installed broker and fresh release native host passed creation inspection
without capture on 2026-11-05, including a separate empty registry with no Apple
account/cache. The isolated development fixture uses
`.sep-check-native-registration-20261105` and the transient
`keychain-native-create-check.service`; its root state is separate at
`/var/lib/keychain-native-create-check` and its socket is private to UID 1001.
The normal installed broker also passed its no-fingerprint availability probe.

The diagnostic helper defaults to inspection only:

```sh
node contrib/check-native-registration.cjs .sep-check-native-registration-20261105
# Only while the user is ready for TWO separate fingerprint prompts:
node contrib/check-native-registration.cjs .sep-check-native-registration-20261105 --create-and-assert
# Reuse the saved public fixture in a fresh process (ONE fingerprint):
node contrib/check-native-registration.cjs .sep-check-native-registration-20261105 --assert
```

Biometric modes have not yet been run. The helper checks registration CBOR/COSE,
SPKI, RP/challenge, flags, CLI inventory, then verifies a fresh-process assertion
with Node/OpenSSL against the registered key. It saves the original transaction
and public metadata for explicit retry/reboot checks, never a private scalar or
wrapped key. Its synthetic RP is `diagnostic.invalid`; it sends no RP or Apple
network request. The transient broker exits after an hour of inactivity; check
that unit and socket before running it later rather than assuming it is alive.

Remaining acceptance: create and use a disposable credential in Chromium,
independently verify the registered key and flags, repeat in a fresh process and
after reboot, and validate cancellation on the real driver. iCloud creation,
CKKS upload/fetch reconciliation and successful use from another trusted device
remain part of the plan. No Apple writes are implemented or performed here.

Explicit local native-record removal is now implemented in the owner broker IPC;
see [durable removal and recovery limits](SEP-LOCAL-REMOVAL.md). No production
browser/CLI deletion action is exposed. Native creation retains its pre-CREATE
intent instead of deleting it after saving the wrapped key. The privileged
registration test now covers legacy intent backfill and a missing committed key:
neither case may execute a replacement CREATE. No real credentials were removed
or regenerated during these tests.


## Real Chromium registration and login — 2026-11-06

The user registered the disposable username `keychain-sep-20261106` at
webauthn.io through the project extension, chose **This device**, completed the
desktop biometric operation and then successfully authenticated with the same
username. The relying party accepted both registration and authentication.
This is actual browser/RP evidence, superseding the earlier inspection-only limit
for this device-only path.

A fresh CLI metadata check found exactly one corresponding native record,
`22fde9bf-71e2-4844-a4b6-da69b95a125f`, with device-bound storage and ES256.
Unified inventory contains five items. Both original passkey summaries still
match their pre-migration public baselines. The new public summary is privately
retained in ignored `.sep-check-main-webauthn-20261106/public-native-after.json`.
No private scalar/wrapped key was exported by these checks.

The browser is installed Chromium 156 on Asahi/M1, launched with the unpacked
extension in the isolated `.sep-check-browser-webauthn-20261106/chromium` profile.
The normal Chromium profile's existing singleton lock was not altered. The
native-host registration uses `cameroncooper.keychain` and the stable project
extension ID. Native registration/login makes no Apple item upload; the iCloud
creation flag remains disabled. This does not establish reboot/cold-boot,
session-lock/expiry behavior, other hardware or synced creation/other-device use.
The demo expires credentials after 24 hours, so persistence tests needing RP
acceptance must account for that external expiry without replacing the local key.
