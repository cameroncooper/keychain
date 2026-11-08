# SEP integration: design and completion plan

Status: implementation and acceptance in progress, updated 2026-11-08.


Transport update: application keys now use the blocking `/dev/sep-keys` version 1
API. See [the migration handoff](docs/SEP-BLOCKING-MIGRATION.md) and
[application migration evidence](docs/SEP-BLOCKING-VALIDATION.md). Historical
START/POLL observations below do not describe the current transport. Existing
wrapped keys, item envelopes and record identities remain unchanged.

The native signing/decryption provider, protected software signing, migration,
selected login/TOTP reveal, native credential creation and iCloud upload path are
implemented. Isolated testing has established native and migrated-synced Chromium
login, a scoped atomic-precondition rejection, and Linux-created iCloud passkey
registration/login with independent cloud fetch/decrypt verification. Those
successes do not establish other-device use or every hardware cancellation path.

Storage selection now lives in the native GPUI window, following the user's later
UI decision: iCloud is the default when the broker offers it, Other Options
exposes device-only storage, and Continue binds the destination before the same
window presents biometric guidance. The extension cannot submit storage. Selection
tolerates focus changes; the bound authorization state cancels on focus loss.
The user confirmed the native preview/transition; the new native-choice browser
registration/login gate remains open. See [native prompt design](docs/NATIVE-CREATION-PROMPT.md).

The version-1 key-node migration has passed existing-key synthetic decryption,
trusted-context validation, a clean Escape -> concurrent CANCEL -> ECANCELED check
and a separately authorized same-key signing check afterward, without a reset.
The migrated broker and key-node-only service allowlist are installed. See
[the migration acceptance record](docs/SEP-BLOCKING-VALIDATION.md). Earlier EIO
attribution remains unresolved historical evidence in
[the investigation handoff](docs/SEP-CANCELLATION-HANDOFF.md) and
[the prior OS acceptance record](docs/OS-UPDATE-VALIDATION-20261107.md).

The protected computation source review and constrained 1-MiB/no-capabilities
synthetic service check passed; broader memory-erasure claims remain excluded.
The complete objective is not achieved. Prompt-disconnect validation,
remaining live lock/expiry/resume and migrated persistence checks, native-choice
browser acceptance and use of a Linux-created credential on another Apple device
still need evidence. Production creation stays disabled, and all existing
credentials, prior uncertain attempts and recovery copies are retained. Root
wrapping remains the separately requested follow-up, not a signing prerequisite.

Earlier transaction history and exact live evidence remain in
[the disposable iCloud test record](docs/LIVE-ICLOUD-TEST.md).

This is the application design and implementation order. The current
[SEP handoff](SEP-INTEGRATION.md), [driver API](docs/sep-driver/README.md),
[decryption contract](docs/sep-driver/DECRYPTION.md) and
[secret-handling guidance](docs/sep-driver/SECRET-HANDLING.md) supply the hardware
and memory requirements. Earlier missing-provider and unproven-decryption
blockers are superseded. No additional research snapshot is required.

## Credential storage and protection

At creation, offer **Save to iCloud** and **Save on this device**. Choose storage
before biometric authentication; do not ask again when using the credential.

| Choice | Key material | Authorized use |
| --- | --- | --- |
| iCloud | Syncable scalar, locally protected in an item envelope | SEP biometric item decryption, then software signing inside the helper |
| This device | SEP-generated private key, locally stored wrapped blob and public point | SEP biometric native signing; only the signature returns |

Model sync disposition, provenance, local protection and permitted operations
separately. Existing iCloud passkeys retain their public key, credential ID,
user handle and backup provenance when their local protection changes. A
non-exportable SEP key cannot be uploaded using this API. Changing device-only
to synced needs a supported replacement/registration flow, not a metadata toggle.

Both creation options are implemented. Device-only and isolated iCloud WebAuthn
registration have passed; other-device acceptance and remaining live gates are
still incomplete. Uploads require
explicit account-write authorization before live tests. Diagnostic native key
creation is not completed passkey registration.

## Desktop interaction

Use the Apple-style interaction: **act in the application, authenticate in a
desktop-owned prompt, continue automatically**. Keep credential selection and
storage choices before authentication. There is no Continue, Approve or Done
button on the successful biometric path.

1. A deliberate application/browser action initiates use of a credential.
2. Resolve the eligible credential. Show a picker only when selection is needed;
   an unambiguous selected credential proceeds directly to authentication.
3. The broker validates and freezes the operation. The session agent displays
   service identity, action, RP and selected account. The immediate process is not
   proof of an ultimate browser identity; origin remains browser-bridge evidence.
4. Once the prompt is visible, start the operation. Show preparation first and
   finger-placement guidance from actual driver status. A visible window or an
   opened descriptor alone does not mean the reader is ready.
5. Successful authorized operation and cleanup dismiss the prompt automatically
   and return the result to the application.

Example:

```text
Use your passkey for webauthn.io
testuser12345

Touch the fingerprint reader

Cancel
```

The session agent owns authentication UI and the pre-authentication storage
choice. The browser/application still owns multi-account credential selection. Cancel/Escape dismisses and cancels. Display progress, mismatch and
terminal errors. Offer password fallback only when policy and implementation
actually support it. A new request after terminal failure needs an explicit
retry; capture guidance within the existing request is not a hidden retry.

Use the same agent for CLI and browser operations. Headless use needs an explicit
non-GUI mode or an unavailable-UI error, never invisible capture. Do not cancel
merely because the requesting app loses focus: the prompt itself may move focus.
The GPUI prompt cancels when its own active window loses focus. Cancel on
caller cancellation/disconnect, session lock/logout, agent disappearance or
expiry. Suppress result delivery after cancellation even if hardware already
executed; wait for cleanup before making the device available again.

Apple references: [Mac passkey flow](https://support.apple.com/en-au/guide/passwords/mchl4af65d1a/2.0/mac/26),
[LocalAuthentication](https://developer.apple.com/documentation/localauthentication/lacontext),
and [protected-key access controls](https://developer.apple.com/documentation/security/secaccesscontrolcreatewithflags(_:_:_:_:)?language=objc).
These inform the interaction; not all macOS credential flows have identical UI
or fallback policies.

## Process and authorization boundaries

```text
CLI / browser extension and native host
        | bounded local operation request
        v
privileged broker <----> user-session prompt agent
        |               storage choice / display / guidance / cancel
        v
safe Rust driver client -> isolated ioctl bindings -> /dev/sep-keys -> SEP
```

Use a small dedicated bindings crate for blocking ioctls and memory-protection unsafe
code; retain `unsafe_code = "deny"` in the main package. Use the supplied header,
not raw firmware packets or Python subprocesses. Check structure sizes/alignment,
pointer offsets, reserved fields and ioctl numbers against the header.

Keep Apple networking, browser plugins and general CLI logic outside the broker.
Keep the one-shot native host. Target systemd socket activation for the broker
and D-Bus activation for the session agent, with idle exit and no persistent
unlocked vault. Device coordination may justify a maintained service later.

Authenticate local IPC with kernel peer credentials on a root-owned Unix socket;
derive owner UID and active local session from that identity. Bind the session
agent to its actual session. Enforce key ownership, algorithm and purpose in the
broker. Claimed UID, app name, origin, owner or biometric-success booleans are
not authorization. SO_PEERCRED cannot distinguish trustworthy applications
sharing a UID; stronger app isolation requires a portal/sandbox identity boundary.

The current driver uses one configured SEP identity/credential set. Explicitly
bind it to the intended local Linux user; reject unsupported users/sessions.
Do not route all Linux users through that shared identity. Serialize sensor use
and implement/test a handoff with fprintd; repeated service stop/start is not the
normal application protocol. Report busy honestly and retain device ownership
until canceled/failed work has cleaned up.

The agent can acknowledge presentation and request cancellation, never declare
authentication success. Freeze key selection and operation contents before
capture. Deliver session-scoped status only for the bound request ID. A normal
standalone window supplies initial modal-style UX, not a protected desktop
surface. Keep presentation replaceable for later shell/compositor integration.
Follow the [polkit service/agent separation](https://www.freedesktop.org/software/polkit/docs/latest/polkit-agents.html)
without treating polkit/PAM success as a SEP authentication context.

Use versioned, length-delimited IPC with strict bounds, unique IDs and monotonic
deadlines. The operation set is capabilities/status, allowed application-key
creation, authorized synced-item import/update, selected-credential use, cancel
and explicit local record removal. The broker resolves persisted key references.
Do not expose arbitrary-blob decrypt or arbitrary-digest sign through browser IPC.
Diagnostic tools are separate from this production interface.

For WebAuthn, revalidate complete request context, RP/origin, allow-list, selected
credential and UV requirement inside the trusted operation path. Browser-origin
evidence still depends on the trusted extension/native-host integration; accepting
arbitrary JSON is not independent proof of an origin. SEP does not validate sites.

```text
validated -> presenting -> preparing -> awaiting finger -> executing -> complete
                  \________ cancel / expire / disconnect _________/
                                      -> cleanup -> canceled / failed
```

Ambiguous completion is terminal; never automatically retry. Broker restart
invalidates pending requests. Persist no SCRD contexts or reusable grants.

## Persistence and secret lifetime

Persist owner, opaque ID, public point, wrapped blob, algorithm, policy, allowed
operations and provenance durably. Use private bounded files, symlink resistance,
atomic replacement and strict input validation. Keep policy/selection metadata
in a root-controlled registry partitioned by owner; retain authenticated encryption
and metadata confidentiality where required. Unprivileged clients must not be able
to rewrite the registry or substitute key/policy/record fields.

For each synced secret, use the documented envelope with canonical context for
application, owner, record ID, RP where relevant, purpose, algorithm and version.
Compare decrypted binding against trusted selected-record state. Public-key
encryption does not authenticate the author or prevent rollback; preserve
authenticated storage, authorized updates and defined version/replay semantics.

Use the exact P-256 ECIES profile: X9.63 SHA-256 material, AES-256, derived 16-byte
IV, empty AAD. Maximum ciphertext is 4096 bytes; the 81-byte overhead leaves
4015 bytes including plaintext context. Refuse oversized records initially.
Larger records need a separately specified envelope-encryption design.

Decrypt only the selected secret for one operation. Keep a synced scalar and its
software key/scratch state inside the hardened helper, wipe after use and return
only the signature to the browser. Intentional password/TOTP reveal operations
return only the explicitly requested output. Never export a passkey scalar or
vault root through production IPC. Secret import during sync is a separate
authorized operation, not a side effect of signing.

Candidate inspection must use protected broker metadata without unlocking the
whole vault for a biometric request. Replace the current whole-vault inspect
dependency; do not add a hidden cross-process unlocked-root cache.

Apply final-size zeroizing allocations, checked mlock and MADV_DONTDUMP before
plaintext arrives, a nondumpable helper, bounded resource limits and no fork/exec
with live secrets. Audit imported key objects and crypto scratch cleanup. Wiping
one buffer does not prove erasure of every compiler/library copy. Validate memory
protections with synthetic data, never production secrets in diagnostic dumps.

## Capabilities and assertion semantics

Keep native P-256 signing, biometric item decrypt, native key import, P-384,
verification policy and freshness separate. Signing bit 2 does not advertise the
local decrypt extension. Require a compatible deployment and handle unsupported
ioctls explicitly. Recheck after reboot because the module is temporary.

For native signing, hash authenticatorData || clientDataHash once, pass the
32-byte digest unchanged and verify DER output against the expected public key.
For synced credentials, validate item binding and scalar/public consistency,
then software-sign the same message. UV comes from the complete authorized
transaction for that credential; neither incoming JSON nor a UI click supplies it.
Retain required-UV refusal until the path is validated end to end. Synced
credentials retain BE/BS provenance; device-only credentials use BE/BS zero.

## Implementation sequence and acceptance gates

### 1. Real native biometric signing

Implement GET_INFO, CREATE, SIGN_START/POLL and CANCEL in the bindings crate;
typed busy/unsupported/refusal/cancel/expiry/ambiguous errors; descriptor ownership
and cleanup. Map stored references to wrapped keys and expected public points.
Connect SepProvider without double hashing. Start with a privileged diagnostic
binary using fresh disposable application keys, never a root browser host.

Acceptance: independently verify two distinct messages; fresh finger-off request
returns no signature; exercise cancellation and cleanup; use the same saved key
from a fresh process and after warm reboot. Fake-provider tests do not establish
hardware behavior.

### 2. Broker and desktop authentication agent

Implement restricted IPC, owner/session mapping, policy checks, device handoff,
activation packaging and request state machine. Add the session UI with automatic
capture/dismissal, actual guidance, Cancel/Escape and accessible statuses. Route
unprivileged CLI diagnostics through it. Native storage selection precedes the
authorization phase; multi-account credential selection remains in the application.

Acceptance: initiate in an app, touch once, complete with no confirmation click.
Wrong owner/session, spoofed UI success, modified requests, disconnect, agent exit,
session lock and expiry cannot deliver results. Verify busy handling, fprintd
coordination, service activation and idle exit.

### 3. Item envelopes and protected software signing

Port seal_item/item_view and DECRYPT_START/POLL. Reset output capacity for every
poll; honor consumed delivery/deadlines and wipe all error/success buffers. Add
canonical binding, broker-owned metadata, encrypted persistence and checked
memory protection. Begin with synthetic items and passkey scalars.

Acceptance: Rust context envelope and real driver round-trip together. Reject
wrong context/key/tag; fresh finger-off request returns no plaintext. A synthetic
imported credential signs correctly with only its signature crossing browser IPC.
Test cleanup on signing failure/disconnect and protection-setup failure. Test an
unsupported decrypt API despite positive signing capability.

### 4. Existing synced credentials and browser UX

Route candidate lookup through broker metadata and complete requests through
native signing or decrypt-and-software-sign. Replace the extension's additional
Approve/Continue step with the desktop prompt after selection; show a picker only
when needed. Add selected password/TOTP access with explicit reveal policy.
Reconcile sync updates without deleting local-only records from mixed inventory.

Acceptance: real browser sign-in using the existing synced credential succeeds
with unchanged identity and correct flags, including required UV on a validated
path. Reject wrong origin/RP/allow-list/context. Test single/multiple accounts,
abort, expiry and unavailable UI/hardware. Native credential browser testing
requires registration in milestone 6; diagnostics alone are insufficient.

### 5. Explicit migration and recovery

Separate selected-item migration from optional protection of the root used for
account/Octagon/other state. Root wrapping is a follow-up, not a native-signing
prerequisite. Specify durable staging, verification, atomic commit and interrupted
operation recovery before migrating real data. Preserve keys and identities.

Acceptance: inject interruption at each durable transition without losing both
the old representation and a verified committed replacement. Verify reopening
from a fresh process and after reboot before retiring old root/scalar copies.
After commit, normal operations cannot fall back to old software copies. Missing
hardware/erased secure state/refused authorization never regenerate a root or
trigger Apple escrow recovery/rejoin. Document old-backup exposure and recovery
alternatives for device-bound data before use.

### 6. Passkey creation with both storage choices

Add provenance, registration lifecycle, native P-256 generation, resident metadata
and BE/BS handling. Implement device-only registration and iCloud-syncable
creation/CKKS upload as distinct features. Show storage choice before biometrics;
offer only options compatible with the relying party's requirements. Persist
registration and sync completion state; do not claim iCloud save before Apple
acceptance and subsequent fetch verification.

Acceptance: register/use a device-only credential without uploading it; create an
iCloud credential that another trusted device fetches and uses successfully.
Verify sync preserves both kinds and interrupted registration/upload reconciles
without silently changing key identity. Live Apple writes need explicit scope.

## Historical implementation and acceptance notes

These notes retain earlier milestones and limitations. The dated status above
and linked acceptance records are authoritative for current completion.

Implemented in this worktree: shared backend factory, RootKeySource seam, typed
authorization/protection capabilities, removal of caller-supplied UV boolean,
concrete NativeSepProvider and isolated Rust ioctl driver crate, privileged
disposable-key diagnostic, Rust item envelopes and dedicated locked/dump-excluded
plaintext memory. The broker core now adds peer-UID and active/unlocked local
session checks, encrypted root-controlled records, request replay bounds and
disconnect/cancel monitoring. The optional GTK session agent implements
presentation, guidance and Cancel/Escape, with no approval button or biometric
success message from UI to broker. Systemd templates and deployment notes are in
[contrib/SEP-SERVICES.md](contrib/SEP-SERVICES.md).

Workspace checks: 232 passing tests, twenty-six ignored (four Apple network and twenty-two privileged
integration tests). Thirteen registry, five coordination and one account-bootstrap test passed separately as root, including
wrong-owner, ciphertext-tamper, missing-root refusal and staged replacement recovery.
The separate-UID worker and systemd startup tests also pass (twenty-one privileged
library tests total).
Eleven browser service-worker flow tests also pass. Strict Clippy is clean.
The broker now exits after an idle interval without interrupting queued/active
work. Its temporary-root listener/disconnect lifecycle test passed separately;
installed socket activation, clean idle exit and new-process reactivation have also passed.
C-header ABI and actual mapping protections are tested.

The [driver validation record](docs/sep-driver/VALIDATION.md) reports J293/M1 native
signing and raw item-decryption warm-reboot evidence. The reusable context
envelope now also has a positive application-side Rust hardware run. Native
signatures on two distinct messages, a fresh finger-off timeout, explicit
cancellation and subsequent device availability passed through the Rust provider.
See [application evidence](docs/SEP-APPLICATION-VALIDATION.md) for exact limits
and remaining negative tests. A normal-user CLI request
through the temporary broker and desktop agent produced a verified native
signature. The explicitly labeled real-operation cancellation test returned
cancellation and no signature. Synthetic synced-item import and biometric
decrypt/software-signing also passed on hardware. Broker metadata lookup,
browser routing/cancellation and staged registry commits are implemented; see
[protected items](docs/SEP-PROTECTED-ITEMS.md). Real browser sign-in through this
path, real-profile migration verification and passkey creation/upload remain pending.
Installed hardened services have completed a synthetic migration and a fresh release
native-host assertion with independent signature, identity and flag checks. Real
fprintd Claim/Release coexistence passed without restarting fprintd or releasing
another client's claim. The goal is incomplete; native signing does not
depend on root migration.

Selected migration now has an encrypted local journal and an explicit
`keychain protect` command. Interrupted staging, server commit and local
configuration updates resume without software fallback or source deletion.
Sync preserves migrated references/native local records, checks recovered public
identity, refreshes metadata and atomically updates a synced-eligibility inventory.
See [migration and recovery-copy limits](docs/SEP-MIGRATION.md). Synthetic
migration completed through the desktop prompt; a fresh native-host process then
produced an independently verified assertion with unchanged identity and synced
flags. Preserved native signing/decrypt key files predating the current boot both
worked again through the Rust path. Source retirement and a reboot check of the
newly migrated record's complete persistence chain remain pending.

Browser authenticator availability now queries the configured backend. Software
mode reports no UV; broker mode checks eligible metadata, agent liveness and
current signing hardware without opening the user vault or prompting. This is
an availability hint, never authorization or a substitute for decrypt validation.

The service template now uses a hidden home hierarchy with a read-only bind of
the paired UID's runtime directory. A temporary systemd sandbox check confirmed
the live desktop socket was visible and the home directory hidden. The installed
root-owned binaries/units, paired socket and active session agent have also been
checked; current native-host availability succeeds without a fingerprint prompt.

Real-profile migration paused when a user sync exposed missing Passwords key
access and an empty-cache overwrite bug. Sync now refuses incomplete decryption,
validates complete zone/protocol responses and keeps an encrypted prior nonempty
snapshot. `keychain join --repair` implements explicit journaled replacement-peer
recovery with old-key retention and independent full-snapshot verification before
promotion. Interruption tests pass; live repair still requires user-entered escrow
credentials. See [sync and trust recovery](docs/SYNC-RECOVERY.md). Do not infer that
Apple authentication failure, SEP service failure or local key loss caused this
incident: authentication succeeded and signed peer metadata included an exclusion.

Fresh GSA authentication then exposed the old Android anisette provider's rejection.
A separate Rust Mac-CoreADI emulator helper now runs locally on Asahi; it provisioned
one isolated identity and passed real-account SRP init through the application before
and after being installed/selected. Password proof, 2FA/PET and real repair remain
pending user input. The prior ADI profile and Prepared journal are retained. See
[authentication compatibility](docs/APPLE-AUTH-COMPATIBILITY.md).

Passkey creation now has a validated creation-request context and a device-bound
registration encoder in `src/passkey/registration.rs`. It validates Chromium's
injected caller origin, RP, challenge, user handle, supported ES256/platform
requirements and exclusions. It emits discoverable credential metadata, COSE
P-256 public key and none-attestation JSON only after consuming an operation-bound
native SEP result with UV and independently verifying the signature against the
new public key. Device-bound BE/BS stay zero. Four offline tests cover encoded
fields and refusal of wrong origin, identity, signature, protection, absent UV,
unsupported requirements and excluded credentials. These tests use synthetic
signing outcomes, not hardware authorization. Durable broker creation, explicit
browser storage selection and registration delivery are connected. An encrypted
intent precedes CREATE, a saved key precedes authorization, and local eligibility
precedes response delivery. Restart/ambiguous-delivery tests retain the same key;
an interrupted CREATE without a saved key refuses reuse of the transaction.
One shared desktop authorization lifetime handles native/protected use and creation.
Exclusion disclosure requires fresh verified presence before InvalidStateError.
General list/show merge native broker metadata without hiding unmigrated synced
items. Real registration/login in Chromium and complete-chain reboot evidence are
still pending; no hardware creation pass is claimed from these tests. iCloud
creation, upload/fetch reconciliation and other-device verification remain required.
See [registration details](docs/SEP-REGISTRATION.md).

The iCloud path now has offline passkey plist encoding and new-item CKKS
encryption. Write-key selection requires an explicit current class pointer,
correct key class and zone-bound authenticated TLK ancestry; it refuses stale
fallback, record collisions and device-bound export. A synthetic newly encrypted
passkey reenters the existing sync pipeline with the same credential ID, user
metadata and P-256 public key. This is local interoperability evidence, not Apple
acceptance. The decoder now retains zone/owner, change tags and opaque server
record bytes. A paginated read adapter and encrypted upload coordinator persist
prepared ciphertext/identity and attempts, reconcile uncertain outcomes through
fetch/decrypt verification and require explicit retries after confirmed absence.
Seventeen coordinator tests pass, including persistence faults and key-pointer changes.
After a definite rejection, explicit re-encryption fetches complete absence and
prepares the same credential against the authenticated current key. Superseded
ciphertexts remain journaled and recognizable, including a late commit from an
older uncertain request. Unknown ciphertext, altered identity and uncertain or
accepted re-encryption are refused. History/send limits retain reconciliation
without permitting unlimited retries or unbounded storage. This is offline
coordinator evidence; no production write transport is enabled.
The broker can now generate and durably seal a syncable key into an isolated
account/request-bound draft, refusing interrupted-key regeneration and storage
path collisions. Drafts remain outside eligible inventory and generic import
verification. Sync consults broker state even without a prior user-cache entry,
so first sync cannot downgrade a protected key into software storage. A typed
FetchVerified receipt now gates synced registration backup flags; fresh protected
UV signing is still independently required. Synthetic persistence, receipt,
registration and first-sync tests cover these paths. Receipt-checked registry
promotion now commits through an Activating checkpoint, protected-record write,
inventory inclusion and final Committed marker. Partial promotions cannot be
used or activated via generic verification. Tests cover interruption at each
transition, changed drafts during signing and response suppression after late
cancellation; retries retain the key and require new authorization. Normal
post-creation metadata refresh/rewraps remain supported, while loss of a committed
record refuses replacement. A broker coordinator now connects upload preparation,
reconciliation, verified backup, signing and promotion within one selected-scalar
lifetime. It does not persist a grant or require a second decrypt for signing;
normal protected signing shares the same selected-secret implementation. Resume
precedes ciphertext preparation and explicit policies govern uncertain/rejected
recovery. Five synthetic complete-operation tests cover cancellation/lost replies,
identity checks, restart and recovery. The authenticated cancellable socket
transport now keeps raw networking outside the broker, validates independent
service UIDs and exact scope/sequence, and closes rather than replaying after
failure. Its disposable different-UID test passes. Current NativeAuthorization
checks now travel through every upload/journal IO call and into partial socket
reads/writes; a constructor-time guard cannot substitute for them. Session checks
use an uncached login1 snapshot with a 250-ms timeout and fail closed. The separate
worker executable/service and minimal encrypted credential export
now exist; a synthetic systemd startup check verifies delivered credentials,
separate UID, scope rejection and idle exit without Apple/SEP IO. Explicit root
account enrollment now imports only the existing Octagon agreement identity,
verifies its signed permanent info and persists an immutable enrollment intent.
The broker authenticates recoverable/live self-shares and constructs its own
complete preflight snapshot; a root integration test exercises raw share/page
framing through that path. See [account bootstrap](docs/BROKER-ACCOUNT-BOOTSTRAP.md).
Worker-start/coordinator/browser wiring is now connected behind the default-off
`--allow-synced-creation` flag. A disposable systemd test verifies guarded startup
and no restart of an active worker. The browser requires an explicit storage
choice and never falls back after an iCloud failure. Real account bootstrap,
remaining library/scratch memory review and live validation remain required
before enabling that flag; see
[coordination limits](docs/ICLOUD-BROKER-COORDINATION.md).
Atomic save framing is implemented from pinned extracted-schema/client references:
create-only item, unchanged-pointer tag check, zone-isolated stream and strict
two-operation reply matching. The HTTP write client disables redirect and replay;
six wire-policy and two loopback tests pass. Live atomic rejection/acceptance is
still unproven; see [wire evidence and gates](docs/CLOUDKIT-WRITE-PROTOCOL.md).
Broker creation/authorization coordination, live fetched/other-device
verification and the remaining reveal/migration gates are still required. A
read-only live metadata check received HTTP 401 with the cached CloudKit token;
it did not validate live metadata or save any snapshot. Fresh local authentication
is still required. See [iCloud creation progress](docs/ICLOUD-CREATION.md).

Cold power-cycle, suspend/resume, other hardware, enrollment-set invalidation,
native private-key import, P-384 and multi-user SEP identity isolation remain
unestablished. Never infer them from warm-reboot success. Never change system
keybags, fingerprints or xART lineage to repair application failures, and never
reuse the maintainer's test keys.

The [selected-secret memory review](docs/SEP-MEMORY-REVIEW.md) records concrete
application/primitive lifetimes, the opt-in ARM POLYVAL backend's cleanup limit,
and the protected worker used for RFC6979/HMAC and selected crypto scratch. AES-GCM/GHASH/POLYVAL cleanup features
are now enabled for the normal Asahi build. TOTP parsing/generation wipes its
owned seed/MAC/code buffers on success and error, rejects ambiguous/invalid
configuration and checks expiry arithmetic. All eighteen RFC 6238 vectors pass.
The service-side [selected login envelope/reveal path](docs/SEP-LOGIN-REVEAL.md)
is now implemented: encrypted staging, biometric verification, owner/revision/
metadata binding, selected password/notes or generated TOTP output, protected
reply serialization and wiping typed client results. Login/passkey namespaces
refuse collisions. TOTP query and seed decoding now use checked locked buffers;
a zero-memlock child proves no unprotected fallback. Synthetic tests cover
context/field substitution, partial reply cancellation, commit/reopen/interruption
and missing-root/revision refusal. CLI login migration/show/list/TOTP routing is
now connected through a metadata-only authenticated cache index. Frozen keyed
content tags prove exact source contents; recovery journals retain the encrypted
source. Config publication precedes primary-cache redaction, and cache/index
markers prevent lost-routing fallback. Unchanged/deleted logins share the managed
sync inventory with passkeys. Changed logins now freeze encrypted successors and
publish pending routes without capture. The next explicit reveal checks and
commits that exact successor through one biometric-decrypt lifetime, then displays
only requested fields. Root staging replacement pins the old pending tag; recovery
retains superseded ciphertexts and refuses known loss/rollback. Tests cover repeated
changes, lost replies, publication faults, concurrent pending commit, bounded history
and cancellation before/after commit. The later live synthetic run below now
establishes selected hardware reveal/update and user-confirmed one-operation UX;
real migration, session-lock/expiry and reboot acceptance still need completion.
Reviewed pure crypto/parser/serializer operations now run on a temporary locked,
dump-excluded, non-inherited stack with guard pages. The caller joins and wipes
its full usable mapping on success or Rust unwind; setup failure never runs the
callback on an ordinary stack. This does not establish erasure of register copies,
unreviewed heap storage or account root/class keys. Hardware and live account
acceptance gates remain open.


Explicit native-record removal is now implemented in authenticated owner IPC,
with exact key-reference selection, a durable purpose-separated removal marker,
interrupted-unlink recovery and refusal to recreate the registration ID. It does
not remove synced recovery copies or perform SEP erasure; see
[local removal](docs/SEP-LOCAL-REMOVAL.md). Browser/general CLI deletion UX is not
exposed. Native registration now retains its pre-CREATE intent after key storage
and delivery, so a missing committed key cannot trigger silent replacement.
Existing saved records backfill that guard when explicitly reopened. These are
synthetic-tested persistence changes; live biometric/account gates remain open.


The session agent now supports user-side D-Bus activation with a Type=dbus user
unit, a fixed activation name and bounded/cancellable readiness checks. It claims
the name after GTK/listener setup and exits after two minutes without an active
prompt. The privileged broker keeps kernel-peer and visible-window checks; bus
activation cannot grant UV or start capture. Direct root diagnostics still need
an already running agent. Metadata-only list/status operations do not activate
it. Availability queries may start the agent process without a window. See
[activation deployment](contrib/SEP-SERVICES.md) for current installation evidence.


Live login progress (2026-11-06): the isolated synthetic record now passes initial
biometric verification, all-fields reveal, and revision 2 verification/commit/reveal
in one decrypt lifetime. The user confirmed the desktop UX and single-operation
update. A fresh client process then revealed the same saved revision; a separate
Cancel/Escape test returned no successful field response, preserved revision 2 and
left the reader available. See [exact evidence and limits](docs/SEP-LOGIN-REVEAL.md#live-synthetic-login-acceptance--2026-11-06).
This does not establish real CLI migration, session-lock/expiry, broker restart,
reboot, browser or Apple-account/write acceptance. The complete goal remains open.

The post-cancellation fresh-client reveal now also passes at revision 2, with the
same broker process and no key/state reset. Main-profile recovery remains the
next prerequisite for real WebAuthn migration: a local status recheck still shows
an empty vault and Prepared trust repair with the prior peer retained. Resume
that existing repair in the user's terminal; do not create another peer/recipient
or treat the synthetic success as evidence that iCloud access is restored.


Account progress (2026-11-06): the user completed fresh password/SMS verification
and recovered the escrow sponsor. The Prepared repair now has a saved sponsor;
no further escrow recovery is needed to resume it. A fresh-token read validated
14 Passwords records. A strict parser then rejected optional identifier enums
omitted by Octagon recovery records. The corrected parser preserves exact scope
and explicit-type rejection, and a read-only probe now decodes 20 encrypted
shares/60 sync-key records. `status` exposes the safe recovery-checkpoint label.
The replacement-peer join and complete-snapshot/promotion gates remain open;
no Apple item write was performed. See [recovery details](docs/SYNC-RECOVERY.md#recovery-record-identifier-compatibility--2026-11-06).


The user subsequently completed repair. Local status confirms Committed/joined,
one retained prior peer and restored counts of two logins and two passkeys;
metadata-only inventory matches the original four record IDs. This satisfies the
main-profile authentication/recovery prerequisite for the authorized WebAuthn-only
migration. It does not migrate that credential or establish SEP browser use by
itself; fingerprint readiness and real browser validation remain separate gates.


The authorized main-profile WebAuthn-only migration now completed with a desktop
fingerprint at revision 1. Its original public metadata/fingerprint and the
unmigrated Apple.com baseline are unchanged, the software recovery copy is
retained, and unified inventory keeps all four items. A fresh main-profile native
host discovers the expected required-UV candidate with biometric availability.
Real browser/RP authentication, post-reboot validation and source-retirement gates
remain open; metadata inspection alone does not satisfy them.


Real browser follow-up: the open default browser was LibreWolf, outside the supplied
Chromium adapter. An isolated Chromium profile now loads the correct extension and
native host. The user confirmed its desktop fingerprint operation completed, but
webauthn.io rejected the old ID before signature verification. The demo's source
expires registrations after 24 hours, consistent with the original test's age.
No key was changed or discarded to work around that server refusal. Native fresh
registration/login and fresh-synced RP acceptance remain distinct pending gates.


Device-only browser acceptance now passed: the user registered and authenticated
`keychain-sep-20261106` in Chromium through the project extension/desktop prompt.
Fresh CLI metadata confirms a native device-bound ES256 credential and five total
items; the two original passkey baselines remain unchanged. This establishes the
native creation/login RP gate, not reboot or iCloud creation. The old synced demo
credential still lacks RP acceptance because the server no longer recognizes its
ID. A fresh Apple-created synced fixture is needed to test that remaining path.


Fresh synced RP acceptance now also passed: the user created a fresh Apple
Passwords credential for `testuser12345` on an Apple device. Sync fetched its new
record ID without changing a protected key in place, and preserved the native
credential. The new synced item completed biometric migration, then real Chromium
login succeeded. Post-use public metadata matches all intended baselines. Native
creation/login and synced decrypt/software-signing now both have RP acceptance.
This does not satisfy complete-chain reboot, source retirement, Rust-created
iCloud save/atomicity or other-device use of a Rust-created key. The iCloud writer
remains disabled and no service account has been enrolled yet.


Structured prompt implementation: the broker now sends typed operation, target,
selected account and storage fields, with canonical RP/origin validation. The
agent owns copy and exposes full origin under Details with its actual browser-
bridge trust boundary. Login copies do not claim cloud provenance, creation does
not claim completed upload, and cancellation checks never display a touch request
as their heading. Private wire version 2 is a coordinated broker/agent update;
legacy prose-based presentation is rejected. See docs/DESKTOP-UI.md. This is not
additional proof of the outstanding live SEP/reboot or Apple-write gates.

The new GPUI prompt subsequently passed a real disposable native-signing check
after fresh user readiness. A fresh process reopened the saved key and verified
the biometric signature for a new public message. The user confirmed the centered
floating window, readable themed contents and dismissal after touch. This closes
the new prompt's successful signing/appearance gate, without using saved passkeys
or contacting Apple.

Escape cancellation and post-cancel reuse then also passed through an isolated
diagnostic broker: the user confirmed Escape, the caller received Canceled with
no signature, and a separately authorized normal touch returned a verified
signature through the same broker PID/invocation, without a sensor or service
restart. The temporary fixture was removed after stopping that isolated unit.
The other remaining hardware/reboot and iCloud-write gates still need their own
evidence; this is not proof of every cancellation trigger.
