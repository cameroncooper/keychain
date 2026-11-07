# Disposable iCloud creation acceptance test

## Native creation chooser rollout

The storage chooser now lives in the unprivileged GPUI agent. Chromium forwards
the frozen request without a storage field; the root broker supplies allowed
destinations, validates the selection, and requires a second acknowledgment of
the drawn, focused bound summary before proceeding. The same window transitions
from the Apple-inspired save summary to fingerprint guidance. Private prompt
protocol 3 rejects earlier versions, replayed selections and unavailable choices.

The root broker and agent were updated together, with prior artifacts retained
under `/var/lib/keychain-service-backups/update.mi6g06_y`. All release binaries
were rebuilt serially. There are 234 passing library tests, 26 ignored privileged
tests, 11 passing browser tests, and passing strict Clippy across all targets with
the desktop-agent feature. The native popup was verified as floating at 420×400;
the compositor no longer overrides operation-specific sizes.

The first interactive preview exposed focus-follows-mouse canceling selection
while the pointer crossed another window. Selection now tolerates focus changes,
because it grants no authorization. A display-only live check verified selection
survives focus loss while the bound authorization state still cancels immediately.
Neither check opened SEP or contacted Apple. The user then confirmed Other
Options, selection and the same-window transition worked. The preview returned
an iCloud selection and a second Visible acknowledgment; no credential was created.

The isolated network worker and browser broker were restarted with their existing
state and thirty-minute idle limits. Chromium was opened with the updated unpacked
extension and existing isolated profile. The real native-choice registration/login
test for `keychain-icloud-20261106-5` is pending. Production iCloud creation stays
disabled, and all earlier drafts/credentials are retained. See
[the native prompt design](NATIVE-CREATION-PROMPT.md) for the state machine and
trust boundaries.

## Fresh registration proposal after the parser fix

The user approved this transaction and readiness for its two fingerprint steps:

- UUID: `b2c70bee-8f52-4b7f-9796-4d77d4c2a520`.
- RP/origin: `webauthn.io` / `https://webauthn.io`.
- Username: `keychain-icloud-20261106-2`.
- Same staged account/owner/zone, isolated registry and item recipient.
- Private review: `/var/lib/keychain-live-write-check-20261106/fresh-registration-review.json`.
- One negative attempt, then one positive save only after definite rejection and
  authenticated absence. Each request and response is captured privately, with
  both operation UUIDs known before sending.

The live read-only review verified this UUID absent and authenticated the current
hierarchy. Fresh real site options were then frozen separately. The negative
attempt passed: both exact request UUIDs were checked against Apple's explicit
atomic/oplock rejection, the coordinator journal became Rejected, and an
independent authenticated fetch confirmed absence and the unchanged pointer.
The exact full outgoing request, reply and negative evidence are retained. This
closes the negative protocol gate with the corrected parser.

The first positive biometric operation returned EACCES/match-or-authorization
refusal before any save input was prepared. After separate fresh readiness, its
retry closed almost immediately with uncertain SEP completion. No positive send
artifact exists; the journal remains Rejected and no registration response was
created. GET_INFO still advertised ABI 4/signing/sensor/two prints, but the kernel
reported sequence-counter/session setup failure and that the sensor did not come
back online. Capability advertisement is not proof of current sensor health.
Further captures are paused pending driver/sensor recovery. The key, frozen
request and successful negative evidence are retained; nothing is regenerated.

The demo challenge expired during this hardware failure. After sensor recovery,
use a fresh explicitly scoped real registration for the positive/other-device
gate, without replaying or silently rebinding this frozen request. The completed
negative protocol test need not be repeated solely because the site nonce expired.
The earlier transaction's two attempts and key below are also unchanged.

The user subsequently restored the sensor by invoking a separate verification;
the driver's existing sensor re-registration/bring-up sequence completed. No app
key, draft or journal was replaced. Application captures have not been retried
since that restoration report. Driver-error diagnostics now retain the numeric
errno without printing payloads or free-form errors, and EACCES is described as
verification not accepted rather than asserting that the wrong finger was used.

The next proposed test uses ordinary Chromium registration for
`keychain-icloud-20261106-3`, with one normal browser-generated transaction and
explicit Save to iCloud selection. The completed negative gate need not repeat.
An isolated browser configuration is staged under
`.sep-check-icloud-browser-20261106`, routing its native host to
`/run/keychain-icloud-browser-check-20261106/broker.sock` and the existing isolated
root registry. No default browser/native-host configuration changes. The browser
will obtain its challenge at the user's Register action; its selected scope and
generated UUID are frozen/validated by the normal host/broker before any send.
This proposed new creation still needs explicit user initiation/approval; the
production service's creation flag stays off. Do not replay an earlier frozen
transaction or claim other-device acceptance until actually observed.

The first manual browser attempt returned the site's generic authenticator error
before any chooser or desktop prompt. No new creation draft appeared. The isolated
browser's native-host manifest had been staged under its XDG config directory,
but Chromium resolves `NativeMessagingHosts` under its actual `--user-data-dir`.
The manifest was copied into that isolated user-data directory, preserving the
same launcher and exact extension allowlist. This changes only test setup; no
capture or creation request was replayed. Browser retry and positive acceptance
remain pending.

### Fresh browser registration after acknowledgment update

The user completed the proposed `keychain-icloud-20261106-4` browser step. New
transaction `f6e8c203-bf0d-476b-a38a-24a4230e0f5e` has a durable FetchVerified
upload and a promoted protected credential. A fresh read-only diagnostic confirmed
the durable upload phase and exact fetched name/type/all requested fields. A
separate unprivileged broker inventory request found this credential with the
expected RP and username, confirming it is committed and visible to the browser.
The biometric agent acknowledged presentation without reporting cancellation.

These are application-side registration and cloud verification results. Explicit
RP success, fresh Chromium authentication and use from a trusted Apple device
are being checked separately. No extra signing or capture was started by these
read-only checks, and production creation remains disabled.

The user subsequently confirmed registration and Chromium login worked for this
fresh credential. This closes the RP creation/login gate for this isolated
iCloud-write flow. Other-device use remains open. The subsequent save-dialog
work changes the browser's storage chooser, with iCloud selected by default when
offered and device-only storage under Other Options; native biometric policy is
unchanged.

After the manifest correction the browser displayed the storage chooser. Choosing
iCloud then returned `prompt was not presented`, with no new creation draft. A
separate display-only request received the expected Visible acknowledgment. The
agent's initial focus tracking could cancel during window mapping before any
drawn frame was acknowledged, including while the browser chooser closes. Focus
loss now cancels only after presentation has been acknowledged; acknowledgment
still requires a drawn, visible, focused window, and capture remains blocked until
then. The browser path needs a fresh manual retry to verify this diagnosis.
The rebuilt agent was installed with its predecessor retained under
`/var/lib/keychain-service-backups/update.p_hq94rq`, then restarted. A new
display-only request received Visible without starting reader verification.
The release build, desktop-agent Clippy and seven prompt protocol tests passed.
The isolated broker and worker were also restarted after their ten-minute idle
expiry, with thirty-minute idle limits for this acceptance session.

The next browser attempt briefly showed the fingerprint window, then returned
`biometric authorization canceled`. A draft for
`15a9e12b-e517-41df-a87e-f74b3dee46c6` is retained. This is not registration or
upload success. A display-only window remained presented through three status
updates without requesting SEP verification. Existing logs did not distinguish
focus loss, request disconnection, session invalidity or SEP cancellation.
The agent and broker now log fixed lifecycle/cancellation reasons without account
labels, origins, item identifiers or credential material. The next manual browser
attempt is diagnostic; no cancellation checks were weakened or operation replayed.
The release broker and agent were installed and restarted, preserving previous
binaries under `/var/lib/keychain-service-backups/update.yyppbbsi`. Native-host
availability passed without capture. Release build, strict Clippy and 16 broker
tests passed; 21 privileged/live tests remained ignored.

### Hands-off retry: sensor bring-up failed

The user confirmed the popup also closed without moving the mouse. At 17:21:54
America/Chicago the agent acknowledged presentation; at 17:21:55 it logged
focus-loss cancellation. The corresponding retained draft is
`49050353-2ec4-40d8-b562-1d6725773713`. The component that took focus is not yet
identified; focus-follows-mouse alone is not an established cause. A separate
display-only prompt over Chromium stayed presented for five seconds.

The later hands-off attempt at 17:24:47 failed differently: the agent acknowledged
presentation and logged no focus cancellation. The broker reported uncertain SEP
completion with errno 5 (EIO). The kernel reported:

```text
sequence counter: the enclave refused the sensor's reply, status 0x107
sensor patch: sequence counter init failed before the patch fetch
verify: the sensor did not come back online
```

Its draft `4815eb9b-5da4-420a-8029-db28b48ceae9` is retained. These logs locate
this failure in sensor bring-up, but do not establish the firmware meaning of
0x107 or whether earlier cancellation caused it. No additional captures, automatic
retry, module reload or secure-state reset were performed. Driver-side recovery
is needed before resuming real biometric tests; the earlier focus issue remains
open separately. A successful fresh browser registration and other-device use
are still unverified.

### Save acknowledgment failure after successful biometric use

After the user restored the sensor again, the next browser registration reached
Apple's save response. Transaction `b8ec5eee-a593-4a5e-bb2c-99f1d74edd97` failed
the acknowledgment's identity/content comparison. Its journal remains Attempted;
the normal browser flow did not retain the raw reply, so the exact failing
operation/field cannot be identified retrospectively from that response.

A root-only read-only diagnostic fetched the complete authenticated zone. The
record exists with the exact requested name and type, no missing requested fields
and no differing requested fields. No save, SEP capture or journal transition
was performed by that inspection. This confirms the encrypted upload is present;
it is not yet a cryptographic backup receipt or completed RP registration.

Acknowledgments now allow omitted fields but still reject conflicting returned
fields, wrong identity/type/zone/tag and mismatched operation IDs. They retain
the actual sparse server record rather than synthesizing requested fields. The
coordinator still requires a complete independent fetch, exact ciphertext and
decrypted credential/public-key verification before issuing backup evidence or
signing/promoting registration. New offline tests cover sparse acknowledgment,
tampered fetched data and read-only pending inspection. Fixed diagnostic logs
distinguish item/pointer identity mismatches from returned-content conflicts.

`examples/icloud-pending-check.rs` inspects an existing root-owned draft and its
upload journal without needing or replacing the expired browser request. Its
optional `--reconcile` verifies the already stored encrypted credential and only
checkpoints the local upload journal. A wrapping UploadIo refuses every save;
neither mode regenerates the key or produces a registration signature.

The exact existing transaction was reconciled with that no-save wrapper. The
complete fetched ciphertext decrypted and matched its retained credential and
public key. Its local journal is now FetchVerified; a fresh diagnostic process
confirmed that durable phase and another exact field comparison. No browser
registration was promoted or signed, and no additional save or fingerprint was
requested. The expired RP challenge is not replaced or rebound to this draft.

The updated release broker was installed with its predecessor retained under
`/var/lib/keychain-service-backups/update.gades2x3`; only the isolated browser
broker was restarted, keeping production creation disabled. All 231 library tests
passed (26 privileged/live tests ignored), and strict Clippy passed for the
library, broker and new example. The application-only focus trace showed the
fingerprint window remained focused throughout the successful biometric step;
focus returned to Chromium after the save-response error.

A fresh manual registration for `keychain-icloud-20261106-4` is proposed to
verify the revised acknowledgment handling end to end. Actual sparse live reply
contents have not been captured, so the exact reason for the earlier comparison
failure remains inferred. Contradictory replies will still be refused, with fixed
operation-specific diagnostics. Successful RP registration and other-device use
remain pending.

Use the fresh review with `--review` and a separate root-private request file
with `--request`; never overwrite the earlier frozen request. Stop if either
operation is uncertain or the user cancels. Submit the resulting registration
response to the real RP before its challenge expires, then verify actual use
from another trusted Apple device.

## Earlier transaction and retained evidence

Prepared 2026-11-06. The user approved this scoped test after the explicit
write-approval request. The first negative save attempt ran and remains uncertain;
there is no proven accepted save or completed registration. Each further biometric
operation still requires separately coordinated readiness.

## Fixed scope

| Field | Selection |
| --- | --- |
| Linux owner | 1001 |
| Apple account | The staged candidate, pinned by account fingerprint in the private review |
| Zone | Passwords, private database |
| New record / registration transaction UUID | `e996362b-1c01-4abd-a65b-80ba525726ef` |
| Proposed RP / origin | `webauthn.io` / `https://webauthn.io` |
| Proposed username | `keychain-icloud-20261106` |
| Account review | `/etc/keychain/upload-test-review.json`, root-only |
| Production writer | Remains disabled |

The live read-only review verified absence of this UUID in a complete 16-record
Passwords snapshot, authenticated one TLK, resolved the current class-A key, and
validated the raw pointer's account/zone/reference. The private report pins the
account fingerprint, class-key ID, pointer-record hash and change-tag hash.
The disposable worker was stopped and its temporary agreement-key registry
removed. Its private ADI state is retained for subsequent checks.

This review is not a prepared ciphertext, permission to write, a durable absence
proof or a backup receipt. No new passkey exists yet. A fresh site registration
challenge must be obtained before freezing the WebAuthn request; a locally
invented challenge cannot establish relying-party registration.

The diagnostic executable, isolated account registry and its sealed SEP item
recipient are staged under `/var/lib/keychain-live-write-check-20261106`. Recipient
creation did not start capture. The installed diagnostic passed default inspection
and refused an unconfirmed negative-write invocation, with registry file
sizes/mtimes unchanged and both workers inactive. The synthetic inspection request
was then removed. After scope approval, a fresh authenticated Apple preflight
matched the exact reviewed account, unused UUID and pointer hashes. Real creation
options were obtained from webauthn.io for the scoped username, with required UV,
resident platform credential, ES256 and no existing excluded credentials. The
complete request plus bridge origin was frozen as the root-only `request.json`
in that directory and passed the installed helper's non-capturing inspection.
The first negative attempt completed biometric item unlock, sealed-key staging
and encrypted CKKS preparation, then stopped without a definite rejection result.
Its immutable draft/intent, encrypted upload journal and exact attempted
ciphertext/pointer are retained. The journal is Attempted, not Rejected. An
independent complete authenticated fetch confirmed that the UUID was absent and
the exact original pointer unchanged. Offline validation of the retained request
also passes both coordinator and worker wire checks. Neither observation proves
that the original operation was explicitly rejected; the positive gate stays shut.

The original uncertain attempt is `d8f7ff89-ab59-4714-a7a2-a7e9703f99b8`.
The first diagnostic obscured its underlying error and did not retain its reply;
the exact failure cannot be reconstructed. The updated harness preserves the
underlying error, optionally saves received replies privately before parsing,
and has a separately confirmed one-send retry mode. Worker failure logs contain
only fixed stages/numeric HTTP status, never account data or free-form errors.
The user subsequently approved one retry and separately supplied readiness.
That retry used the same ciphertext and key and captured a 567-byte reply. Both
response headers used explicit NONE=0, both result codes were FAILURE=3, and the
client errors were ATOMIC_FAILURE=16 and OP_LOCK_FAILURE=15. The old parser
rejected NONE before inspecting those codes. A post-retry authenticated fetch
again confirmed absence and the exact original pointer.

The parser now accepts explicit NONE only for FAILURE, retaining both exact
operation-UUID checks, explicit status, no-success-payload and recognized-error
requirements. Synthetic tests reproduce the observed shape without publishing
private account records. The current journal remains Attempted: that retry
captured its reply but not the full outgoing message containing the second
operation UUID. We do not reconstruct expected UUIDs from a reply or invent a
rejection checkpoint after the fact. New diagnostic captures retain the complete
request before transmission and the reply before parsing, allowing strict offline
exchange validation. No third attempt or positive write has been run.

Do not refresh the frozen request now that a draft exists. The demo's published
[registration implementation](https://github.com/duo-labs/webauthn.io/blob/15d77cd9059618e0cb8c863303531fdcf7ee5a3a/_app/homepage/services/registration.py)
stores challenges for twice the advertised timeout. Our request advertised 60
seconds; that two-minute lifetime elapsed during diagnosis. Retain this key and
request for protocol investigation. After the negative gate is proven, prepare
a fresh real browser registration under its own explicit transaction/scope for
the positive/other-device acceptance test. Do not upload this expired registration
merely to call the test complete or transfer its approval to a different UUID.

## Execution gates

1. The disposable-signature check through the new GPUI window passed after fresh
   user readiness. The saved key's signature verified independently, and the user
   confirmed centering/floating, readability/theme and automatic dismissal.
   Further captures still require fresh readiness for their specific operation.
2. The diagnostic harness is `examples/icloud-write-check.rs`. Its offline tests
   cover one-byte tag alteration with opaque-field retention, scope/cancellation
   refusal and no replay after rejection, uncertainty or unexpected acceptance.
   Use the tested root-owned executable and the pinned review, not a browser IPC
   extension. This diagnostic does not enable production browser creation.
3. Explicit user authorization was obtained for the fixed scope above: one
   negative precondition attempt, then one positive create only after definite
   rejection and independent absence verification. Fingerprint readiness is
   separate from permission to write.
4. Use an isolated broker registry/worker and the retained private candidate
   identity. Freeze the real site's request, transaction, user and storage choice.
   Stop if the account or reviewed hierarchy differs. Durably seal the new scalar
   before any send; never regenerate it after an uncertain result.
5. Following the authorized selected-secret operation, inspect the exact encrypted
   item and both-operation request: new-item create-only, same Passwords zone,
   unchanged class-A pointer target and original opaque pointer encoding.
   Keep secrets out of logs/review output. No scalar enters the network worker.
6. For the negative attempt, change only the expected pointer change tag, with
   the diagnostic encoding validated offline. Do not change the pointer target,
   rotate a class key or overwrite an existing item. Require explicit whole-batch
   rejection and a fresh authenticated complete fetch proving this UUID absent
   and the original pointer unchanged. An error, HTTP success, mixed reply or
   unexpected item presence stops the test; none permits an automatic retry.
7. Only with a still-valid RP request, use a fresh authorized operation and the
   same staged credential identity. This invocation's challenge has expired:
   hold its positive leg and prepare the separately scoped fresh registration
   described above after the protocol gate passes. For a valid request, use the
   explicit rejected-upload recovery policy for the positive attempt.
   Require both acknowledgements and independent authenticated fetch/decryption
   before registration delivery or a backup claim. A new fingerprint may be
   required: the negative attempt does not retain a reusable biometric grant.
8. Complete registration/use on the RP, then verify that another trusted Apple
   device fetches and uses this Rust-created passkey. A record appearing in a
   list, local software verification or existing Apple-created passkey does not
   satisfy this gate. Account for the demo site's registration expiry.

Keep the draft, encrypted upload journal and exact key identity if a send or
delivery is uncertain. Do not delete or recreate them to retry. No existing
credential deletion, Apple.com migration, account repair, new peer, ADI reset or
recovery-copy retirement is part of this scope. Any cleanup of a successfully
created cloud record is a separately reviewed action.

Passing this test is evidence for the iCloud creation gates, not for the separate
warm-reboot, suspend/session-lock, expiry or other outstanding SEP acceptance
checks in [the completion plan](../SEP-IMPLEMENTATION.md).

## Diagnostic invocation

Build as the ordinary developer, sequentially:

```sh
cargo build -j 1 --release --example icloud-write-check
```

Stage the reviewed executable and isolated account registry in a root-owned,
private directory. Import the broker candidate with the isolated worker's socket
and provision that registry's item recipient explicitly. The helper never starts
a worker or provisions a recipient itself. Keep the production units unchanged.
Start the session authentication agent as its user before any coordinated capture.

The frozen request is the browser bridge's complete creation-options JSON,
including the real RP challenge, user handle and injected HTTPS origin. Store a
reviewed copy as a root-owned private regular file. The helper checks every input
ancestor for root ownership, symlinks and writable permissions; a path under the
developer's home is therefore not an administrator input. A synthetic request
may validate inspection mode only and cannot establish RP acceptance.

Default inspection checks the local request/account selection only. It starts no
worker, key creation, capture or save:

```sh
sudo -n /var/lib/keychain-live-write-check-20261106/icloud-write-check \
  --registry /var/lib/keychain-live-write-check-20261106/registry \
  --request /var/lib/keychain-live-write-check-20261106/request.json
```

Only after explicit write-scope approval and fresh fingerprint readiness, append
`--mode negative --confirm-record e996362b-1c01-4abd-a65b-80ba525726ef`.
The helper consumes the production selected-secret coordinator and records the
exact diagnostic ciphertext/pointer input privately before calling the worker.
It requires an explicit precondition rejection, a fresh authenticated absence
check with the unchanged reviewed pointer, and a Rejected coordinator journal
before saving negative evidence. It never sends a second request in that run.

The separately coordinated positive run uses `--mode positive` with the same
confirmation UUID, request and registry. It requires that negative evidence and
Rejected journal, then uses the existing explicit re-encryption/recovery policy
with the same sealed key. Successful independent fetch/decrypt and registration
signing save only the public registration response in the private registry.
Transfer that response to the real site's still-valid registration transaction;
the diagnostic itself does not submit it to the RP or launch a browser as root.

All write modes require a kernel-authenticated, already-running enrolled worker.
The root diagnostic should run with the broker's AF_UNIX-only network restriction;
Apple HTTP and anisette remain in the dedicated service. An uncertain result
retains the attempt inputs, sealed key and encrypted coordinator journal. The
helper refuses a positive resend of an Attempted journal. Default inspection
now reports the saved phase and validates an existing attempted request entirely
offline. No inspector opens the fingerprint reader or contacts Apple.

After separate approval for an additional negative attempt, `--mode retry-negative`
also requires `--confirm-attempt d8f7ff89-ab59-4714-a7a2-a7e9703f99b8`, as well as
the original confirmation UUID. It requires that exact Attempted journal and a
fresh authenticated absence/pointer check, uses RetryConfirmedAbsent with the
same sealed key and ciphertext, and keeps the original attempt file. A new
attempt artifact and any received raw reply are saved privately. It permits one
send only; uncertainty never enables an automatic resend or a positive save.

`--mode reconcile` is a separate no-save path for an existing Attempted, Accepted
or FetchVerified journal. It requires the same confirmed UUID, frozen request and
fresh biometric authorization. The coordinator independently fetches/decrypts
before completing registration; a transport wrapper refuses every save even if
the coordinator requests one. Absence remains unresolved and cannot authorize a
retry in this mode. It preserves key/request identity and saves only a completed
public registration response, never a scalar. This is not a way to renew an
expired RP challenge or retire earlier recovery material.
