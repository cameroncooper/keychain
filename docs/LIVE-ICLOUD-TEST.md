# Disposable iCloud creation acceptance test

Prepared 2026-11-06. No write authorization has been given and no Apple save has
been sent. This scope is a proposed test, not permission to execute it.

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
was then removed. No real RP request has been frozen and no draft, attempt,
negative evidence or registration response exists yet. Both write approval and
fingerprint readiness remain pending.

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
3. Obtain explicit user authorization for the fixed scope above: one negative
   precondition attempt, then one positive create only after definite rejection
   and independent absence verification. Fingerprint readiness is separate from
   permission to write.
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
7. With a fresh authorized operation, use the same staged credential identity
   and the explicit rejected-upload recovery policy for the positive attempt.
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

Both write modes require a kernel-authenticated, already-running enrolled worker.
The root diagnostic should run with the broker's AF_UNIX-only network restriction;
Apple HTTP and anisette remain in the dedicated service. An uncertain result
retains the attempt inputs, sealed key and encrypted coordinator journal. The
helper refuses a positive resend of an Attempted journal: investigate/reconcile
separately, without deleting state or changing the UUID to hide uncertainty.
