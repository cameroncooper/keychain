# SEP authorization-session research handoff

Date: 2026-11-08. Audience: the kernel/SEP driver agent.

## Objective

Investigate whether our SEP application-key path can support a bounded reusable
biometric authorization context. The desired Passwords-app experience is:

1. Authenticate once to unlock a Passwords session.
2. Reveal selected passwords and generate current TOTP codes during that session
   without a fresh fingerprint for every reveal.
3. Lock explicitly or automatically, revoke pending delivery and require a fresh
   authentication for the next session.

Prefer keeping items encrypted until requested and using SEP for each protected
item operation. Reusing authorization must not mean retaining the entire decrypted
vault. Browser autofill and passkey signing need their own authorization scopes;
opening the GUI must not silently authorize every same-UID client.

This is a research request, not an agreed ABI or authorization to weaken current
key policy. Coordinate any live fingerprint capture with fresh user readiness.
Use disposable fixtures, not real credentials. Do not reset secure state, change
provisioning/enrollments, rotate existing keys or change password-fallback policy.

## What Apple's public documentation establishes

### Reusable authenticated contexts

Apple documents `kSecUseAuthenticationContext` as accepting an `LAContext` for
Keychain authentication. Without a supplied context, an authentication-required
operation creates a context for that operation. A previously authenticated
supplied context can satisfy later Keychain operations without a new prompt;
a successfully authenticated context can subsequently be reused.

Source, available on macOS since 10.11:
[Security: kSecUseAuthenticationContext](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext).
Apple also publishes a directly readable
[Markdown version](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext.md).

`LAContext.invalidate()` cancels pending evaluations and prevents subsequent
policy evaluations using that context:
[LocalAuthentication: invalidate](https://developer.apple.com/documentation/localauthentication/lacontext/invalidate()).

Apple's documented mechanism establishes that authorization reuse is supported;
it does not establish the proprietary Passwords app's exact implementation,
its private SEP protocol, whether it caches particular plaintext, or its exact
inactivity timeout. The user's observed unlock/reveal/relock behavior is the UX
reference, not proof of a specific internal key hierarchy.

### Do not confuse device-unlock grace with app-session lifetime

`touchIDAuthenticationAllowableReuseDuration` can reuse a recent device unlock
performed with Touch ID. Apple's sample describes a maximum of five minutes and
explicitly distinguishes this grace period from Keychain retrieval authentication.
It is not documentation of a five-minute Passwords-app session or an arbitrary
reusable SEP credential's lifetime.

Sources:
[Accessing Keychain Items with Face ID or Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id),
[reuse-duration property](https://developer.apple.com/documentation/localauthentication/lacontext/touchidauthenticationallowablereuseduration).

Apple separately documents Keychain access-control constraints and Secure Enclave
evaluation. Do not assume a successful fingerprint match alone authorizes every
key, operation, application or user:
[Keychain data protection and access control](https://support.apple.com/guide/security/secb0694df1a/web).

## Our current implementation and constraints

The authoritative current handoff is
[SEP-BLOCKING-MIGRATION.md](SEP-BLOCKING-MIGRATION.md). It records blocking
`/dev/sep-keys`, interface version 1, and a fresh kernel-owned biometric credential
for every private-key operation. Credentials do not reach userspace. Existing
sign/decrypt requests are single operations, with blocking execution and
concurrent cancellation on the same open file. Native signing keeps the scalar
inside SEP; decryption returns the selected plaintext to the caller.

Canonical UAPI/source references and the exact installed reference-client paths
are in that handoff. Use those definitions. The polling ABI in `docs/sep-driver/`
is historical; do not implement a new session feature against its START/POLL API.

Application code relevant to a future integration:

- `crates/sep-driver/src/lib.rs`: blocking device adapter and cancellation.
- `src/security/authorization.rs`: operation-bound verification outcomes and
  capability reporting. An old successful result is not a reusable grant.
- `src/broker/native.rs`: native prompt, active-session checks and cancellation.
- `src/broker/login.rs`: selected-item policy, biometric decryption, intentional
  reveal/current-code generation and wiping after consumption.
- `src/security/sep/envelope.rs`: per-item envelopes and trusted context checks.
- `src/broker/session.rs`: current local desktop-session checks.

Existing item envelopes do not yield a reusable vault master key when one item
is decrypted. An application `unlocked` Boolean cannot bypass another item's
SEP requirement. Caching one revealed item would only make that item reusable;
it would not unlock other protected items.

## Kernel/firmware questions to answer

Please distinguish observed behavior from hypotheses in the report.

1. Which firmware objects implement the current authentication context and
   biometric credential? Which layers own their lifetime and disposal? Identify
   the relevant call sequence and policy fields, without logging credential bytes.
2. Is the credential single-use, or does our driver currently choose to dispose
   a reusable credential after one operation? Can a context survive more than one
   successful private operation without another sensor match?
3. What is it bound to: a key/blob, access group, identity/keybag, credential set,
   operation/purpose, challenge, digest, firmware connection or generation?
   Can it authorize distinct messages and different eligible item keys? A
   per-key context is still useful; report that limit explicitly.
4. Does reuse work with the existing signing and combined signing/decryption key
   profiles and existing wrapped blobs, or require different ACLs/key creation?
   Does any apparent success depend on the automatically validated machine
   context rather than a real prior biometric event?
5. What expiry, reuse count, lock-state, enrollment-change or anti-replay constraints
   does SEP actually enforce? Which constraints would instead be enforced only by
   the Linux kernel or broker? Do not describe a host timer as SEP enforcement.
6. What happens after cancellation, a failed operation, transport loss, sensor
   recovery, sleep/resume, firmware reset or a failed credential-destruction call?
   Can the authorization still be used? Can destruction race an in-flight use?
7. Can such a context be revoked reliably, including when no private operation is
   active? What must be drained/joined before releasing it? What can firmware
   finish after revocation, and what must the driver suppress from delivery?

## Desired interface properties, if firmware supports reuse

These are requirements to evaluate, not proposed ioctl numbers or layouts.

- Keep the current fresh-per-operation API/policy working unchanged. Negotiate an
  explicit optional capability/version for session reuse; fail closed when absent.
  Do not repurpose version-1 reserved fields or silently broaden existing keys.
- Begin with a deliberately requested biometric session. Keep its credential and
  firmware context kernel-owned. Userspace receives at most an opaque reference,
  never authentication material or a reusable exported credential blob.
- Bind the session to its owning device-file context and appropriate kernel
  identity. Explain descriptor duplication, inheritance, transfer, process exit
  and final-close behavior; an opaque ID alone is not an ownership boundary.
- Separate session lifetime from each operation's request ID, digest, timeout,
  cancellation and single-result rules. Preserve exact input binding and existing
  strictly increasing request IDs. A canceled result never becomes deliverable
  because its authentication session is still alive.
- Enforce bounded lifetime/revocation below the GUI. Specify the clock and behavior
  across suspend; a monotonic clock that pauses in suspend alone is insufficient
  to implement an elapsed-time expiry spanning sleep. The broker must still
  convey desktop lock/logout/suspend events and enforce application scopes.
- Revoke first, reject new uses, cancel/revoke pending delivery, drain outstanding
  users and dispose the credential. Credential-cleanup failure must not leave an
  apparently usable session or relax the existing fail-closed/poison behavior.
- Retain ordinary `sign`/`decrypt` success/failure semantics and buffer wiping.
  Do not automatically replay an uncertain private operation during renewal or
  recovery. A session reference must not become generic permission for every key.

If the driver cannot enforce a requested application-specific restriction, state
that explicitly; the broker can enforce narrower item/operation/origin rules.
Linux desktop-session validity and application identity do not come from a
userspace-supplied UID or the mere fact that a process can access an opaque ID.

## Focused disposable-fixture acceptance evidence

Run only after the relevant live-capture readiness and test scope are established.

| Case | Required evidence |
| --- | --- |
| No authentication | Session use cannot produce plaintext or a signature |
| Initial authorization | One real biometric event establishes the intended context |
| Repeated use | Distinct authorized decrypts/messages work without a second touch; independently validate outputs |
| Cross-key use | Allowed/forbidden key and policy boundaries are demonstrated, not assumed |
| Wrong handle/file/owner | Rejected without private output; include dup/transfer behavior |
| Explicit revoke | Further use fails; a raced result cannot be delivered after revocation |
| Expiry | Reuse fails without silently acquiring fresh authentication |
| Cancellation | Per-operation cancel stays correct while the session is alive; no replay |
| Lifecycle | Close/exit, lock-event revocation and suspend/resume behavior are established |
| Failure cleanup | Transport/disposal failures do not leave a valid-looking reusable context |
| Compatibility | Existing fresh-per-operation keys still require fresh authentication |

Record timing, object/request identities, policy names, status/error codes and
independent verification outcomes. Do not record biometric material, credential
bytes, private keys or real item plaintext. Reuse success alone does not prove
that expiry, revocation or owner isolation is correct.

## Application work and alternatives

If feasible, the application will add a broker-owned, scoped unlock-session state
machine and GUI lock state. An idle timeout and hard maximum are separate policy
choices; background requests must not keep authorization alive indefinitely.
GUI sessions should be bound to an authorized client/channel rather than becoming
a global same-UID unlocked flag. Browser autofill retains item/origin checks;
passkey user-verification semantics remain a separate policy decision.

If credential reuse is not feasible with the current profile, report why and
whether a different SEP-backed profile can support it. A dedicated vault wrapping
key unsealed into locked broker RAM could provide similar UX, but changes the
in-memory security model and requires a deliberate envelope/key-hierarchy
migration. It is not an equivalent result from this kernel investigation.

Password fallback/keybag research is separate. Do not change the identity-bag
secret or introduce software OR envelopes as a workaround. Combining a password
and current TOTP code from one already-authorized item decrypt is also a separate
application improvement; it does not require a reusable kernel credential.

Please return: feasibility and limits, the firmware/policy evidence, a proposed
minimal capability/UAPI contract if feasible, lifecycle/failure semantics, existing
blob compatibility, and a clearly separated list of untested assumptions.
