# SEP integration for keychain developers

## Current handoff: signing and biometric item decryption — 2026-11-05

Start with [the concrete decrypt API and working example](docs/sep-driver/DECRYPTION.md),
[the header](docs/sep-driver/sep-bio.h),
[the client](docs/sep-driver/sep-key.py), and
[the reference item envelope](docs/sep-driver/sep_envelope.py).
For the production helper design, also consider
[secret handling and process isolation](docs/sep-driver/SECRET-HANDLING.md).
These files are present HERE; no missing research prototype or raw SEP artifact
is needed to implement the application adapter. Driver development remains local;
no PR has been opened. The copies match local follow-up commit `85aabf1657`.

The loaded driver supports:

- `SepClient.create()` and `sign_digest(blob, digest)`: new native P-256 keys;
  private scalar stays in SEP and only the signature returns.
- `SepClient.create(decrypt=True)` and
  `decrypt_into(blob, sealed, output, timeout_ms)`: biometric-gated item decryption
  into a caller-owned 4096-byte bytearray. The recipient private scalar stays in
  SEP; decrypted item bytes enter host memory. Wipe them after the authorized use.
- `seal_item(public, context, plaintext)` and
  `item_view(output, length, expected_context)`: tested-format host encryption
  and authenticated item-binding checks. Python is a reference, not a hardened
  production secret-memory provider.

The same saved decrypt key worked after a warm reboot without a diagnostic
signature. Modified-tag input was rejected with no plaintext, a fresh request
with finger off timed out with no plaintext, successful output was consumed,
and the original signing-only key still produced an independently verified
signature. [Validation details](docs/sep-driver/VALIDATION.md) separate hardware
results from source-only checks and remaining production work.

There is no demonstrated native private-key import. A downloaded iCloud passkey
can be encrypted as an item, then biometric-decrypted for SOFTWARE signing.
New device-bound passkeys can use SEP-native signing. Protect selected-record
metadata, check owner/RP/purpose, and verify decrypted item context before use.
Do not claim that a synced scalar decrypted to the host stays non-exportable.

Next application work is the real provider/privileged transport, item-envelope
storage, identity/purpose binding and disposable integration validation. The
hardware primitive is no longer blocked on proving biometric decryption. This
does not authorize automatic migration of the existing software root: no vault
migration/recovery transaction has been validated. Do not replace a root or fall
back silently when an operation is unsupported. Keep data and current backups.

The device remains root-only/exclusive; coordinate fprintd. Signing capability
bit 2 is not a decrypt capability bit; this local extension requires the known
compatible driver and explicit unsupported-error handling. The module is
currently loaded temporarily; reboot may select a different driver. Do not
provision the system keybag, restore xART, reuse test keys, or change enrollments.

## Historical context — superseded by the current handoff above

The older notes below retain the research progression. Claims that decryption,
fresh request contexts or the concrete API are still missing are historical.
Use the current header/client and DECRYPTION.md for implementation; do not
reconstruct the firmware protocol in this application.


## Concrete driver API available for integration — 2026-11-04

The local Aurora review implementation now exposes explicit application key
ioctls. See [the API and example](docs/sep-driver/README.md),
[the userspace header](docs/sep-driver/sep-bio.h), and
[the runnable reference client](docs/sep-driver/sep-key.py). These copies are
from local review commit `bbeb7c0900`; no upstream PR has been opened.

The test module is currently loaded on this MacBook. Hardware validation passed
on J293/M1 on 2026-11-05: key creation, a real right-index-authorized signature
verified independently, a new request with the finger removed returning no
signature, ordinary fingerprint matching, and a second verified signature with
the SAME saved wrapped key after a warm reboot. Successful completion includes
acknowledged credential deletion. These results use the concrete new ioctls,
not a fake provider or reserved-field ATTEST protocol. Cold power-cycle,
suspend/resume and other hardware profiles are not claimed by these tests.

Implement the concrete `SepProvider` against KEY_SIGN_START/KEY_SIGN_POLL and
CANCEL, storing a key reference mapped to its wrapped blob and expected public
point. The provider already receives a SHA-256 digest: pass those 32 bytes
unchanged. Do not use the message-hashing `sign` command on a digest. The reference
client exposes `SepClient.sign_digest` and a matching `sign-digest` CLI mode:

```sh
sudo python3 docs/sep-driver/sep-key.py create application-key.json
sudo python3 docs/sep-driver/sep-key.py sign-digest application-key.json digest.bin signature.der
```

Here `digest.bin` contains exactly 32 raw bytes, not hexadecimal text.
 The device is root-only and exclusive; a trusted helper/broker must
coordinate with fprintd for an unprivileged application. The example is a
reference client, not an authenticated multi-user broker. Keep origin/RP/key
ownership checks in the application. Verify returned signatures against the
saved public key and exact digest, and do not retry ambiguous completions.

**Biometric unsealing is not required for native P-256 signing.** It remains
unsupported and must still block protected-root migration. Existing synced
passkeys are not replaced by newly generated SEP keys. The interface also does
not provide P-384 or private-key import. Keep unavailable capabilities explicit.

Earlier prototype-file references below refer to the separate development host,
not this application workspace. The header and example above are the concrete
interface to use; no raw machine artifacts or SCRD handles are needed by this
application. The test kernel/module is temporary, so recheck the advertised
capability after reboot rather than assuming this interface remains loaded.


Status: 2026-11-04. Biometric-authorized P-256 signing has been demonstrated on
J293/M1 under native Linux. A stable application-facing SEP key API has not yet
been implemented. This document separates the working primitive from the work
needed to integrate it into this repository.

## Start here

Keep Apple authentication, Octagon, CKKS and browser request validation behind
their existing boundaries. Implement SEP support through
[`SecurityBackend`](src/security/mod.rs), with a small transport client and an
explicit authorization interface. The current CLI and one-shot browser host do
not need to become an always-running keychain daemon.

Do not implement biometric protection as `fprintd.verify(); software_sign()` or
as a client-supplied `user_verified = true`. The demonstrated mechanism has SEP
enforce an access policy on the actual key operation. A normal fprintd result
does not supply the SEP authentication context required by that operation.

The next practical dependencies are a maintained driver/broker interface,
validated context isolation and disposal, and biometric-gated unsealing. Do not
advertise these as already available just because the signing experiment works.

## What is proven

The experiment created two disposable keys, preserving existing machine keys
and fingerprint enrollments. The same wrapped keys were used after reboot.

| Operation | Result |
| --- | --- |
| Unrestricted P-256 control signing, including after reboot | Signature verified independently |
| Biometric-policy key signing without an authentication context | SEP refused |
| Signing with a passcode-validated context before a scan | SEP refused |
| Ordinary fingerprint identification followed by signing | Finger matched; signing refused |
| Fingerprint matching into the signing context, then signing | Signature verified independently |
| Another signature using that context, without a new scan | Signature verified independently |

The successful signatures covered distinct supplied digests and used the same
biometric key, distinct from the unrestricted control. No host boolean or
Linux-generated match-result token was substituted for a SEP credential.

Important limits:

- The authenticated context is reusable. Fresh-fingerprint-for-each-operation
  semantics have not been established.
- Only the J293/M1 biometric P-256 signing path has been demonstrated here.
  Other platform/firmware profiles must report their actual capabilities.
- Biometric-gated unsealing, importing existing private keys into SEP,
  SEP-native P-384 operations, context revocation/isolation and enrollment-set
  invalidation still require validation.
- Key/context capacity limits have not been measured. Wrapped blobs avoid
  assuming a permanently resident key slot per item, but do not imply unlimited
  resources. Bound live contexts and loaded keybags and clean them up.
- The prototype used one configured identity context. Multi-user isolation has
  not been validated; do not route every Linux user through one shared context.

## Three distinct uses in this project

### Protect the local vault and imported software keys

The existing backend reads a plaintext software root from `software.key`,
derives purpose keys and encrypts state and the key database. See
[`software.rs`](src/security/software.rs) and [`store.rs`](src/store.rs).

The first broadly useful integration is an envelope backend that protects a
local root/data key with a biometric-policy SEP key. After authorized unsealing,
retain the existing HKDF purpose separation and AEAD envelope design. Bulk vault
encryption remains in the host process. Unwrapped roots, decrypted records and
software private keys do enter host memory and must retain existing zeroization
and bounded-lifetime handling.

This is a proposed use of the primitive: biometric-gated unsealing must pass its
own negative and positive tests before this backend is enabled. Aurora's current
machine-ref-key trusted-key backend does not provide this policy by itself.

Define unlock scope explicitly: one command, one selected item or an explicitly
bounded session. Opening the vault once must not silently become authorization
for every later signing request. The browser inspection and assertion stages
are separate one-shot processes; plan their prompting and metadata access rather
than relying on a hidden process-global unlocked flag.

### Continue using synced iCloud passkeys

[`RecoveredPasskey::import`](src/passkey.rs) imports an existing P-256 private
key through `import_p256_x963`. That existing key must remain the same: its
public key is already registered with the relying party. Generating a new SEP
key cannot replace it transparently.

Until SEP private-key import is proven, protect the imported scalar/key database
using the SEP-gated envelope backend and perform signing in software after an
authorized unlock. Describe this accurately as SEP-protected storage with
software signing. It is not a newly generated non-exportable SEP private key.
Preserve the synced credential's identity and backup provenance.
Once the scalar is available in host memory, SEP cannot force authentication
for every subsequent software signature. A broker can apply a per-use policy,
but that is a different guarantee from a SEP-enforced native key operation.

### Add new device-bound passkeys

A newly generated SEP P-256 signing key is the appropriate primitive for a new
device-bound credential. Persist an opaque key reference, its wrapped blob,
public key, policy and credential metadata; never request a plaintext private
scalar. This repository currently lacks `generate_p256` in `SecurityBackend`
and does not implement WebAuthn credential creation. Add those deliberately.

A new local credential also needs a registration flow with the relying party,
its own credential ID and explicit provenance in the model. Do not invent an
Apple CKKS record or add Apple-account writes as a side effect of this work.

## Backend and authorization changes

The current `BackendCapabilities` describes algorithms but cannot distinguish
native SEP signing, imported software signing, biometric requirements or
verification freshness. Extend it with explicit supported guarantees. Do not
claim native P-384/import support to satisfy callers that require it; the
existing Octagon flow needs P-384 signing, ECDH and recovered-key import.
A hybrid envelope backend can retain those software operations without claiming
they execute inside SEP.

Keep `KeyRef` opaque. Validate backend, algorithm, usage and access rights on
every operation. Persist key policy and provenance separately from display
labels. Changing a backend ID is not a state migration.

Add a typed authorization request/session boundary. The existing
`sign_p256_sha256(key, message)` method has no way to express fresh biometric
authorization or return a trustworthy verification outcome. Do not solve this
with a new global boolean or a reusable token copied from the browser request.
An example contract, not an existing API, is:

```text
sign_p256_sha256(key_ref, message, authorization_request)
    -> signature_der + trusted authorization outcome
```

The authorization request identifies the selected key, operation and exact
message/request being approved. Capture, cancellation and completion belong to
one transaction. The internal SEP context must never be returned to an
unprivileged application as a reusable bearer handle.

Prefer a safe Rust client for a narrow, versioned transport. An on-demand
privileged SEP broker can own device permissions, serialize access with other
biometric clients and manage contexts while the CLI/browser host stay one-shot.
It must authenticate peers and enforce key ownership; a caller-supplied app name
is not an application identity. Same-UID application isolation needs a real
sandbox/portal or other trustworthy identity mechanism if it is a requirement.

If direct ioctl bindings are necessary, isolate them in a small reviewed crate
or module. Do not relax this package's `unsafe_code = "deny"` globally. Do not
shell out to root-only experiment scripts, parse kernel logs as responses, or
reuse the prototype's reserved-field ATTEST commands as an application ABI.

The proposed fresh-use flow is: create an operation-scoped context, prepare it,
match into it, execute the exact approved operation and dispose of it on every
exit path. Validate real SEP deletion, isolation, stale-context behavior and
loss-of-connection handling before promising this guarantee. The experiment
proved that keeping an authenticated context permits additional operations;
the key policy did not cryptographically bind that grant to one message.

Return explicit errors for cancellation, mismatch, unsupported policy, missing
hardware, unavailable key and ambiguous completion. Do not silently fall back
to the software root, a passcode-only grant or an unrestricted machine key.

## WebAuthn integration details

[`sign_assertion`](src/passkey.rs) currently signs
`authenticatorData || clientDataHash`. Its backend method accepts message bytes,
whereas the demonstrated SEP `osgn` operation accepts a precomputed 32-byte
digest. Hash the complete message once with SHA-256 at the agreed transport
boundary. Do not double-hash or sign only the browser challenge. SEP returned
DER ECDSA `(r,s)` signatures, matching the current backend's DER output.

[`browser.rs`](src/browser.rs) currently refuses `userVerification: required`.
Keep that refusal until the request-bound biometric path works end to end.
The public `user_verified` boolean in `sign_assertion` is not evidence of
verification. The browser must obtain that outcome from the trusted operation,
not its incoming JSON or the approval window. Build the intended signed flags
inside the authorized transaction and return an assertion only if it succeeds.

The current code always sets BE and BS for synced credentials. Model credential
provenance explicitly before adding device-bound keys. For a single-device
credential both bits are zero; moving a synced key into protected storage does
not change its backup eligibility. UV requires actual user verification, and
BE cannot change after registration. See the
[WebAuthn authenticator-data and backup-state rules](https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data).

Preserve the existing exact origin/RP binding, credential allow-list, request
bounds and browser-origin checks. SEP signing is not a replacement for those
checks or a complete WebAuthn authenticator. A key-possession signature is also
not Apple-certified authenticator attestation.

## Driver-side mechanism and reference pointers

These details explain the successful experiment; they belong in the SEP
provider, not in Apple protocol or browser code. Reuse typed builders and
platform profiles rather than constructing firmware packets in this application.

1. Create a distinct wrapped reference key with an authenticated biometric ACL.
   Apple's operation dictionary carries policy under `ed -> acl`; the signing
   constraint is `osgn -> cbio -> pbioc`, bound to the live catacomb identifier.
   The demonstrated policy is biometry-any. Current-set policy additionally
   uses `pbioh`; its invalidation semantics have not been tested here.
2. Prepare a real SCRD authentication context. Supply it to key operations as
   `acmh`. An ordinary Linux fprintd result token is not this context.
3. Match into that same context. In the matching macOS 13.5/J293 firmware
   request, the base image-init header is 0x97 bytes. Set the little-endian match
   flags word at offset 0 to 0x08, the little-endian context length at offset
   0x93, then append the context at offset 0x97. The demonstrated context is
   16 bytes, giving a 0xa7-byte request. Preserve all other normal capture fields.
4. Submit the key operation with the same context and wrapped key. Parse both
   mailbox and operation status and return a signature only on success.

The separate SEP research checkout contains `drivers/soc/apple/refkey_probe.rs`
and the capture hook in `sbio.rs`; the companion notes are
`j293-mesa-trace/SEP-BIOMETRIC-KEYS.md` in the `j293-mesa-host` workspace.
Ask the SEP maintainer for that source snapshot/maintained transport if it is
not present in your workspace. These experimental additions are not implied
to exist in the public Aurora branch.

Public reference code is in
[Aurora's SEP branch](https://github.com/aurora-silicon/linux/tree/feat/sep/drivers/soc/apple):
`refkey.rs`, `scrd.rs`, `sks.rs`, `sbio.rs`, `refkey_seal.rs`, `trusted.rs` and
`sep-bio.h`. The stock ATTEST operation signs with the machine reference key;
it is not a per-application biometric-key API. The stock trusted-key adapter
explicitly ignores policy options. Neither is a substitute for this feature.

The proof used native Linux; boot instrumentation is not an application
dependency. Raw protocol versions and key type/class numbers are profile
details, not constants to copy into `SecurityBackend`.

## Persistence, migration and recovery

Store wrapped blobs and authenticated metadata durably with existing private,
bounded, symlink-resistant file handling. Do not persist raw SCRD contexts as
application state. Protect against key-reference, algorithm, policy and purpose
substitution, and define crash recovery for interrupted creation/deletion.
Deleting a host blob alone does not prove cryptographic revocation of backup
copies; that behavior remains to be established.

An explicit software-to-SEP migration must preserve the existing root and
private keys, verify the new protection after a fresh process/reboot, and commit
atomically before removing the plaintext software root. Never generate a new
root just because protected state cannot be opened. Migration does not
retroactively protect backups containing the old software root.

SEP-bound data may become inaccessible after device erasure, keybag changes or
loss of the hardware. Device-bound passkeys require a separate recovery plan;
synced credentials retain their distinct recovery model. Do not automatically
rerun Apple escrow recovery or Octagon join to repair a local backend error.

The application must never provision/replace the system SEP keybag, reset
enrollments, fork xART storage or restore old SEP/xART snapshots. The driver owns
shared-xART durability and must commit mutations before acknowledging SEP.
Use only the current secure-state lineage; no pre-erase artifacts are inputs to
application provisioning. Test with disposable application keys.

## Suggested implementation sequence

1. Add typed client/capability and authorization interfaces with a fake provider.
   Keep current software behavior explicit and unchanged. Test refusal when a
   requested guarantee is unsupported.
2. Productize the context-bound P-256 operation with the SEP provider. Test
   pre-auth denial, wrong finger, cancellation, exact-message signing,
   independent signature verification, fresh-context isolation, context cleanup,
   expired/replayed requests, reboot reload and disconnect handling.
3. Prove biometric-gated unsealing, then add the envelope backend and explicit
   migration. Test that the protected backend cannot open without authorization
   and cannot fall back to the old plaintext root.
4. Integrate synced passkey authorization and UV truthfully, with software-key
   exposure documented. Add new device-bound credential registration and
   provenance/BE/BS handling as a separate feature.

Keep protocol, transport, storage, prompting and browser validation in separate
modules. Use focused functional commits and tests; do not combine this work
with formatting sweeps or changes to Apple account/trust protocols.
