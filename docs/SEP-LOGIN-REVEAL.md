# Selected login protection and reveal

The broker implements login envelope staging, biometric verification and selected
reveal. This is the service foundation for milestone 4; the normal CLI still uses
the software vault. CLI migration, show/list routing and sync reconciliation are
not yet connected. No real login has been imported or revealed through this path.

The same SEP item recipient and ECIES/context format used for protected passkeys
protect a typed login payload. It does not introduce another encryption scheme or
an export interface for passkey scalars. Login and passkey purposes, payload magic,
registry namespaces and metadata encryption purposes remain distinct so one kind
cannot be interpreted as another or take over its record ID.

## Data and policy

`LoginMetadata` contains the record ID, domain, username, title, timestamps and
presence flags for password, notes and TOTP. Metadata lookup requires the paired
owner/active local session but no fingerprint and never opens the owner's vault.
Metadata is encrypted at rest under the broker metadata root. That software root
remains separate from the protected-root-unsealing follow-up.

The private payload is versioned `KCLOGIN` magic, three big-endian u16 byte lengths
and UTF-8 password, notes and TOTP URI. Parsing borrows the selected protected
allocation, rejects invalid UTF-8, lengths, trailing bytes, mismatched presence
flags and invalid TOTP configuration. It never creates an owned plist/JSON object
containing these fields. The ECIES context binds application, version, owner,
record, revision, recipient, login purpose/format and SHA-256 of the exact typed
metadata. Revision/owner/context checks precede use. Public-key encryption alone
does not authenticate a writer; authenticated owner IPC and the root registry
supply that policy.

The envelope remains bounded by the SEP API's 4096-byte ciphertext limit. Context
and ECIES overhead count against that limit. Oversized passwords/notes/URI
combinations fail before staging, preserving the source. Larger records need the
separately specified envelope-encryption design; no truncation or unprotected
fallback is used.

## Staging and recovery

`LoginImport::seal` assembles the selected fields into final-size protected memory
and encrypts them on the source side. Import IPC contains metadata and ciphertext
only. `ImportLogin` checks the exact recipient, expected revision, timestamps,
bounds and namespace before atomically staging `login-ID.pending.enc`. Incoming
JSON cannot set `verified` or supply a biometric-success assertion. A pending
update cannot hide or replace the currently verified active revision.

`VerifyLogin` opens the desktop prompt, performs a new selected biometric decrypt,
validates the context/content and commits only if the entire staged record still
matches. The verified active envelope is atomically published and fsynced before
the pending file is removed/fsynced. Reopening after interruption retains the same
revision/content; a leftover identical pending copy can be verified again and
cleaned up. Missing committed predecessors, stale revisions and changed staged
records refuse replacement. Explicit discard checks the staged revision and
cannot remove the active record. A missing recipient or metadata root never
triggers regeneration while encrypted login records exist.

These are broker-side transitions. The CLI migration journal must still retain
and bind the original source/recovery representation, publish broker-only routing
only after verification, and prevent fallback after a committed migration. No
source retirement is justified by the synthetic tests.

## Intentional reveal

`RevealLogin` requires an exact record ID and one explicit selector: password,
notes, TOTP code, or all three for intentional `show`-style disclosure. It accepts
no caller-provided title/domain, decrypt blob, seed-export selector, signing input
or authorization flag. Only a verified active login is eligible. Pending data is
excluded. The native desktop prompt names the selected stored account/domain and
requested output, automatically starts capture, and supplies no success grant.
The real SEP decrypt completion establishes fresh presence for that operation.

Password/notes remain borrowed from the protected decrypt mapping. TOTP URI
parsing and base32 decoding now use final-size locked, dump-excluded buffers; no
seed-bearing Url, query String or decoded-seed Vec is constructed. The URI source
is borrowed. Parameter names/values are percent-decoded directly into checked
protected destinations, with duplicate/invalid settings rejected. Configuration
validation does not compute a discarded HMAC; only an actual code request does.
The returned TOTP has code/expiry/period and no seed field.

The reply serializer writes directly into a bounded 32-KiB protected buffer rather
than a `serde_json::Value` or growing plaintext Vec. Session/cancel/deadline checks
run after decrypt, before serialization delivery and between write chunks. The
active registry is compared under its mutation lock immediately before output.
Late cancellation discards results; partial delivery is terminal and never gets
an appended error or automatic retry. Bytes already delivered cannot be revoked.
The caller checks cancellation and complete framing before accepting a response.

`broker::login::reveal` verifies the root kernel peer, request ID, selected record,
revision and returned field set. The caller becomes nondumpable before receiving
output. Read framing owns a wiping receive buffer; decoded password/notes have
individual wiping owners, including partially constructed response errors. The
owned result and generated code wipe on drop and unknown seed-shaped fields are
refused. Intentional output still exists in the requesting process and wherever
that process sends it. Parser/compiler/HMAC scratch is subject to the limits in
[the memory review](SEP-MEMORY-REVIEW.md).

The browser extension/native host does not expose these login operations. Future
browser autofill needs its own validated origin/selection policy before invoking
a reveal; the explicit CLI disclosure operation is not site-origin evidence.

## Validation and remaining acceptance

Offline tests independently decrypt synthetic envelopes, verify context/content
binding, encode/decode typed wire replies for each selector and prove that seed
URIs are absent. They reject changed owner/record/revision/recipient/metadata,
malformed payloads, forged verification fields, unwanted reply fields and
seed-shaped responses. Socket tests cancel before any header and after a partial
frame; bounded writer tests cover worst-case escaping and overflow. RFC 6238
vectors and a child with zero allowed memlock cover TOTP interoperability and
fail-closed protected-allocation failure.

A disposable root integration test covers staging/metadata separation, wrong
owner/recipient, changed-during-verification refusal, active-update preservation,
fresh-process reopen, interrupted cleanup, stale/missing revisions, login/passkey
namespace collision, metadata-purpose confusion and missing-root refusal. Its
synthetic decrypt is explicitly a test stand-in, not hardware authorization.

Real biometric login verification/reveal, cancellation/session-lock/expiry,
CLI migration/routing, sync update/delete handling and fresh-process/reboot
acceptance remain required. No password/TOTP browser autofill or Apple write is
claimed from this service implementation.

Installed validation on 2026-11-06: 208 workspace tests passed with 22 intentionally
ignored tests; 18 privileged library tests passed separately. Formatting, strict
Clippy and release build passed. Updated service binaries were installed with a
retained backup. The installed broker/native-host availability check passed with
`--availability-only`; ListLogins returned an empty inventory and a synthetic
passkey ID was refused by RevealLogin before capture. No real login envelope,
biometric operation, account bootstrap or Apple write was used for these checks.
