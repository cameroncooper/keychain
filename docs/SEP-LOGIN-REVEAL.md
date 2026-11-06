# Selected login protection and reveal

The broker implements login envelope staging, biometric verification and selected
reveal. `keychain protect ID` now dispatches selected login or passkey migration;
`show`/`show --json`, `totp` and `list` route protected logins through broker
metadata/reveal. Sync stages changed login payloads without capture and publishes
a route to the exact encrypted successor. The next explicit reveal verifies,
commits and displays it within one selected biometric-decrypt lifetime. No real login has been imported or revealed through this path.

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

The private payload is versioned `KCLOGIN` magic, a random 32-byte content-MAC
key, three big-endian u16 byte lengths and UTF-8 password, notes and TOTP URI. Parsing borrows the selected protected
allocation, rejects invalid UTF-8, lengths, trailing bytes, mismatched presence
flags and invalid TOTP configuration. It never creates an owned plist/JSON object
containing these fields. The ECIES context binds application, version, owner,
record, revision, recipient, login purpose/format and SHA-256 of the exact typed
metadata, plus the frozen HMAC-SHA256 content tag. The tag covers a domain
separator, payload magic, lengths and all three private fields. Its random key
stays inside the encrypted payload; publishing a tag does not publish a key/salt
for offline password guessing. Verification recomputes it after biometric decrypt.
The CLI freezes that tag before import, so unchanged public labels cannot conceal
substitution of different private contents. Revision/owner/context checks precede use. Public-key encryption alone
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
update never overwrites the verified active revision. `ReplaceStagedLogin` pins
the existing pending content tag and expected verified predecessor before
atomically replacing an unverified slot. A lost pending version cannot be treated
as an empty new slot. An identical leftover staging copy after active publication
can be replaced by a successor only when it exactly matches the committed file.

`VerifyLogin` pins the exact revision/content tag before opening the desktop
prompt, performs a new selected biometric decrypt,
validates the context/content and commits only if the entire staged record still
matches. The verified active envelope is atomically published and fsynced before
the pending file is removed/fsynced. Reopening after interruption retains the same
revision/content; a leftover identical pending copy can be verified again and
cleaned up. Missing committed predecessors, stale revisions and changed staged
records refuse replacement. Explicit discard checks the staged revision and
cannot remove the active record. A missing recipient or metadata root never
triggers regeneration while encrypted login records exist.

The CLI holds StateLock and freezes the source account/owner/socket, full recovery
credential and prepared ciphertext/content tag in an authenticated encrypted
`state/protection/login-ID.enc` journal before import. Lost replies are resumed by
state discovery, never an automatic resend or key regeneration. Metadata,
recipient, revision and content tag must match the frozen source before verification
and after the broker commits. Changed source data refuses resume.

After verification, the journal records BrokerVerified. The CLI then durably
publishes non-secret routing (ID/account/recipient/revision/content tag) before
clearing password/notes/URI from the primary cache and setting its protected
marker. Config, cache and metadata index publication failures retain the encrypted
source and can resume with the same ciphertext. Missing committed data refuses
replacement. Config loss is detected by the authenticated cache/index marker;
only explicit migration resume can restore routing from the source journal. No
recovery-copy retirement is justified by these tests.

## Intentional reveal

`RevealLogin` requires an exact record ID, selected revision/content tag and one
explicit selector: password, notes, TOTP code, or all three for intentional `show`-style disclosure. It accepts
no caller-provided title/domain, decrypt blob, seed-export selector, signing input
or authorization flag. A verified, enabled active predecessor is required.
A changed revision/content tag refuses before capture. Initial unverified imports
remain excluded. An explicitly selected pending successor requires a verified,
enabled predecessor. Its entire pending record and predecessor are frozen through
capture. After context/content verification, both are compared under the registry
mutation lock; the successor commits before output is serialized. Current cancel,
session and deadline checks surround commit and delivery. A late cancellation can
leave a verified durable successor, but supplies no output or reusable UV grant.
The next request still decrypts with a new biometric operation. The native desktop
prompt names the selected stored account/domain and requested output, automatically starts capture, and supplies no success grant.
The real SEP decrypt completion establishes fresh presence for that operation.
After delivery/validation the desktop status changes to finishing, so it does not
keep asking for a finger during persistence and reply delivery.

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

## Metadata-only CLI selection and synchronization

StateStore writes a separately purpose-encrypted `vault-index.enc` containing
login metadata, protected markers and passkey metadata only. It binds the exact
encrypted vault snapshot by SHA-256. The vault is atomically published before the
index; interrupted publication is detected by the hash and refuses lookup until
explicit protection/sync repairs it. A lone index also prevents file-root
regeneration. Existing software-only profiles without an index can build metadata
from their legacy vault; committed protected login routes cannot use that fallback.

Protected show/totp lookup resolves IDs across the shared metadata index and
broker inventory, preserves prefix ambiguity, and never opens the source journal
or vault. Missing protected matches cannot resolve to a different software prefix.
The broker rechecks the selected revision/tag before capture; the typed client
checks reply identity/revision/fields. `show --json` preserves the existing schema
with borrowed secret fields, avoiding an extra owned secret JSON tree. Config
stores no usernames/titles or private fields. The primary cache/index markers
prevent lost config from enabling software reveal or sync downgrade.

Complete sync checks the current account, frozen recovery lineage and exact
known broker versions before redacting a managed login in the new
primary snapshot. Its ID joins passkey IDs in one managed inventory update;
account deletion/logout disables synced entries without deleting native local
passkeys or their recovery representations. Different account/recipient/revision,
missing state and unknown updates fail closed. Changed content/metadata freezes
a new encrypted version in the recovery journal before any root publication. The
root service compares the exact pending tag when replacing an unverified update.
After root acknowledgement, config routing is published before cache/index
replacement, so even an interrupted sync cannot select the older password or
restore plaintext into the protected primary entry.

The journal retains up to 64 preceding source/ciphertext versions (4 MiB total),
including superseded unverified plans; it never silently prunes recovery data.
The limit refuses a new plan before modifying the root service. Unknown root
versions, acknowledged stage loss, known rollback and a changed recipient refuse
recreation. A lost local-publication reply is discovered by exact root state; no
send is repeated within the failed invocation. A later explicit sync can publish
the same frozen ciphertext against its unchanged verified predecessor if it was
never acknowledged. This local metadata publication is separate from any SEP or
Apple command and never repeats biometric capture.

If another explicit reveal commits a pending value while sync prepares a newer
replacement, only an unpublished Prepared plan can be rebased against that known,
verified predecessor. Both ciphertexts remain in recovery history. Published
versions are not regenerated. `show`/`totp` lookup resolves the exact configured
pending metadata without opening the secret-bearing journal; the root service
checks and commits that selection during the new biometric decrypt. `protect`
can also explicitly verify/resume the frozen latest version.

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

The synthetic hardware runs below now cover biometric verification/reveal/update,
desktop cancellation and fresh-client persistence. Real-credential CLI migration,
session-lock/expiry/disconnect, restarted-broker and reboot acceptance remain required. No password/TOTP browser autofill or Apple write is
claimed from this service implementation.

Installed validation on 2026-11-06: 223 workspace tests passed with 23 intentionally
ignored tests; 19 privileged library tests passed separately. Formatting, strict
Clippy and release build passed. Updated service binaries were installed with a
retained backup. The installed broker/native-host availability check passed with
`--availability-only`; ListLogins returned an empty inventory and a synthetic
passkey ID was refused by RevealLogin before capture. No real login envelope,
biometric operation, account bootstrap or Apple write was used for these checks.

CLI fault tests additionally cover lost stage/verification replies, destination
content substitution with unchanged public metadata, changed source data,
config/index publication failures, lost-config marker refusal and explicit
routing repair. The original encrypted recovery source and prepared content tag
remain unchanged across retries. Index tests prove metadata contains no password,
notes or seed, detects stale two-file publication and can select metadata without
decrypting the vault. Shared-inventory tests preserve native passkeys while
including or disabling synchronized login IDs. No real login migration/reveal
was performed for this milestone.

Update tests cover repeated cloud changes, exact pending replacement, lost import
replies, routing-publication faults, unchanged/deleted snapshots, history limits,
wrong account, known rollback, acknowledged loss and a reveal/replace race. A root
integration test freezes both pending/predecessor records, independently validates
synthetic plaintext, refuses changed/missing/disabled state, suppresses output on
cancellation before and after commit, and handles interrupted cleanup. These
simulate biometric completion; they do not establish hardware acceptance or
one-fingerprint behavior on the real reader.

The updated release services were installed with the write gate still disabled.
Installed broker/native-host availability passed without capture; both pinned
VerifyLogin and RevealLogin refused a synthetic passkey ID before opening an
authorization prompt. ListLogins still contained no real login records. The real
reader, browser, fresh-process and reboot acceptance gates remain unproven.

## Opt-in synthetic hardware check

The diagnostic binary now provides a repeatable check with published synthetic
password/notes and the RFC 6238 SHA-1 seed. Run it only when ready to interact with
the desktop prompt:

```sh
./target/release/keychain-sep broker-login-check \
  --socket /absolute/path/to/broker.sock \
  --state /absolute/path/to/synthetic-login-check.json
```

Run as the paired desktop user. This adds one synthetic login to the selected
broker; use a disposable broker registry/socket to keep it outside normal
inventory. It does not replace the synced inventory, read a real credential,
contact Apple or change any creation flag. An existing item recipient and
`--allow-item-decrypt` deployment are required. The state file is created privately
before import and contains frozen metadata/ciphertext/selections, with no real
password, seed or account tokens. It must be retained with the selected registry.

The first successful run uses three separately labeled biometric operations:
initial verification, initial all-fields reveal, then a pending update committed
and revealed within one decrypt lifetime. Only touch when the desktop prompt asks.
The check verifies password/notes, locally generates the expected TOTP for
the returned expiry window (allowing a period boundary during capture), and checks
durable active revision/pending cleanup after the update. It logs no revealed
fields or code. It does not count fingerprints or claim success from a UI event.
Observe that update/reveal requires only one successful biometric operation.

A later invocation with the same state/socket checks revision 2 in a fresh client
process, using another new biometric operation. Repeat after reboot to validate
that persistence chain. Lost replies resume by reading exact root state; changed
metadata/recipient/revision/content or a missing previously prepared record
refuses recreation. Cancellation/errors stop the invocation, with no automatic
capture retry. A leftover initial pending file after a failed cleanup can require
explicit production verification before this diagnostic continues; it is never
silently replaced. No recovery data or committed records are automatically deleted.

Offline diagnostic tests cover TOTP-window rollover, stale/wrong codes, wrong
password version and missing/changed output fields. The hardware runs below
establish selected synthetic verification/reveal/update and fresh-client behavior.
CLI migration/source-journal publication, session-lock and reboot persistence
still need their own acceptance checks.

Isolated fixture prepared on 2026-11-06 (subsequently exercised below):

- Unit: `keychain-login-check.service` (transient, one-hour idle exit).
- Root registry: `/var/lib/keychain-login-check-20261106`.
- Owner-only socket: `/run/keychain-login-check-20261106/broker.sock`.
- Expected recipient: `77ab7ff4-2da7-4151-b4e0-c1fa4a6cee5d`.
- Private client directory: `.sep-check-login-20261106` (ignored by Git).

The new recipient was created through the existing native CREATE API, without a
biometric request. The installed broker returned an active local session and
available SEP. Its transient sandbox retains the installed service's hidden home,
read-only owner-runtime bind, AF_UNIX restriction, device allow-list, no core dumps
and 1-MiB memlock limit. It enables item decrypt only; there is no account
enrollment, network worker or iCloud-write flag. The main registry was untouched.

Only when ready for the three initial prompts:

```sh
./target/release/keychain-sep broker-login-check \
  --socket /run/keychain-login-check-20261106/broker.sock \
  --state "$PWD/.sep-check-login-20261106/check.json"
```

Check the unit and socket first; preparation is not evidence they remain live.
If idle exit/reboot removes the transient unit/socket, restore the broker against
the retained registry and owner before using the same client state. Do not create
a replacement recipient or discard state to make a persistence check pass.


## Live synthetic login acceptance — 2026-11-06

With explicit user readiness, the retained isolated recipient
`77ab7ff4-2da7-4151-b4e0-c1fa4a6cee5d` and record
`2ae732a0-e4ba-4840-89c8-f32965e27b8f` passed through the installed root broker and
D-Bus desktop agent against the real SEP. The idle transient broker was restored
against its existing registry before the run; no new recipient was created.
The client state is `.sep-check-login-20261106/check.json`, mode 0600.

1. Initial biometric decrypt/content verification committed revision 1.
2. A new biometric operation revealed the published synthetic password/notes and
   a current TOTP. The client compared the values without logging them.
3. A staged revision 2 was verified, committed and revealed inside one biometric
   decrypt lifetime. The client re-read root state and confirmed active revision 2
   with no pending record. The user confirmed that the desktop prompts behaved as
   expected, including one fingerprint operation for this update-and-reveal.
4. With separate readiness, another invocation from a fresh client process
   revealed the same committed revision 2 and correctly checked all fields/TOTP.
5. With explicit instructions/readiness to press Cancel/Escape without touching,
   `--cancel-check` received the typed Canceled result, no successful field
   response, and verified that the active revision remained 2 with no pending
   mutation. A subsequent no-prompt broker status returned `sepDevice: available`.
6. With renewed readiness, another fresh client process successfully revealed
   revision 2 after that cancellation. The broker remained PID 427569 throughout
   these runs; no broker restart, new recipient or state reset intervened. This
   checks fresh authorization/device cleanup after cancellation in the same
   broker process, rather than masking a stuck state by restarting it.

Cancellation mode requires existing client state and unchanged committed revision
2; it never initializes, verifies or updates another item. Unexpected success,
timeout or another error fails the check and logs no field values. A synthetic
unit test checks those distinct outcomes. To deliberately test desktop cancellation:

```sh
./target/release/keychain-sep broker-login-check   --socket /run/keychain-login-check-20261106/broker.sock   --state "$PWD/.sep-check-login-20261106/check.json" --cancel-check
```

Do not touch the reader for that mode, even though the normal production reveal
prompt offers fingerprint guidance. These runs did not read a real login, perform
Apple requests, alter enrollment/keybags, retire a source copy or test a reboot.
A fresh client process is not evidence of a restarted broker or full reboot.
Real CLI migration, session lock/expiry/disconnect, durable recovery-copy
retirement, browser/account integration and reboot gates remain open.
