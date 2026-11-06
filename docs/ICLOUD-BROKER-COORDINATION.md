# Syncable creation: broker operation and network boundary

The broker now has a trusted in-process creation coordinator. It is not exposed
through browser/owner IPC, and the browser still offers device-only creation.
No Apple write or biometric capture was performed to validate this addition.

`Broker::create_synced_registration` checks the configured owner, exact frozen
request and explicit decrypt deployment, serializes the operation and validates
the active local session. It fetches the initial hierarchy before presenting
the desktop prompt or holding a scalar. Exclusion disclosure shares the native
registration path's verified-presence policy. The registry durably stages the
key before a selected biometric decrypt begins.

The existing protected-signing path and creation now share one selected-scalar
lifetime. The driver result and exact item binding are checked before creating
a private borrowed `SelectedScalar`. That value has no plaintext accessor,
serialization or reusable grant. It can prepare encrypted CKKS data and sign
only the selected record. The primary decrypted scalar and assembled X9.63
input use checked locked, dump-excluded, non-inherited memory. They are wiped
when the operation returns, including errors. Existing plist/encryption buffers
zeroize on drop; not every encoder allocation or library temporary is yet
individually locked. That audit remains required before production activation.

Within that lifetime, the coordinator:

1. Reopens an existing upload journal under its transaction lock before calling
   any encryption factory. Corruption or missing roots cannot trigger replacement.
2. Checks the journal against the selected key, complete credential and frozen
   account/peer/request binding. A new journal gets ciphertext prepared from the
   initial authenticated snapshot; the scalar never enters the IO interface.
3. Reconciles/fetches and, where appropriate, sends the prepared upload. A normal
   resume does not resend an uncertain attempt or re-encrypt a rejected one.
   Explicit recovery choices enable confirmed-absence retry or rejected-upload
   re-encryption with the same key and retained ciphertext history.
4. Obtains a typed VerifiedUpload from independent fetch/decrypt verification,
   signs the exact WebAuthn registration using the still-selected scalar, and
   commits through the registry's durable activation sequence. No second decrypt
   or persisted UV result is used to bridge upload and signing.

The desktop status changes to saving after the driver completes, so the prompt
does not keep asking for a finger during upload. Session/cancel/deadline guards
surround preparation, worker calls, signing, commit and delivery. A result received
after cancellation is discarded even if the server saved the record. A new
authorized operation can reconcile that attempt without another send.

Five disposable root integration tests passed with a synthetic recipient and
server: complete creation/fresh-process delivery retry, lost upload reply,
cancellation before and after acknowledgement, explicit recovery policies and
changed selected key/expired-operation refusal. These tests simulate biometric
completion; they do not prove one-fingerprint behavior on hardware or browser
acceptance. The journal factory/resume behavior has an additional offline test.

The production network boundary remains unfinished. The `UploadIo` supplied to
this coordinator is a trusted internal dependency, not an untrusted client RPC.
Directly using AppleUploadIo inside the privileged process would violate the
agreed separation. The installed broker retains AF_UNIX-only restrictions.
Owner-supplied snapshots or success booleans cannot replace trusted transport
results. A production bridge must authenticate the worker independently of
ordinary owner/browser clients, freeze its account/peer/request scope, bound all
messages and forward only ciphertext/public metadata out of the broker.
Start and authenticate that worker before capture; the broker must not fork or
exec with the selected scalar live.

The current guards cannot interrupt an arbitrary blocking trait implementation.
The bridge must poll cancellation and the monotonic deadline while awaiting IO,
close the worker channel on cancel/expiry, and return promptly so the scalar is
wiped. A late Apple response remains an uncertain journaled attempt, with no
automatic replay. Worker responses need request/step correlation and strict
framing; no deserialize shortcut may construct VerifiedUpload from client JSON.
This transport, memory audit, scoped live Apple tests, real biometric creation
and browser/other-device validation remain gates before enabling iCloud creation.
