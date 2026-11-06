# Protected synced passkeys

The broker can now import an encrypted synced P-256 scalar and use it after a
fresh biometric item-decrypt operation. The original credential ID, public key,
RP, user handle and synced provenance are preserved. This uses SEP decryption
followed by software signing inside the privileged broker. Device-bound native
signing remains a separate path.

## Setup and protocol

Root setup explicitly creates an item recipient with
`keychain-broker --registry DIR --owner UID prepare-item-key`. Serve must opt into
`--allow-item-decrypt` with the compatible local decrypt driver installed. The
signing capability bit alone is insufficient; unsupported decrypt ioctls fail
without a fallback. Losing a recipient while protected records exist refuses
replacement. The recipient blob and metadata are encrypted by the root-owned
registry's software metadata root, independently of the user vault root.

`ItemRecipient` returns only the recipient ID and public P-256 point. A client
uses `ProtectedImport::seal_scalar` to encrypt the selected source scalar before
IPC. `ImportProtected` accepts ciphertext, metadata and an expected revision.
The broker derives ownership from its authenticated peer, normalizes/validates
metadata and substitutes its own signing reference. It never accepts plaintext
key material, a caller-supplied UV result, an arbitrary decrypt request or a
generic production signing message.

The encrypted context binds application/version, owner, record, recipient,
revision, RP, hashes of credential ID/user handle/public point, purpose and
algorithm. The selected root-controlled record supplies the expected context.
Public-key encryption alone does not authenticate a sender; owner/session checks,
authenticated root storage, revision checks and update locks provide that policy.

## Staging and verification

1. Import writes and fsyncs the complete authenticated record to a temporary
   file, then atomically publishes `protected-ID.pending.enc`. A process lock
   serializes registry mutations. Only one pending revision per credential is
   allowed. An existing active revision stays untouched.
2. `VerifyProtected` freezes the staged record and presents the desktop prompt.
   SEP decrypts only that record into checked locked, dump-excluded memory. The
   helper validates the envelope and scalar/public consistency, signs a fresh
   domain-separated verification message and independently verifies the result.
3. Under the update lock, commit compares the entire record with the one that
   was actually verified. It atomically writes/fsyncs the verified active record
   before removing/fsyncing the pending file. A crash during cleanup leaves an
   active verified successor and a recoverable pending copy. Re-verification is
   safe and does not change credential identity.
4. `DiscardStaged` requires the matching owner and staged revision and removes
   only the pending representation. It cannot remove the active credential.

Unverified and diagnostic records are excluded from browser candidate lookup.
Updates cannot change credential identity or public point. A different key is a
different credential, not an update to a registered identity. Atomic commit and
restart tests cover staging and the post-commit/pre-cleanup state; comprehensive
I/O failure injection and real-vault migration remain pending.

## Signing and browser routing

`Inspect` reads authenticated broker metadata only; it never opens the user
vault. Both inspection and assertion enforce origin, RP and allow-list policy.
`Assert` chooses native or protected software signing from the stored reference.
Protected signing returns an assertion with UP/UV and the existing synced BE/BS
flags. Each request decrypts anew, with no reusable biometric grant or plaintext
cache. Caller disconnect, desktop cancellation, session lock and expiry discard
results. Command errors with uncertain completion are never retried.

The broker executable becomes nondumpable before serving requests. Plaintext
arrives only in a dedicated mlocked/DONTDUMP/DONTFORK mapping, wiped on every
exit. RustCrypto SecretKey/SigningKey objects zeroize their owned scalar on drop.
This does not prove complete erasure or locking of compiler/library temporary
copies. The decrypted scalar and software-signing key remain inside the helper;
only the completed assertion crosses browser IPC. Protection verification returns
only revision/status, not its diagnostic signature.

An optional absolute `credential_broker` socket in config selects broker-only
browser mode. A broker error cannot fall back to the software vault. In this mode,
one eligible account starts the desktop prompt directly. Multiple accounts use
the browser picker first. Browser abort disconnects the native port; stdin EOF in
the native host shuts down its broker connection, canceling the root operation.
Existing software-only mode retains explicit presence approval and refuses UV.

## Current limits

Synthetic biometric decrypt-and-sign has passed on hardware. Real browser use of
an existing credential, installed services, source-key retirement and
password/TOTP reveal still need completion. Selected migration and sync
reconciliation are implemented with recovery tests; see
[migration](SEP-MIGRATION.md). The config
switch is opt-in and has not been applied to the user's real profile. No source
scalar, user root, account session or Apple record has been replaced or deleted.
Same-key warm reboot remains an acceptance gate before retiring old copies.
