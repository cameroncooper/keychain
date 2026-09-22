# Keychain: design and architecture

Status: Rust MVP implemented; live login, join, ADP sync, and Chromium WebAuthn validated
Target: Asahi Linux on Apple silicon
Implementation language: Rust
Primary interface: `keychain` CLI

## Decision summary

`keychain` will be a small, read-oriented Linux client for Apple Passwords. It will authenticate
as a stable Apple device, join Octagon trust through an explicitly confirmed escrow recovery,
download CKKS records, decrypt password and passkey items locally, and keep an encrypted offline
snapshot.

The implementation is a single Rust package with a library, one CLI binary, and a one-shot Chromium
native-messaging host. It does not require an always-running `keychain` daemon. Anisette is an
authentication dependency behind a provider interface and is supplied by a managed, on-demand
native helper. A persistent Docker container is therefore not an architectural requirement.

Secure Enclave support is behind the `SecurityBackend` interface. The implemented MVP uses the
explicitly chosen software-file backend: a random mode-`0600` root key protects tokens, Octagon
private material, and the local vault. A future SEP backend can provide device-bound root-key
protection without changing protocol code. Direct SEP-native Octagon keys remain optional and
should only be enabled after the driver supports every operation they require.

The earlier Python implementation and sanitized protocol evidence served as specifications for the
port. Python is not a runtime dependency of the new utility.

## Goals

- Provide `setup`, `login`, `join`, `sync`, `list`, `show`, `totp`, `passkey`, `status`, and
  `logout` operations.
- Read Apple Passwords, TOTP metadata, and passkeys into an encrypted local snapshot.
- Keep credentials, tokens, and private keys encrypted at rest.
- Use the Apple SEP when available without coupling protocol code to a particular driver API.
- Work without a continuously running application container or network listener.
- Make dangerous escrow recovery impossible to invoke accidentally.
- Preserve byte-for-byte protocol behavior with tests ported from the Python implementation.
- Keep the core usable without a desktop environment or browser extension.

## Non-goals for the first release

- Creating, editing, or deleting Apple Passwords.
- Creating or updating passkeys, payment cards, or arbitrary keychain subsystem records.
- Becoming a general-purpose replacement for macOS Keychain or Linux Secret Service.
- Perfectly reproducing all internal macOS `securityd` behavior.
- Eliminating anisette before a reliable local provider exists.
- Running unattended background sync. It can be added later with a systemd timer.
- Password and TOTP browser autofill, passkey creation, and browser-independent CTAP transport.

## Trust and mutation boundary

The project should be precise about what it changes.

- `login`, `bottles`, `sync`, `list`, `show`, `totp`, and `status` are read-only with respect to
  password records.
- `setup` and `join` are not read-only once explicitly confirmed: they register a new Octagon peer
  and update the account trust graph.
- Escrow recovery during `setup` or `join` consumes one of a small number of server-enforced
  attempts. A bad passcode can permanently damage recovery access.
- The first version must never upload, modify, or delete a password item.
- Local `logout` removes local tokens and decrypted snapshots. Any future server-side peer removal
  must be a separate, explicitly named command.

## System shape

```text
 Chromium -> MV3 extension -> one-shot browser host --+
                                                       |
 CLI --------------------------------------------------+
                                                       v
+------------------------------------------------------+
|                   shared keychain library             |
|                                                       |
|  workflow/state machine -> Apple protocol clients ----+----> Apple services
|                         -> CKKS decode/decrypt         |      (verified HTTPS)
|                         -> typed vault projection      |
|  browser request validation -> assertion signing      |
|  security backend <---------- software / future SEP   |
+----------------------+----------------+---------------+
                       |                |
              encrypted state     managed anisette helper
              + software root     (only during network commands)
```

There are three independent concerns:

1. Apple protocol interoperability: authentication, CloudKit, Octagon, escrow, and CKKS.
2. Local secret protection: encrypting persistent state and controlling access to it.
3. User interfaces: the CLI and a narrow Chromium native-messaging adapter.

Keeping these separate allows the Rust port to proceed while the SEP driver evolves.

## Implemented source layout

Start with one package. Split crates only when an actual process or reuse boundary requires it.

```text
keychain/
  browser/chromium/          unpacked MV3 WebAuthentication Proxy extension
  Cargo.toml
  Cargo.lock
  DESIGN.md
  src/
    main.rs                 CLI parsing and exit codes
    bin/
      keychain-browser-host.rs  bounded one-request native-messaging process
    lib.rs
    browser.rs              Chromium request validation, selection, and signing boundary
    apple/
      auth.rs               GrandSlam/GSA SRP, tokens, device identity
      anisette.rs           managed on-demand helper and provider boundary
      cloudkit.rs           ckAppInit and CKCode transport
      ckks.rs               zone record retrieval and typed values
      octagon.rs            peer identity, signed info, trust join
      escrow.rs             bottle listing and guarded recovery
      cuttlefish.rs         bounded Cuttlefish protobuf messages
      crypto.rs             P-384 ECIES, AES-SIV, Apple KDF/padding
      nska.rs               bounded NSKeyedArchiver expansion
      octagon_keys.rs       peer key and signed-info construction
      pipeline.rs           TLK, class-key, and item unwrap pipeline
    config.rs               versioned configuration
    credential.rs           password/sidecar classification and TOTP
    passkey.rs              Apple passkey parsing and WebAuthn assertion signing
    model.rs                versioned persistent state
    paths.rs                XDG paths, locking, private atomic files
    proto.rs                bounded protobuf encoding/decoding
    security/
      mod.rs                SecurityBackend trait and opaque key references
      software.rs           encrypted software P-384/P-256 key store and envelopes
    secret.rs               recursive zeroization for decrypted plist values
    store.rs                encrypted account/vault repository
    totp.rs                 RFC 6238 generation
```

Library modules return typed errors and never print. The command layer owns prompting and output.
The SEP driver bindings and any required `unsafe` code must be isolated in `security/sep.rs` or a
small dedicated crate once its ABI stabilizes.

## Command model

```text
keychain setup [--username <id>] [--bottle <label>]
                                 authenticate and perform one explicitly confirmed first-run join
keychain login                   authenticate and persist reusable session state
keychain bottles                 list recoverable devices; never spend an escrow attempt
keychain join [--bottle <label>] choose a recovery device and explicitly join; may spend one attempt
keychain sync                    fetch and atomically replace the local snapshot
keychain list [query] [--json]   list matching logins and passkeys without secrets
keychain show <entry>            explicitly reveal one locally cached credential
keychain totp <entry>            generate a current code locally
keychain passkey assert ...      interactively approve and emit a diagnostic WebAuthn assertion
keychain status                  show local lifecycle and token state
keychain logout                  remove local session and vault
keychain logout --forget-device  full local cryptographic reset, including device and anisette data
```

`login` and `join` remain separate lifecycle operations for reauthentication and repair. The
convenience `setup` command deliberately composes them for first use and carries its short-lived PET
directly from account authentication into escrow; it is never persisted. Successful authentication
must not by itself cause an irreversible escrow attempt. Before either `setup` or `join` sends
`SRP_INIT` or `RECOVER`, it must:

1. Fetch bottles and non-destructive `GETRECORDS` metadata.
2. Show the selected device and bottle identifier.
3. Explain that a failed passcode consumes a limited recovery attempt.
4. Require a default-no interactive confirmation after displaying that exact bottle.
5. Refuse non-interactive operation unless a future, deliberately scary override is designed.

Secret values go to stdout only when explicitly requested. Human status and warnings go to stderr
so scripts can safely consume machine-readable output. A later `--json` mode must redact passwords,
TOTP seeds, tokens, and private material unless a command explicitly requests the secret.

## Lifecycle state machine

```text
Uninitialized
    |
    | login or setup authentication
    v
Authenticated -------- token expiry --------> NeedsLogin
    |
    | create local Octagon identity
    v
IdentityReady
    |
    | explicitly confirmed join or setup recovery
    v
SponsorRecovered
    |
    | joinWithVoucher accepted; sponsor signing key destroyed
    v
JoinedAwaitingTlkVerification
    |
    | self-addressed TLKs fetched and compared
    v
JoinedSponsorRetirementVerified
    |
    | checkpoint saved; sponsor encryption key destroyed
    v
Joined
    |
    | successful sync
    v
Ready ----------------- sync ----------------> Ready
```

Network responses are validated before new state is committed. If a process dies during sync, the
previous vault remains valid. Join is the deliberate exception to “completed facts only”: a
successfully recovered sponsor is committed before the network trust mutation. The explicit trust
state records whether recovery, share verification, or key retirement is pending. On restart the
CLI reconciles live Octagon state and resumes the pending phase without repeating escrow recovery.

## Apple protocol pipeline

The Rust port preserves the current proven sequence:

1. Obtain stable anisette machine headers.
2. Perform GrandSlam SRP authentication and the account-selected trusted-device, SMS, or voice
   second factor.
3. Mint a PET, exchange it through `loginDelegates`, and persist the resulting `mmeAuthToken` and
   service tokens. In the combined `setup` flow only, retain that PET in zeroizing memory for the
   immediately following escrow request; never persist it.
4. Call `get_account_settings`, then `ckAppInit`, to obtain service URLs, `cloudKitToken`, and the
   per-container `cloudKitUserId`.
5. Generate a stable Octagon peer with separate P-384 signing and encryption keys.
6. List viable escrow bottles and correlate them with `GETRECORDS` device metadata.
7. On explicit confirmation, recover the selected bottle and authenticate its recoverable
   TLKShares using the sponsor peer's P-384 signing key.
8. Re-encrypt each recovered TLK to the new peer, sign it with P-384/SHA-256, and attach those
   self-addressed shares to `joinWithVoucher`. If a join response is lost or share visibility is
   delayed, reconcile explicitly through `keychain join` and Cuttlefish `updateTrust`.
9. Fetch the shares back as the new peer and compare their UUID, zone, class, and key bytes. Save a
   crash-safe verification checkpoint, then destroy the recovered sponsor keys and remove their
   references from state. Until verification succeeds, retain the sponsor encryption key so sync
   remains recoverable.
10. Fetch CKKS zones and apply the unwrap chain:

   ```text
   TLKShare --P-384 ECDH + X9.63 KDF + AES-GCM--> TLK
   synckey  --AES-256-SIV-----------------------> class key
   item key --AES-256-SIV-----------------------> item key
   item     --AES-256-SIV + authenticated data--> plist
   ```

11. Classify records using their access group and combine password-manager sidecars (including
    their site arrays). Strictly decode `com.apple.webkit.webauthn` records, verify each 97-byte
    P-256 private representation against its public point, and import it into the security backend.
12. Atomically commit one encrypted typed snapshot containing logins, TOTP configuration, passkey
    metadata, and opaque passkey `KeyRef`s. Raw passkey private scalars exist only during import and
    are never stored in the vault record.

All HTTPS requests verify certificates. The implementation does not emit raw headers, request
bodies, decrypted plists, or cryptographic material to logs.

## Advanced Data Protection

Advanced Data Protection is supported by the architecture and must never be disabled as a
workaround. Passwords and iCloud Keychain are end-to-end encrypted under both standard and
Advanced Data Protection; ADP extends end-to-end encryption to additional iCloud categories but
does not give Passwords a different server-decryption path.

Consequently, Apple Account authentication and 2FA are necessary but not sufficient in either
mode. The Linux identity must still recover or receive the key hierarchy through Octagon trust,
then decrypt CKKS records locally. Authorizing iCloud.com is not an alternative: Apple explicitly
does not release iCloud Keychain service keys to a web session. The implemented login, trust join,
new-record sync, and record-update sync have been validated with ADP enabled. Apple may still apply
stricter trusted-device eligibility policy to other account configurations, but that changes
interoperability testing rather than the cryptographic design.

References: [Apple iCloud data security overview](https://support.apple.com/102651) and
[Advanced Data Protection security](https://support.apple.com/guide/security/sec973254c5f/web).

## Anisette boundary

SEP support does not replace anisette. Anisette supplies Apple authentication machine data;
the SEP protects local keys. They are separate protocol surfaces.

```rust
pub trait AnisetteProvider {
    fn headers(&self) -> Result<BTreeMap<String, String>>;
}
```

The initial provider is `ManagedAnisette`. The user supplies an absolute path to a compatible native
helper. `keychain anisette setup` provisions stable machine data, while each network command binds a
random loopback port, starts the helper, consumes only an allowlist of authentication headers, and
kills and reaps the child on exit. Helper stdout and stderr are discarded because known helper
versions log raw authentication headers at normal log levels.

The helper keeps a stable machine identity in the private state directory. There is no configurable
remote HTTP endpoint and no persistent container. The CLI does not embed or silently download
third-party images or binaries.

## Local secret protection

### Stored data

Use XDG locations according to their meaning:

```text
$XDG_CONFIG_HOME/keychain/config.toml       non-secret settings
$XDG_STATE_HOME/keychain/software.key       software backend root key (raw, mode 0600)
$XDG_STATE_HOME/keychain/keys.enc           encrypted P-384/P-256 private-key database
$XDG_STATE_HOME/keychain/account.enc        auth tokens; never the Apple password
$XDG_STATE_HOME/keychain/octagon.enc        peer identity and sponsor recovery material
$XDG_STATE_HOME/keychain/vault.enc          projected credential snapshot
$XDG_STATE_HOME/keychain/device.enc         stable Apple-facing device identity
$XDG_RUNTIME_DIR/keychain/                   lock and optional daemon socket
```

Directories are mode `0700`; files are created as `0600`. Writes use a same-directory temporary
file, `fsync`, atomic rename, and directory `fsync`. A state lock prevents concurrent mutating
commands.

Each encrypted file has a versioned envelope rather than relying on Rust struct layout:

```text
magic | format_version | purpose | backend_key_id | random_nonce | ciphertext_and_tag
```

The implementation uses XChaCha20-Poly1305 and authenticates the magic, version, purpose, nonce,
and backend identifier as associated data. Purpose-separated keys are derived from the random root
with HKDF-SHA-384. Account-to-Octagon binding is checked separately with an account fingerprint.
Apple account passwords and device passcodes are never local encryption keys.

The initial implementation has one explicit backend, `software-file-v1`, selected in versioned
configuration. It stores the random root directly in `software.key`; it never derives local
encryption from an Apple password or passcode. Reads reject symlinks, non-regular files, group/world
permissions, unknown envelope purposes, and unknown schema versions. A missing root is never
silently regenerated while encrypted state exists.

When the SEP driver is ready, add a new backend identifier and selection path rather than silently
changing the protection of existing state. Migrating a root or peer must be an explicit operation.

Passwords, passcodes, PETs, private keys, and unwrapped TLKs use secrecy-aware containers and are
zeroized when practical. Rust's safety does not prevent swapping, core dumps, tracing, or reads by a
compromised same-user process; documentation must not promise otherwise.

## Secure Enclave integration

Design around capabilities rather than the first driver ABI.

```rust
pub trait SecurityBackend: Send + Sync {
    fn capabilities(&self) -> BackendCapabilities;
    fn seal(&self, purpose: Purpose, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn open(&self, purpose: Purpose, envelope: &[u8]) -> Result<SecretBytes>;
    fn generate_p384(&self, usage: KeyUsage) -> Result<KeyRef>;
    fn import_p384_x963(&self, usage: KeyUsage, private: &[u8]) -> Result<KeyRef>;
    fn import_p256_x963(&self, usage: KeyUsage, private: &[u8]) -> Result<KeyRef>;
    fn public_spki(&self, key: &KeyRef) -> Result<Vec<u8>>;
    fn sign_p384_sha256(&self, key: &KeyRef, message: &[u8]) -> Result<Vec<u8>>;
    fn sign_p384_sha384(&self, key: &KeyRef, message: &[u8]) -> Result<Vec<u8>>;
    fn sign_p256_sha256(&self, key: &KeyRef, message: &[u8]) -> Result<Vec<u8>>;
    fn ecdh_p384(&self, key: &KeyRef, peer_x963: &[u8]) -> Result<SecretBytes>;
}
```

The first SEP milestone is sealed root-key storage. It provides meaningful protection at rest and
works even if Octagon needs software representations of some keys.

Synced passkeys add a separate capability: import an Apple-exported P-256 key and perform
ECDSA/SHA-256 without exporting it again. The software backend implements that boundary now. A SEP
backend can adopt passkey keys independently of Octagon once persistent P-256 import and signing
are reliable; the vault's opaque `KeyRef` does not change.

Direct SEP-native Octagon keys require all of the following before use:

- Persistent, device-bound P-384 key handles.
- Export of the public point/SPKI, but never the private scalar.
- ECDSA with SHA-384 for Octagon metadata, SHA-256 for TLKShares, and the signature encodings Apple
  accepts.
- P-384 ECDH against arbitrary uncompressed peer points for the encryption key.
- Defined behavior across suspend, reboot, driver upgrade, and SEP reset.
- A recovery story when a handle becomes unavailable.

Signing alone is insufficient: the Octagon encryption key must perform ECDH to unwrap TLKShares.
Escrow temporarily recovers an older sponsor's private encryption scalar. If the SEP cannot import
that scalar, it remains software-managed and is stored only inside a SEP-protected envelope until
the recovered TLKs have been re-shared to, fetched by, and verified with the new peer. The sponsor
key is then destroyed. Envelope protection remains required for this recovery window even after
direct SEP-native peer keys are supported.

Do not change an existing Octagon peer from software keys to SEP keys in place. Its peer identifier
is derived from its public keys and signed permanent information. A key-backend migration creates a
new peer and performs a new, explicit trust join.

## Optional `keychaind`

No daemon is required for the CLI MVP. Add `keychaind` only if the SEP device must be owned by a
privileged broker, if a browser integration needs an authorization boundary, or if keeping an
unsealed root out of short-lived clients provides a measurable benefit.

For browser WebAuthn, origin context must come from a trusted browser/authenticator API, never from
a page content script or an origin string invented by the extension. The implemented Chromium
WebAuthentication Proxy path receives a request only after Chromium validates the caller and RP ID;
Chromium then injects `extensions.remoteDesktopClientOverride` with the caller origin and ancestor
relationship. The native host requires that field, rejects cross-origin frames, reconstructs
`clientDataJSON`, checks the allow-list, and returns authenticator data plus a DER ES256 signature.

The extension has no content script. It first launches the native host in inspect mode, stores the
request in extension session storage, and opens a local approval window containing only the RP,
origin, and matching account labels. On approval it consumes that pending UI state and launches a
fresh one-shot host in assert mode; the host revalidates the entire request before signing. Native
messages and all attacker-controlled collections are bounded. The stable extension ID is the only
origin permitted by Chromium's native-host manifest.

The software backend asserts user presence after explicit local approval, but refuses a request
that requires user verification until a real PIN, PAM, Touch ID, or SEP-backed verifier exists. The
approval is not a security boundary against same-user malware while software key material remains
readable by that user. A future SEP backend can require verified authorization inside its signing
operation without changing the browser protocol. A browser-independent CTAP2/`uhid` authenticator
can remain a later adapter over the same assertion core.

If added, it should be systemd socket-activated rather than continuously running:

- Unix domain socket only; never TCP.
- Socket under `$XDG_RUNTIME_DIR/keychain/` for a per-user service, mode `0600`.
- Authenticate clients with kernel peer credentials.
- Length-delimited, versioned protocol with small bounded messages.
- A narrow operation set: capabilities, decrypt named state, encrypt named state, sign, ECDH, lock.
- No operation that exports a SEP private key or local root key.
- Idle timeout and memory zeroization on exit.
- Optional user-presence or desktop-session policy when the SEP driver can enforce one.

Peer credentials stop other users, not malware already running as the same user. The main security
gain is non-exportability and policy enforcement in the SEP, not the mere existence of a daemon.

## Cryptographic and parser requirements

- Use established Rust crypto implementations; do not implement AES, ECDSA, or hash primitives.
- Keep protocol glue such as X9.63 KDF and Apple-specific padding small and covered by vectors.
- Enforce P-384 point validation and scalar/point consistency on imported software keys.
- Treat protobuf and plist inputs as hostile: bound message size, recursion, field lengths, record
  count, decompressed size, and pagination.
- Preserve CKKS field types because authenticated-data encoding differs for strings, bytes,
  integers, doubles, dates, and references.
- Authenticate before parsing decrypted plaintext and reject malformed ISO-7816 padding.
- Refuse unknown local envelope versions or purposes instead of guessing.
- Pin minimum supported TLS behavior through the HTTP client and expose no `--insecure` production
  option.

The locked implementation uses `p384`, `p256`, `sha2`, `hkdf`, `aes-gcm`, `aes-siv`,
`chacha20poly1305`, `zeroize`, `plist`, `ciborium`, `serde`, `reqwest` with rustls, and a small
bounded protobuf codec. Dependencies are implementation choices, not part of the wire-format
contract.

## Testing strategy

The port should be developed against offline evidence before live Apple calls.

1. Preserve applicable sanitized reference vectors as Rust tests.
2. Add differential tests that run the same sanitized inputs through Python and Rust and compare
   encoded messages, signatures where deterministic inputs permit, decoded fields, and projected
   credentials.
3. Keep redacted fixtures for GrandSlam, CloudKit framing, Cuttlefish messages, CKKS records,
   bottles, TLKShares, sidecars, and malformed inputs.
4. Property-test protobuf framing, varints, encrypted envelope round trips, and record
   classification.
5. Fuzz protobuf, plist, native-messaging, and encrypted-envelope parsers with strict size limits.
6. Put live-account tests behind explicit environment flags. Never run escrow recovery in an
   automated test.
7. Run the full suite on aarch64 Linux; crypto-only tests should also run on ordinary Linux CI.

Secrets and live account artifacts must never enter fixtures, snapshots, panic messages, or CI
logs.

## Implementation sequence

### Phase 1: offline foundation — implemented

- Create the Rust package, error types, secret wrappers, XDG paths, locking, and encrypted envelope.
- Port protobuf framing, Apple crypto, Octagon key serialization, bottle crypto, CKKS parsing, item
  classification, TOTP, and their tests.
- Implement `list`, `show`, and `totp` against fixture/imported vaults.

Exit criterion: Rust produces the same offline results as Python for all sanitized fixtures.

### Phase 2: authentication and transport — implemented and live-validated

- Implement the anisette provider interface and managed loopback helper.
- Port device identity, GrandSlam/GSA, `loginDelegates`, account settings, `ckAppInit`, CKCode, and
  CKKS zone reads.
- Implement `login`, `status`, and authenticated-session reuse.

Exit criterion: a live login succeeds with TLS verification and no Python runtime.

### Phase 3: guarded Octagon join and sync — implemented; core join and ADP sync live-validated

- Port bottle listing, escrow SRP, voucher construction, `joinWithVoucher`, authenticated
  recoverable TLKShares, self-addressed TLK sharing and sponsor retirement, and the complete decrypt
  pipeline.
- Implement combined `setup` plus separate `bottles`, `join`, and `sync` workflows with atomic state
  transitions.

Exit criterion: a manually confirmed join and subsequent sync produce the same password set as the
Python implementation without modifying password records.

### Phase 4: passkey read and assertion core — implemented and live-validated

- Decode bounded Apple WebAuthn records and validate their P-256 private/public representation.
- Import passkey keys through a dedicated backend usage and store only opaque references in the
  encrypted typed vault.
- Implement RP/origin-bound ES256 assertions, honest UP/UV flags, safe inventory, and interactive
  diagnostic signing.
- Validate a synced passkey against a live relying party without exposing key material.

Exit criterion: a passkey synced from Apple successfully authenticates to webauthn.io. This is
complete; browser transport is tracked separately in Phase 6.

### Phase 5: SEP backend

- Stabilize a small driver ABI and implement capability discovery.
- Add SEP-sealed root protection first.
- Add optional direct Octagon key handles only if signing, ECDH, persistence, and failure semantics
  all pass tests.
- Decide from measurement whether a socket-activated `keychaind` improves the boundary.

Exit criterion: copied encrypted state is unusable off-device, reboot/suspend do not lose keys, and
driver failure is safe and diagnosable.

### Phase 6: convenience integrations — Chromium passkey adapter live-validated

- Add a systemd user timer for opt-in periodic sync.
- Maintain the bounded, live-validated Chromium WebAuthentication Proxy extension and one-shot
  native host.
- Consider CTAP2/`uhid` only if another browser needs a transport independent of Chromium's API.
- Add password and TOTP autofill behind a separately reviewed browser protocol.
- Add Hide My Email as a separate optional protocol module.

## MVP acceptance criteria

- `keychain login` and authenticated-session reuse are implemented and live-validated without
  Python. Expired account credentials require another interactive login because the Apple password
  is never stored.
- The only required long-lived identity is data, not a continuously running container or process.
- Neither `keychain setup` nor `keychain join` can spend an escrow attempt without an interactive
  warning and confirmation.
- `keychain sync` implements read-only download and decryption of web passwords and TOTP metadata;
  password creation and website updates have been live-validated.
- Synced Apple passkeys remain behind opaque backend references, and an ES256 assertion has been
  accepted by webauthn.io without claiming unavailable local user verification.
- Chromium has authenticated to webauthn.io through the one-shot native host after explicit local
  approval, with no content script or persistent broker.
- No secret is written unencrypted or emitted through normal logs.
- Loss or corruption of a new sync cannot destroy the last valid vault.
- SEP is not required by the current build; protocol code depends only on backend capabilities.
- The software backend is the explicit version-0.1 implementation and is visibly reported by
  `keychain status`.
- Protocol and crypto behavior is covered by ported vectors and parser limits.

## Open questions

These should be answered with small probes before they become architectural commitments:

1. Which P-384 operations and key-import modes will the Linux SEP driver expose?
2. Can SEP policy bind unsealing to the current Linux boot, user authentication, or user presence?
3. Does the driver need a privileged system broker, or can device-node permissions safely grant
   the logged-in user access?
4. Does the chosen anisette helper preserve the same machine identity reliably across upgrades?
5. Which Apple Passwords views are necessary for the minimum useful sync on the target account?
6. When should locally imported passkey keys absent from a later Apple snapshot be garbage
   collected, and what grace period best protects against incomplete sync pages?

The implemented defaults are: one CLI process, managed loopback/on-demand anisette, a software-file
root key until SEP is available, no Apple-password saving, no background daemon, and one encrypted
typed snapshot for passwords, TOTP configuration, and passkey metadata.
