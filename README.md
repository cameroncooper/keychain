# keychain

`keychain` is an experimental, read-only Rust CLI for accessing Apple Passwords from Linux. It
implements native Apple authentication, an explicitly guarded Octagon trust join, CKKS download
and decryption, local search, password display, TOTP generation, and read-only use of synced
passkeys. An optional Chromium extension provides explicitly approved browser assertions. Python
and a persistent container are not runtime dependencies.

This is an unofficial reverse-engineering project and is not affiliated with Apple. The protocol
implementation has comprehensive offline tests; login, Octagon join, and read-only password sync
have been validated against a live account with Advanced Data Protection enabled. Apple passkey
decoding, ES256 assertions, and the Chromium adapter have been live-validated with successful
webauthn.io authentications. Migrating preexisting TLKs during a join has not yet been exercised
against a nonempty account.
`join` mutates the Octagon trust graph and escrow recovery has a server-enforced attempt limit. Read
the warning before using it.

## Build

Rust 1.85 or newer is required.

```sh
cargo build --release
./target/release/keychain --help
```

This builds the CLI and the one-shot `keychain-browser-host` native-messaging binary. The CLI is
self-contained apart from an anisette helper. The current integration expects
a native `anisette-v3-server`-compatible executable with `--host`, `--port`, `--adi-path`, and
`--skip-server-startup` options. The CLI never downloads or installs that executable.
The [local Mac anisette helper](helpers/mac-anisette/README.md) implements that interface
in Rust using local macOS CoreADI emulation on Asahi. It is a separate process;
no Mac or public anisette server is required. It replaces the Android helper on the
development machine; see [authentication compatibility](docs/APPLE-AUTH-COMPATIBILITY.md)
for the validation limits.

## Set up and use

Supply the helper by absolute path. Setup provisions persistent anisette machine data once; every
later network command launches the helper on loopback and terminates it when the command exits.

```sh
keychain anisette setup --helper /absolute/path/to/anisette-v3-server
keychain setup
keychain sync
keychain list
keychain list --json
keychain show ID_OR_UNIQUE_PREFIX
keychain show ID_OR_UNIQUE_PREFIX --json
keychain totp ID_OR_UNIQUE_PREFIX
```

When Apple requires two-factor authentication, `keychain` retrieves the available methods before
sending a code. If both are available, it lets you choose between a prompt on your trusted Apple
devices and a text message or voice call to each masked trusted phone number. At the code prompt,
use `r` to resend, `m` to choose another method, or `q` to cancel. Apple's GrandSlam interface
treats trusted devices as a group and does not provide a reliable per-device picker.

`setup` is the normal first-run command. It authenticates the account, creates the stable
Apple-facing device identity, and continues into the guarded Octagon join while reusing the same
short-lived PET in memory. The Apple ID password and 2FA exchange therefore happen only once.
`setup` still displays the selected recovery record, explains the attempt limit, and requires a
default-no confirmation before asking for its passcode; merely signing in cannot spend an escrow
attempt. Pass `--bottle RECORD_LABEL` to skip the device picker.

`login` and `join` remain available as separate recovery and maintenance commands. `login` only
refreshes Apple authentication. `bottles` only lists viable recovery records. `join` resumes an
interrupted join or starts a guarded recovery for an already authenticated account; when starting a
new recovery on its own, it needs a fresh Apple password and 2FA exchange to obtain escrow
authorization.
If authentication works but this peer has lost access to keychain keys, use
`keychain join --repair` to start an explicit replacement-peer recovery. It retains
the existing profile and old keys, resumes interrupted recovery, and restores a
complete verified snapshot before switching peers. See [trust repair](docs/SYNC-RECOVERY.md).
If a join is interrupted after successful recovery, the recovered sponsor is saved so the next run
can reconcile or resume without automatically spending another escrow attempt.
After joining, the CLI re-encrypts the recovered TLKs to its own Octagon encryption key, signs the
new shares, fetches them back for exact verification, independently decrypts a complete snapshot,
and only then destroys the recovered sponsor
keys. If a join response is lost or Apple has not made the new shares visible yet, the CLI retains
the sponsor encryption key and asks you to rerun `join`; reconciliation uses `updateTrust` without
another escrow attempt.

The current pre-release state layout intentionally has no compatibility migration. A full reset is
always available with `keychain logout --forget-device`, even when an obsolete Octagon state file
cannot be decoded. This also removes the software security root and anisette machine data, so run
`keychain anisette setup` before signing in again.

`show` displays the current TOTP code and remaining validity alongside the password when one is
configured. `show --json` emits the same secret-bearing result as one compact JSON object for
structured consumers. The narrower `totp` command emits only the current code and remains the safer
choice for scripts that do not need the password.

The Apple ID password is read from the terminal only when a fresh Apple authentication is needed.
It is never saved. The device passcode, 2FA code, PET, and decrypted transport keys are also never
persisted. The account state retains only the reusable `mmeAuthToken` and `cloudKitToken` needed by
the Passwords flow, not the generic GSA token set. `show` intentionally writes a requested password
to stdout; `totp` intentionally writes a requested code.

`sync` recognizes Apple WebAuthn records, validates the embedded P-256 private scalar against its
public point, imports the key into the configured security backend, and stores only an opaque key
reference with passkey metadata in the encrypted vault. The general `list` command includes logins
and passkeys with an explicit `kind`; it never prints the raw passkey credential ID or user handle.
Its JSON output includes only a short SHA-256 credential fingerprint. `show` accepts either kind of
ID and reveals only passkey metadata for a passkey.

Sync fails without replacing the vault if any requested zone is incomplete or any downloaded
CKKS item cannot be decrypted. It also keeps an encrypted backup of the last nonempty snapshot.
See [incomplete sync and recovery](docs/SYNC-RECOVERY.md) for the difference between expired
authentication and missing Octagon keys, backup behavior, and diagnostic output.

For protocol testing, `passkey assert` accepts a unique passkey ID prefix, base64url challenge,
and HTTPS origin. It displays the relying party, origin, and account, requires an interactive
default-no approval, and emits a WebAuthn assertion JSON object. It binds the origin to the stored
RP ID and deliberately does not claim user verification. This is a diagnostic/integration surface,
not the normal browser path.

## Chromium passkeys

Chromium 115 or newer can use synced passkeys through the extension in `browser/chromium`. Build
the release binaries and install the native-messaging manifest:

```sh
cargo build --release
./browser/chromium/install-host.sh
```

Then open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select the
absolute `browser/chromium` directory from this checkout. The manifest contains a fixed public key,
so its extension ID is stable: `lcadeibeloholafalbgoehpbhnplmojh`. Verify that this matches the ID
shown by Chromium. The toolbar badge reads `ON` while passkey proxying is enabled; clicking the
extension icon toggles it.

For each `navigator.credentials.get()` request, Chromium supplies its validated caller origin and
RP ID to the extension. A one-shot native host first returns only matching account labels. The
software path opens a local presence-approval window before a second one-shot host revalidates
the request and signs it. In broker mode, one matching account goes directly to the OS fingerprint
prompt; multiple accounts first get an account picker. The extension has no content script,
network permission, password access, or long-running native process.

There are deliberate initial limits:

- Device-only creation is implemented through the SEP broker: choose **This device**, then use the
  OS fingerprint prompt. Native keys stay in the broker registry and appear in `list`/`show`.
  The current creation path still needs real browser acceptance testing. See
  [registration lifecycle and limits](docs/SEP-REGISTRATION.md).
- iCloud-syncable creation and Apple uploads remain unimplemented; the browser never silently
  substitutes device storage for an iCloud save.
- Cross-origin iframe requests and unsupported extensions are refused. Creation supports
  `credProps`; the Chromium caller-origin override is always required.
- The software backend refuses `userVerification: required`. The SEP broker requires a fresh
  verified biometric operation for native or protected-scalar signing.
- Chromium's WebAuthentication Proxy replaces its normal authenticator handling while the badge is
  `ON`. Requests with no matching eligible passkey fail instead of falling back to a hardware key.
  Click the icon to show `OFF` before using Chromium's normal authenticators.

The adapter relies on Chromium's documented
[`webAuthenticationProxy`](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy)
API. The native host also requires Chromium's injected
`extensions.remoteDesktopClientOverride` value, rechecks exact HTTPS origin/RP binding and the
credential allow-list, and caps all messages and credential collections before parsing or signing.

## Local security model

The initial implementation uses the explicitly chosen software backend:

- a random 32-byte root key at `$XDG_STATE_HOME/keychain/software.key`;
- purpose-separated keys derived with HKDF-SHA-384;
- XChaCha20-Poly1305 authenticated encryption for account, device, Octagon, key database, and vault
  state;
- opaque references to P-384 Octagon keys and P-256 passkey keys stored in the encrypted key
  database;
- `0700` directories and `0600` files, atomic replacement, schema checks, bounded reads, and refusal
  to follow state-file symlinks.

The default state location is `~/.local/state/keychain`; non-secret configuration is under
`~/.config/keychain`; runtime locks are under `$XDG_RUNTIME_DIR/keychain` when that variable is set.

This protects files copied from disk, but it is not equivalent to SEP protection: a process running
as the same Linux user can read both the root key and encrypted files. It also does not provide a
local user-presence prompt before `show`. The browser approval window prevents accidental signing,
but under the software backend another process running as the same user can still invoke the native
binary and read the software key. Avoid backups or synchronization of `software.key`, and protect
the Linux account and disk accordingly.

Account/Octagon state uses the `SecurityBackend` interface. Selected passkeys can use the separate
SEP broker for native signing or biometric decrypt/software signing. Protecting the account-state
root is a follow-up; native signing does not depend on it. Direct Octagon SEP keys additionally
need persistent P-384 signing, public-key export, ECDH and imported recovered-key support.

## Current scope

- Included: Apple Passwords login records, password-manager sidecars and TOTP metadata, plus
  synced ES256 passkeys, explicit WebAuthn assertion signing, an opt-in Chromium adapter, and
  development SEP broker/desktop-agent, device-only creation and selected-passkey migration paths.
- Excluded: writes to Apple records, iCloud-syncable passkey creation, password/TOTP browser autofill, payment
  cards, Hide My Email, background sync and other browser transports.
- Network TLS verification is always enabled; there is no insecure switch.

See [DESIGN.md](DESIGN.md) for the architecture, protocol boundary, and SEP integration plan.
The current [SEP completion design](SEP-IMPLEMENTATION.md) covers native signing, biometric item
protection, the desktop authentication prompt, migration, and both iCloud/device-only creation.
The Rust driver/provider, broker, desktop prompt and synthetic migration/native-host path have
[application-side hardware evidence](docs/SEP-APPLICATION-VALIDATION.md). Build the optional agent
with `cargo build --release --features desktop-agent` (requires GTK development files). See
[service deployment](contrib/SEP-SERVICES.md) and [selected migration](docs/SEP-MIGRATION.md).
Installed service activation has passed; real browser validation and source retirement remain pending.

See [SEP-INTEGRATION.md](SEP-INTEGRATION.md) for the proven biometric signing mechanism, backend integration guidance,
and the remaining requirements for SEP-protected keys and passkeys.
