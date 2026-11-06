# Local Apple network worker

The separate `keychain-network-worker` executable serves only root broker peers
under the `keychain-network` service UID. It has networking and no SEP devices,
home-directory access, account private keys, TLKs or vault. The broker keeps its
AF_UNIX-only restriction. The service is started explicitly before biometric
capture and exits after 120 idle seconds. It has no enable target or automatic
restart/replay policy.

The worker's immutable credential package contains only the CloudKit token,
public account/device/peer scope and a seed of the already provisioned local Mac
anisette identity. The export code selects that token rather than serializing
all account tokens; it never loads the vault or exports Octagon private keys.
It refuses unjoined/mismatched peers and never creates an account encryption root.
Export runs as the profile owner and requires a private pipe (terminals and
regular redirected files are refused). It does not fork or
start a helper with loaded credential material. The shell starts the encryption
process separately; no plaintext intermediate file is needed.

systemd host-key encryption is the current software storage baseline for this
service package. It is not SEP-protected root unsealing. On this host systemd
delivers plaintext credentials as a root-owned 0440 file on a read-only mount;
the service checks root ownership, trusted ancestors, modes, bounds and schema.
Token/ADI buffers zeroize on drop, but this is not a claim that every account-token
or library temporary is individually locked. No password, PET or passkey scalar
is included in the package or sent to the anisette helper.

## Install artifacts

Build the main workspace with all features, and build/retain the separate GPL Mac
helper described in [its README](../helpers/mac-anisette/README.md). The installer
accepts explicit local helper/image sources:

```sh
cargo build --release --workspace --all-features
sudo bash contrib/install-sep-services.sh \
  --network-helper /home/cameron/.local/libexec/keychain-anisette-mac \
  --network-coreadi /home/cameron/.local/state/keychain/anisette/lib/CoreADI
sudo systemd-sysusers /usr/lib/sysusers.d/keychain-network.conf
```

The installer copies reviewed executables and verifies the pinned public CoreADI
SHA-256 before installing it. It never copies a private ADI profile, exports a
token, creates/replaces an identity, enables or starts the worker. Apple binaries
remain outside Git. The optional `--destdir` stages artifacts without system
changes, and installed artifacts have rollback backups.

## Explicit account bootstrap

First complete fresh local authentication/trust repair in the normal profile.
The cached-token CloudKit check returned HTTP 401; an offline credential export
does not prove that an expired token works. Run `keychain join --repair` in your
terminal if still needed. Do not send passwords, exported credentials or ADI state
in chat.

With the intended profile selected, create an encrypted candidate package. This
is an administrative operation, separate from browser credential requests:

```sh
set -o pipefail
/usr/libexec/keychain/keychain-network-worker export |
  sudo -n sh -c 'umask 077; exec systemd-creds encrypt --with-key=host \
    --name=network-account - /etc/keychain/network-account.cred.new'
```

Only proceed if BOTH sides succeed. Do not publish an empty/failed export or
overwrite a working credential on a failed refresh. Validate the encrypted
candidate through a disposable service, which starts no helper or Apple request:

```sh
sudo systemd-run --wait --pipe --collect \
  -p User=keychain-network -p Group=keychain-network \
  -p LoadCredentialEncrypted=network-account:/etc/keychain/network-account.cred.new \
  /usr/libexec/keychain/keychain-network-worker check-credentials
```

After validation, publish the candidate as root and explicitly start the service:

```sh
sudo mv -T /etc/keychain/network-account.cred.new /etc/keychain/network-account.cred
sudo systemctl start keychain-network-worker.service
```

For rotation, finish/cancel any active broker operation and stop the worker
before replacing its package. No automatic token refresh or public/remote
anisette fallback occurs. Missing credentials fail startup before helper/network
work. An already running instance keeps its original credential scope until exit.

The first startup seeds a new private service ADI directory by atomic directory
rename. A digest of the stable host/device/local identity identifies that seed across
restarts, excluding the mutable ADI store and allowing the
helper's mutable OTP state to evolve. Re-exporting the same identity with a
new store/token does not replace the service's current store. A different identity or missing/unsafe machine
file is refused; the existing identity is retained. Service startup never runs
anisette setup/provisioning or resets the owner's original profile. Root-owned
helper/image inputs are checked, including the pinned CoreADI hash, before launch.
Primary credential buffers are dropped before helper exec, then re-read from the
immutable credential mount and checked against the frozen scope/device/identity.
Credential-directory environment variables are removed from the helper's launch.
The helper is trusted code running under the same service UID; this is process/
protocol separation, not a separate UID or filesystem sandbox for the emulator.

## Validation and remaining connection

The disposable startup check uses the actual worker executable, systemd credential
delivery, a different UID, a fake loopback helper, and a copy of the public image.
It denies all non-loopback traffic and uses synthetic account/ADI data only:

```sh
sudo python3 contrib/check-network-worker.py \
  --binary target/release/keychain-network-worker \
  --coreadi /home/cameron/.local/state/keychain/anisette/lib/CoreADI
```

It verifies scope rejection before backend construction, kernel worker identity,
handshake and idle socket cleanup. Unit tests cover selective export, malformed
credentials and seed persistence/refusal. These checks have passed; they do not
prove live Apple token acceptance or upload atomicity. Those checks used only
synthetic credentials; later real-candidate staging is recorded below.

The broker's separate [agreement-key enrollment and authenticated root bootstrap](../docs/BROKER-ACCOUNT-BOOTSTRAP.md)
now exist. The broker/worker packages are intentionally separate and neither has
been applied to the production account. The fixed-unit worker-start/connect path and
coordinator/browser wiring are connected behind the default-off
`--allow-synced-creation` broker flag. Owner-supplied snapshots, roots and uploaded
flags are refused. Fresh authentication, account bootstrap, remaining memory
review, scoped live Apple tests and biometric/browser tests are still required
before enabling the iCloud choice. The installer never adds this flag.


## ADI identity interoperability and local candidate validation

The pinned helper also uses macOS UDIDs (`8 hex digits-16 hex digits`) as ADI
provisioning identifiers. These are distinct from the app's CloudKit UUID. A
real-profile local export exposed that the worker incorrectly required a UUID
for both. The worker now accepts nonzero UUIDs or that precise UDID format;
malformed/arbitrary identifiers still fail. Existing UUID seed markers are byte-
identical. UDIDs use a distinct typed digest input, so they cannot alias UUID
identities. Mutable OTP store updates still do not replace a seeded identity.

Eight worker tests passed, including the existing-marker golden value, UDID
credential round trip, strict CloudKit UUID scope, malformed/zero rejection and
refusal to replace a seeded UDID. The separate-UID/systemd startup check now uses
a synthetic UDID with a distinct UUID for CloudKit; credential delivery, kernel
peer identity, wrong-scope refusal, handshake and idle exit passed with a fake
loopback helper and no Apple/SEP IO. The release worker and strict Clippy passed.

Root-only encrypted candidates from the real profile now exist and pass local
format/identity checks. They remain unapplied; see
[BROKER-ACCOUNT-BOOTSTRAP.md](../docs/BROKER-ACCOUNT-BOOTSTRAP.md#local-bootstrap-candidates--2026-11-06).
No ADI identity or account key was regenerated. This is not evidence of token
acceptance, live share recovery, upload atomicity or another-device passkey use.
