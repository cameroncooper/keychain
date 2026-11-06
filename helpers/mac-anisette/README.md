# Local Mac anisette helper

`keychain-anisette-mac` runs Apple's macOS CoreADI image under local CPU emulation
on Linux, including Asahi/aarch64 with 16 KiB pages. Its Rust emulator/provisioner
dependency is [os-findmy-e](https://github.com/sacca97/os-findmy-e), pinned at
`d4d2a832baf47d1cf43d989879950ac2aec45f47`.

This is a separate **GPL-2.0-only** executable, with its own Cargo workspace and
[LICENSE](LICENSE). The MIT application does not link the emulator; the helper is
excluded from the main workspace. Apple's library is not included or redistributed.

## Build

Use current Rust, a C compiler, CMake and libclang. Python is not a runtime
dependency. The optional upstream acquisition script uses Python and 7-Zip only
to download and unpack the Apple image.

```sh
cargo build --release --locked --manifest-path helpers/mac-anisette/Cargo.toml
install -d "$HOME/.local/libexec"
install -m 755 helpers/mac-anisette/target/release/keychain-anisette-mac \
  "$HOME/.local/libexec/keychain-anisette-mac"
```

Obtain your own CoreADI image from Apple's iTunes 12.8.3 distribution. The pinned
upstream `tools/fetch_mac_coreadi.py` downloads directly from Apple, verifies the
DMG SHA-256, extracts CoreADI and produces the x86_64 slice. It requires `7z`:

```sh
git clone https://github.com/sacca97/os-findmy-e.git /tmp/keychain-macadi-source
git -C /tmp/keychain-macadi-source checkout d4d2a832baf47d1cf43d989879950ac2aec45f47
cd /tmp/keychain-macadi-source
python3 tools/fetch_mac_coreadi.py --dest ext/itunes/mac
```

The slice is at
`ext/itunes/mac/coreadi-pkg/rootfs/System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/CoreADI.x86_64`.
Its SHA-256 is `2eafc3c79c7f41a8afbfbeaaf23ee5dab5ad5bda55ec8e54dbc0ddf1d20ce630`;
the engine verifies that build before loading it. Copy it to
`~/.local/state/keychain/anisette/lib/CoreADI` (adjust for `XDG_STATE_HOME`), then:

```sh
keychain anisette setup --helper "$HOME/.local/libexec/keychain-anisette-mac"
```

## State and process boundary

The adapter accepts the managed-helper flags `--host`, `--port`, `--adi-path`,
`--skip-server-startup`, and optional `--coreadi`. Only explicit setup can provision;
normal startup refuses missing or interrupted state. Setup checkpoints the new
identity before network work and retains it on failure. Private atomic/fsynced
state is at `anisette/macos/machine.json`, separate from the retained Android
`adi.pb` and `device.json`. The profiles are not interchangeable; old account
tokens may need fresh authentication.

The application launches the helper on demand, then kills/waits for it when the
network command finishes. Linux parent-death signaling handles an abruptly lost
parent too. It binds only to IPv4 loopback and uses no public anisette service or
Mac service. Provisioning and explicit resync contact Apple with verified TLS.
No Apple password, 2FA code, PET, escrow passcode, Octagon key or vault root enters
the helper. Its ADI state uses private checked files, an exclusive profile lock
and a nondumpable process. Normal operation prints no header values.

GET `/` returns the allowed header set. POST `/v1/resync` handles a bounded SIM
after Apple's explicit pre-password resync request, persists the resulting store
and confirms completion. HTTP framing is bounded; duplicate lengths and chunked
bodies are refused. The application's loopback client uses no proxies/redirects.
Each launch also requires a private random nonce passed through the child
environment and authenticated on every local HTTP request, never command-line
arguments or logs. Missing, mismatched or duplicate authorization is refused
before calling the emulator; ordinary webpages cannot read headers or trigger resync.
The emulator clock remains real, so OTPs do not become stale constants.

## Verification and limits

```sh
cargo test --locked --manifest-path helpers/mac-anisette/Cargo.toml
cargo clippy --locked --manifest-path helpers/mac-anisette/Cargo.toml --all-targets -- -D warnings
# Offline freshness check; holds the selected profile lock for 31 seconds:
keychain-anisette-mac --adi-path "$HOME/.local/state/keychain/anisette" --check-clock
```

Offline tests cover private persistence, symlink/permission/corruption rejection,
and HTTP framing. On the development M1, the hash-verified image loaded, one
isolated identity provisioned, and a synthetic-account probe returned the expected
`ec=-20970` / `hsc=200`. Through this adapter, `keychain` then passed SRP init for
the configured real account, first in isolation and again with the installed
helper. Those checks sent no password proof or escrow attempt. Full login,
2FA/PET and trust repair remain user-operated acceptance gates.
The installed helper also passed the 31-second OTP freshness check, with no header
values printed and no network request sent.
