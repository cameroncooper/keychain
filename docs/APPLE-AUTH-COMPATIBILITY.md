# Apple sign-in and anisette compatibility

Investigation date: 2026-11-05. Fresh GrandSlam authentication is a separate
requirement from using previously issued iCloud tokens. Existing account-settings
and CloudKit requests succeeded during the missing-Passwords-key investigation;
fresh sign-in for escrow recovery subsequently failed before password proof.

## Observed behavior

- The old Xcode client profile received HTTP 503 HTML from GSA init. Parsing that
  body as a plist produced `ExpectedEndOfEventStream { found: String }`.
- An authkitd Mac profile received a structured Apple rejection, `ec=-80045`.
- Tested Windows authkitd/iTunes profiles did not restore authentication with this
  local helper: responses included HTTP 403/503 HTML and `ec=-80045`.
- A separate private temporary profile, with fresh identifiers, existing library
  binaries and new provisioning, also failed SRP init. The main `adi.pb` was not
  reset. Changing CPD booleans to strings did not resolve the rejection either.
- The public GSA URL bag returned the same service endpoint used by this client.

These checks sent SRP init only: no password proof, second-factor code, escrow
passcode, trust join or item write. Fresh provisioning occurred only in the
separate test profile. The affected main profile remains in Prepared trust repair
with its previous peer retained. A failed init does not spend an escrow attempt.

The helper checkout is at `2ef18d7`; fetched upstream HEAD `6848957` changes client
branding and build/documentation, not its Android CoreADI implementation. We did
not replace its binary or reset the user's provisioning. Updating that checkout
alone is therefore not established as a remedy. The upstream maintainer discusses
the underlying provider mismatch in
[anisette-v3-server issue 61](https://github.com/Dadoum/anisette-v3-server/issues/61).
The reported header workaround was tested here and was insufficient; do not
present it as a verified fix for this machine.

## Application changes

GSA advertises authkitd rather than obsolete Xcode branding. Each service owns its
client profile: the helper's client-info suggestion cannot overwrite it (including
case variants), while ADI validation material and matching device metadata pass
through. Experimental Windows profiles and CPD type changes were not retained.
This cleanup does **not** establish that the current provider can sign in.

Authentication parse errors now identify the operation, HTTP status, content
class and parser error without printing response bodies or tokens. Decrypted
session-data parse failures are labeled separately, after verified SRP proof.
The HTTP response buffer is zeroized, and GSA moves the Response dictionary rather
than cloning it. Never solve a non-plist error by ignoring malformed content or
skipping server-proof verification.

The developer-only ignored test below performs no password exchange:

```sh
cargo test --lib apple::auth::tests::live_srp_init_without_password_or_escrow -- --ignored --nocapture
```

It reads the configured account/device/helper and respects StateLock. Optionally
set `KEYCHAIN_TEST_ANISETTE_PROFILE` to a separate test directory containing
`state/anisette/` to test another provisioning profile without selecting it for the
real account. It never switches providers, resets main state or retries escrow.
With the original Android helper the live check fails; passing offline tests do
not imply live auth works. The result below supersedes that failure only for SRP init.

## Remaining requirement

Find and validate an anisette implementation Apple accepts, running entirely
locally on Asahi. The user explicitly chose that constraint; a remote Mac or
public service is not an acceptable replacement.
Generating plausible-looking headers, changing platform labels or rewriting the
existing generator in Rust does not by itself establish Apple acceptance. A new
provider must keep its provisioning separate, supply a matching client profile,
and pass init, verified SRP, 2FA/PET, then the account/escrow/CloudKit flows before
being considered fully validated for recovery. Do not silently use a public anisette service.

## Local Mac provider — implemented and selected

The standalone Rust [Mac helper](../helpers/mac-anisette/README.md) now runs macOS
CoreADI under local emulation on this aarch64/16-KiB-page Asahi host. The image was
downloaded directly from Apple's iTunes distribution and both DMG and slice hashes
verified. No Apple library is committed. The pinned GPL emulator builds separately
from the MIT application and receives no password, PET, escrow secret or vault root.

A new isolated identity provisioned, and a synthetic-account probe returned the
expected `ec=-20970` / `hsc=200`. Real-account SRP init then passed through the
adapter in isolation and again with the installed main-profile helper. No password
proof or second-factor code was sent. A later check returned HTML 503; the final
check passed after explicitly requesting `Connection: close` as well as disabling
pooling for GSA/escrow. This is transport evidence, not proof that Apple cannot
return another service refusal. No 503 retry was added to authentication.
The selected binary is
`/home/cameron/.local/libexec/keychain-anisette-mac`; its private state is under
`anisette/macos/`, separate from the retained Android files and old helper.

SRP now reuses one CPD/OTP set for init/complete. GSA and escrow use independent
HTTP/1.1 connections. One resync/re-init is allowed only for Apple's explicit
`hsc=434`, `ec=-22421` and bounded valid SIM; other failures never retry auth or
replace identity. Repair refreshes service tokens and keeps the PET in memory for
immediate recovery, avoiding two password/2FA exchanges after a provider change.

Next, run `keychain join --repair` in the user's terminal. Full sign-in, 2FA/PET,
restored trust and recovered cache are not yet verified. The previous peer keys,
Prepared journal and original ADI state remain.
The installed helper's offline 31-second check confirmed changing OTPs, avoiding
the frozen-clock failure described by the emulator project. It printed no header
values. Full password proof and recovery still require the user.

## Subsequent cached-token read check

The read-only CloudKit metadata probe on 2026-11-05 received HTTP 401 using the
stored `cloudKitToken` with the selected local Mac provider. The test stopped
before metadata validation; it sent no password, escrow attempt, biometric
operation or Apple record write, and saved no account/vault snapshot. Earlier
cached-token success therefore does not establish current access. The response
does not distinguish expiry from provider/session binding. Fresh local
authentication through `keychain join --repair` remains the next live recovery
step; do not reset provisioning or retry escrow to address this HTTP response.


## Reproduced GSA-init 503 and login-profile alignment — 2026-11-06

The user retried the retained Prepared trust repair and received HTTP 503 with a
190-byte HTML body at GSA init. One configured-account, password-free init probe
reproduced that exact failure. No password proof, factor code, escrow operation,
trust write or vault/account snapshot was sent/saved by the diagnostic.

The installed local Mac helper passed another offline 31-second OTP clock check;
the host reports synchronized time, and this command environment has no configured
HTTP proxy variables. No helper update, identity replacement or reprovisioning was
performed. These checks do not prove that Apple accepts every future OTP.

The application still used `akd/1.0 CFNetwork/808.1.4` with a plist-only Accept
header. The pinned provider's actual *login* implementation instead uses
`akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0` and `Accept: */*`:
[login device profile](https://github.com/sacca97/os-findmy-e/blob/d4d2a832baf47d1cf43d989879950ac2aec45f47/native/apple-core/src/login/device.rs),
[login request headers](https://github.com/sacca97/os-findmy-e/blob/d4d2a832baf47d1cf43d989879950ac2aec45f47/native/apple-core/src/login/messages.rs).
Its provisioning client has a separate user agent; that was not copied into the
login path. The application now matches these two login settings while retaining
its service-owned AuthKit client info and the existing HTTP/1.1/no-pooling/close
policy. The helper still cannot overwrite the service profile.

One password-free init probe then passed using the same retained identity. This
is a before/after observation, not proof of causality or a guarantee against
intermittent Apple edge refusals. No automatic 503 retry was added. Full verified
password proof, 2FA/PET, trust repair and recovered Passwords keys remain unproven;
the user must retry `./target/release/keychain join --repair` in their terminal.
Do not reset anisette or spend an escrow attempt to work around a non-plist init
response. The original peer and repair journal remain retained.
