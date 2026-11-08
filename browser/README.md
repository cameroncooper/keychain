# Browser adapters

The extension provides passkey creation/authentication and password/current-code
form filling. Chrome and Firefox/LibreWolf share the compact account menus,
toolbar, form controller, Rust native host and broker. Storage selection and
fingerprint authorization remain native GPUI dialogs. Our own code and assets
adapt the interaction patterns documented in [the Apple reference](APPLE-UX-REFERENCE.md).

## Build and load

```sh
cargo build --release --bin keychain-browser-host --bin keychain-broker -j 1
node browser/build.mjs
```

Load the **built package**, not its source directory:

- Chromium: install the host with `./browser/chromium/install-host.sh`, then load
  `browser/dist/chromium` through `chrome://extensions` → Load unpacked. It keeps
  the existing fixed extension ID. If an older unpacked copy points at
  `browser/chromium`, replace that source path with the built package.
- Firefox/LibreWolf: run `./browser/firefox/install-host.sh`, then open
  `about:debugging#/runtime/this-firefox` → Load Temporary Add-on and select
  `browser/dist/firefox/manifest.json`. The add-on ID is
  `keychain@cameroncooper`. Temporary installation lasts until browser restart;
  permanent installation on signature-enforcing builds requires Mozilla signing.
  This project does not disable add-on signature enforcement.

The Firefox installer registers the host for both `~/.mozilla` and `~/.librewolf`,
allowlisting only that add-on ID. `--destdir HOME` stages manifests for inspection;
`--binary FILE` selects a different host executable. Sandboxed/Flatpak browsers
may require additional native-messaging integration and are not validated here.
The native host uses the normal Keychain configuration; broker mode must point
to the migrated broker, which must also contain the Firefox caller parser.

Open the toolbar popup to see connection status, matching accounts, the native-app
handoff and the explicit **Use Keychain in this browser** switch. In Firefox, OFF delegates *new* calls to
the browser's captured original methods; disabling during a request cancels it.
There is no automatic fallback after a native operation fails or is canceled.
Other passkey extensions may intercept the same methods: avoid enabling multiple
passkey providers while evaluating this adapter.

## Password and verification-code filling

Passwords/codes are offered only for verified, enabled **broker-protected logins**.
Username fields also offer matching verified broker passkeys, labeled **Passkey**. A cached software
login does not implicitly become browser-accessible. To protect a selected
existing login, use `keychain protect ID` with the paired SEP broker; this is an
explicit biometric operation that retains the encrypted recovery copy. See
[login protection](../docs/SEP-LOGIN-REVEAL.md).

On a top-level HTTPS page, focus a username/password or one-time-code input and
choose an account. Arrow Down enters the menu; arrows move between accounts,
Enter selects, and Escape closes it. The toolbar also offers accounts for the
page's current form. Selecting a password or code starts native fingerprint
authorization. Username-only forms fill public account metadata without a scan.
Choosing a passkey account fills its public username only; then use the site's
Authenticate/Sign In control to begin its ordinary passkey request. It does not
start a signature or fill a password. Passkey accounts are excluded from password
and verification-code inputs. Username suggestions respect each passkey's RP ID
(the RP host or its subdomains), rather than the broader password domain policy.
This is not conditional WebAuthn mediation: pending conditional requests and
`autocomplete="webauthn"` integration remain unsupported.
No flow submits the form automatically.

Password/code matching uses the registrable domain, so an `apple.com` item is
also offered on `account.apple.com` and `developer.apple.com`. The root broker
uses the embedded [Public Suffix List](https://publicsuffix.org/list/), including
private entries: `alice.github.io` and `bob.github.io` remain separate, as do
`example.co.uk` and `other.co.uk`. The `psl` dependency version and its list
snapshot are pinned in `Cargo.lock`; list updates ship with dependency updates.

HTTPS is required and ports must match (bare names imply the default HTTPS port).
IP addresses, localhost and names with unknown suffixes stay host-exact. This
changes password/code account matching only; the live document origin and native
prompt still identify the actual requesting site. WebAuthn RP rules are unchanged.
No cross-domain organization aliases (such as `apple.com` to `icloud.com`) are
inferred.
Only the requested password or current code is returned. Notes and TOTP seeds
have no browser operation. The native prompt shows the validated HTTPS origin
and account. Passwords intentionally filled into a website can be read by it.

The background freezes the browser-reported top-level origin and one-use item
selection; the broker repeats destination/field/revision checks before device
access. The content controller retains the original inputs, form membership,
action, method, target and page URL. It rechecks them before delivery and after
username input handlers. Hidden/replaced/reassigned inputs and changed forms
receive no password. Navigation, disconnect, disabling and expiry revoke work.
Passwords/codes are not persisted to extension storage; JavaScript/browser form
memory is outside the native locked-memory guarantee.

Shared CSS follows `prefers-color-scheme`. LibreWolf privacy settings can report
a light theme to web pages while extension windows use dark mode; the inline menu
respects that reported setting. Browser privacy/window-size constraints can also
change account-picker window dimensions; the content remains compact.

Save/update prompts, password generation, QR enrollment and browser-autofill
settings integration are not implemented. In particular, the existing passkey
CloudKit create path is not a password update API: password writes need a reviewed
Apple item encoder, change-tag conflict checks, and authenticated fetch/decrypt
verification before the UI can report an iCloud save.

## Shared code and browser trust boundaries

`shared/sender.js` validates browser-reported form/Firefox caller identity;
`shared/forms-background.js` binds account inspection and selected fill to that
connection. `shared/forms.js` owns the guarded field/controller and closed-shadow
menu. The closed shadow root is presentation isolation, not authorization.
`shared/core.js` owns native messaging, one-use selection, cancellation, bounded
request deadlines, availability and response dispatch. `shared/approval.*` owns
only account selection; storage/fingerprint decisions stay native.
`build.mjs` copies these canonical sources into self-contained packages. It does
not fetch dependencies or produce a second maintained implementation.

Chromium's thin worker connects its `webAuthenticationProxy` API to that core.
The browser injects `remoteDesktopClientOverride`; page scripts cannot choose
its authenticated origin. The broker still validates RP, origin, allowlists and
credential policy.

Firefox has no equivalent proxy in this implementation. Its document-start
isolated content script uses Firefox Xray/exportFunction/cloneInto facilities to
wrap public WebAuthn methods and return page-realm credential objects. Extension
APIs never become page objects. The background derives origin from the browser's
`runtime.Port.sender`, requires its own add-on ID, frame 0, HTTPS, non-opaque and
consistent sender metadata, and checks the current tab before dispatch. Page
options cannot supply either caller envelope. The background emits the distinct
`keychainFirefoxCaller` envelope; native host and broker accept exactly one
adapter envelope and repeat RP/origin validation. This is trust in the allowlisted
extension/browser, not cryptographic attestation against a compromised host.

Firefox's initial adapter supports **top-level HTTPS documents** and explicit
create/get calls. Subframes, conditional mediation/autofill and HTTP localhost
are not supported. Firefox-restricted pages cannot be injected. Page code can
modify its own WebAuthn wrappers/results, as with other script-based providers;
it cannot use that to assert another origin or bypass broker authorization.
Signatures still bind the browser-validated origin, RP and challenge.

Page abort, pagehide, top-level navigation, closing the tab/port, disabling the
extension and timeout revoke delivery and disconnect native work. Connections
awaiting validation count against a 64-global/4-per-tab bound. The shared core
also bounds requests (at most two minutes, availability five seconds), persists
account-picker deadlines across worker suspension, and refuses expired selection.
Chromium may omit or expand the site's timeout in proxy JSON; the shared maximum
bound still applies. Firefox also enforces the page's bounded timeout.
No request, assertion, password, private key or account metadata is logged by the
production adapter.

API references:
[Chrome proxy](https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy),
[Firefox sender metadata](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/MessageSender),
[Firefox compartment sharing](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Sharing_objects_with_page_scripts),
[native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging).

## Test harness

```sh
node --test browser/tests/*.test.cjs
cargo test --lib -j 1
```

The same lifecycle/account-picker scenarios run against both browser API shapes,
including native cancellation, immutable requests, single completion, selection,
expiry and no fallback after creation failure. Firefox-specific tests cover
sender spoofing, opaque origins, frames, navigations and pre-dispatch disconnect.
Form-service tests cover metadata-only inspection, exact item selection, forged
callers, stale toolbar handles, cancellation, navigation, username-only filling, passkey username suggestions and
refusal to use a passkey suggestion for password/code reveal.
Codec tests cover BufferSource offsets, response methods and fresh public copies.
Rust tests check both caller envelopes and reject ambiguity/foreign RPs before IPC.

For real browser execution, install matching ChromeDriver and GeckoDriver, then:

```sh
GECKODRIVER=/path/to/geckodriver \
FIREFOX_BINARY=/path/to/librewolf \
node browser/tests/browser-harness.mjs both
```

The selector can also be `chromium` or `firefox`. For a targeted UI rerun after a
full deadline check, `KEYCHAIN_HARNESS_SKIP_DEADLINE=1` skips the slow deadline
scenario and explicitly labels that omission in console/results. `KEYCHAIN_HARNESS_THEME=light|dark` selects the isolated UI test theme. `CHROMEDRIVER` and
`CHROMIUM_BINARY` override Chromium discovery. The harness needs Node, Python 3
(for ZIP packaging), OpenSSL and the selected browser/driver. It creates a private
`/tmp/keychain-browser-harness-*` directory, isolated HOME/profiles, local HTTPS
RP and a **synthetic native provider**, then loads the actual packaged extensions.
It verifies registration/accessors, the real shared account picker, signed assertion
origin/challenge, foreign-RP refusal, abort, timeout and a fresh request after cancellation.
It also verifies password/code/username-first filling, input events without form
submission, changed form destinations, replaced/hidden/reassigned inputs, and
light/dark extension styling. Screenshots and JSON results are retained. Evidence is retained
in that directory; child sessions are closed on completion. Chrome's proxy can
omit or expand timeout, so its negative deadline check may take two minutes.

GeckoDriver uses `--allow-system-access` only for the isolated browser process so
the harness can inspect its own extension pages. It does not modify your browser
preferences or disable signature checks in your profile.

The synthetic provider never accesses SEP, the real broker, Apple or the user's
profiles. A green browser run proves adapter/browser interoperability, not a real
fingerprint or iCloud upload. Real hardware/RP validation remains a separate,
user-initiated check through the normal native broker.
