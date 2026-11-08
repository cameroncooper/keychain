# Browser adapters

The extension provides passkey creation and authentication. Password/TOTP form
filling is not implemented. Both adapters use the same Rust native host, broker,
account picker and native GPUI storage/fingerprint prompts.

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

The toolbar badge toggles interception. In Firefox, OFF delegates *new* calls to
the browser's captured original methods; disabling during a request cancels it.
There is no automatic fallback after a native operation fails or is canceled.
Other passkey extensions may intercept the same methods: avoid enabling multiple
passkey providers while evaluating this adapter.

## Shared code and browser trust boundaries

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
scenario and explicitly labels that omission in console/results. `CHROMEDRIVER` and
`CHROMIUM_BINARY` override Chromium discovery. The harness needs Node, Python 3
(for ZIP packaging), OpenSSL and the selected browser/driver. It creates a private
`/tmp/keychain-browser-harness-*` directory, isolated HOME/profiles, local HTTPS
RP and a **synthetic native provider**, then loads the actual packaged extensions.
It verifies registration/accessors, the real shared account picker, signed assertion
origin/challenge, foreign-RP refusal, abort, timeout and a fresh request after cancellation. Evidence is retained
in that directory; child sessions are closed on completion. Chrome's proxy can
omit or expand timeout, so its negative deadline check may take two minutes.

The synthetic provider never accesses SEP, the real broker, Apple or the user's
profiles. A green browser run proves adapter/browser interoperability, not a real
fingerprint or iCloud upload. Real hardware/RP validation remains a separate,
user-initiated check through the normal native broker.
