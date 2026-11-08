# Apple browser-extension UX reference and adaptation plan

Reviewed 2026-11-08 against Apple's iCloud Passwords **3.4.0** packages for Chrome
and Firefox. This records the original inspection and adaptation plan. Implementation status
is tracked below and in [the adapter guide](README.md).

## Evidence

- [Firefox listing and screenshots](https://addons.mozilla.org/en-US/firefox/addon/icloud-passwords/).
- [Chrome listing](https://chromewebstore.google.com/detail/icloud-passwords/pejdijmoenmkgeppbflobdenhhabjlaj).
- [Apple's documented enable, fill, save and update flows](https://support.apple.com/en-au/guide/icloud-windows/-icw76039ec0f/icloud).
- Downloaded Firefox XPI from the listing's AMO API and Chrome CRX from Google's
  extension update endpoint. Both manifests report 3.4.0. The Firefox file matches
  AMO's advertised SHA-256:
  `0cffb1716a9eff72e44a592bdef05e32d102d68253fdc508e5e6bdb5880ecbef`.
  Chrome's downloaded file SHA-256 is
  `610ddd342cab1f66c317da9a24206839829a7ba10376afbb21c94781c3d84f26`.
- Their popup, completion-list and settings HTML/CSS are identical. Main UI and
  content scripts match after stripping trailing whitespace. The main platform
  differences are background registration, permissions and Firefox metadata.
- Static inspection covered manifests, UI structure/styles, English message IDs,
  keyboard handling, native-host/protocol markers and the public screenshots.
  No Apple extension code was executed, and its native helper was not available
  for live Mac/Windows interaction. Runtime behavior is attributed to Apple's
  documentation where possible; static states are not proof of a completed flow.

Downloaded packages/screenshots remain in the ignored local directory
`.sep-check-apple-extension-reference/`; none of Apple's scripts, templates,
styles, logos or icons are shipped in our extension. Implement the observed
patterns with our own code/assets and Keychain identity.

## What the reference actually presents

The extension is a compact password/verification-code companion to the native
Passwords application. Its manifest does not request `webAuthenticationProxy`;
inspection found form-autofill handling rather than our WebAuthn interception
path. This is not evidence that every Apple passkey experience belongs to this
extension. Keep our passkey support and native save/authentication dialogs.

| Surface | Observed reference | Proposed Keychain equivalent |
| --- | --- | --- |
| Toolbar popup | Compact account list and separate setup, authorization, loading, unavailable and empty states | Same visual hierarchy; report real broker/agent state and site matches |
| Focused login field | Small anchored account menu, account name above website, key icon | Same interaction after adding broker-validated login matching/filling |
| Account selection | Choose a row to fill; keyboard navigation/activation | A selected row starts our existing native authorization; no extra post-touch approval |
| Native app handoff | Footer entry opens password management | Open `keychain gui` through a fixed, narrowly scoped native-host action |
| Verification codes | Site/account-specific code filling and QR setup | Broker-generated current code after authorization; QR enrollment is a later explicit action |
| New/changed login | Explicit save or update decision | Explicit native review and truthful local/iCloud persistence result |
| Settings | In-page suggestions and browser autofill integration controls | Shared settings, with browser autofill control opt-in if implemented |
| Visual theme | Small system type, restrained separators, hover/selection states, light/dark variants | Shared CSS tokens and `prefers-color-scheme`; retain accessible focus states |

The public screenshot shows a short account menu under the focused field and a
management footer. Package geometry provides a useful starting point:

- Popup content width approximately 344 CSS pixels, with small outer gutters.
- Credential rows approximately 44 pixels high.
- Primary account text around 14 pixels; secondary website text around 13 pixels.
- Small key/type icon, muted secondary text and subtle selection background.
- System-font stack; use available Linux system fonts rather than bundle Apple's
  fonts. Rounded menu edges and soft shadows should follow the browser surface.

Apple's inline list and toolbar popup share a visual model. We should likewise
share the row, empty/loading/error state, type badge and keyboard logic rather
than maintain unrelated Chrome, Firefox and page-menu implementations.

## Keep the flow, retain real authorization semantics

Apple's documented enable flow includes entering a six-digit code shown by its
native application. The package connects to `com.apple.passwordmanager` and has
SRP/PAKE handshake state. This is a separate native-bridge authorization flow;
it should not be confused with Apple Account sign-in or reproduced as a cosmetic
PIN screen. Our native messaging allowlists, paired Linux owner/session checks
and fresh SEP operation policy are different.

For Keychain, the intended sensitive-action flow remains:

1. The user chooses an account/action in the browser.
2. The extension freezes the browser-authenticated destination and selected item.
3. The broker validates that destination and item policy, then presents the native
   site/account/action summary and fingerprint guidance.
4. A successful authorized operation completes the original request; cancellation,
   navigation, expiry or disconnect returns no result.

A toolbar status must describe actual readiness. Do not label the whole vault
unlocked when the provider still requires fresh authorization per operation.
If persistent browser pairing is desired later, design and implement it as a
real protocol, separately from UI polish. Do not add a password/PIN fallback
that the current SEP provider cannot enforce.

## Implementation order

### 1. Shared presentation and existing passkey flow

Restyle the current account picker using the compact row/menu hierarchy above,
including direct row selection, Arrow Up/Down, Enter and Escape, light/dark mode
and visible focus. Keep browser-authenticated site information visible. Preserve
native storage selection and fingerprint dialogs, and the existing one-account
shortcut where no browser account choice is needed.

Add a toolbar popup with truthful connection/readiness, active-site context,
settings and a native-app handoff when available. Move the current badge-click
ON/OFF action into an explicit popup control. Do not show nonfunctional account
or save controls while the corresponding backend operations are absent.

### 2. Password and TOTP autofill

This is a functional addition, not a stylesheet change: the current browser host
only exposes passkey operations. Add browser-scoped login inspection and selected
reveal operations. A CLI's ability to reveal an arbitrary record is not authority
to send it to a website.

The broker must match the selected record against the browser-authenticated
hostname/destination before unsealing. Use an explicit registrable-domain policy
with Public Suffix List boundaries, including private hosting suffixes.
Inspect with metadata only. Release only selected fields to the original live
document/form after native authorization; never store passwords/TOTP seeds in
extension session/local storage. Generate current TOTP codes natively and keep
seeds in protected storage.

Revalidate the original destination, navigation state and intended fields before
filling. Do not automatically submit forms. Passwords filled into a page become
readable by that page; the UI should not imply WebAuthn-style secret isolation.
Inline presentation must resist page overlap/clickjacking; an extension-owned
account picker remains the fallback when a trustworthy inline interaction cannot
be established. Begin with top-level HTTPS documents in both adapters, then add
frame support only with browser-validated frame/ancestor handling.

### 3. Save/update and QR enrollment

Model new and changed logins as explicit, origin-bound proposals. Show which
account and destination will change, and retain cancellation/navigation binding.
Use the protected mutation/durable sync machinery as appropriate. A successful
local mutation is not a verified Apple upload: native review and completion text
must state the actual storage result. Browser password-write support needs its
own authenticated CKKS write/fetch validation before claiming iCloud save/update.

Add QR/TOTP enrollment only as an explicit user action with account/issuer/site
review, protected seed storage and clear persistence results.

### 4. Extend the existing two-browser harness

Keep the real-package Chrome/LibreWolf harness and shared unit suite. Add the
same local HTTPS fixtures for one/multiple saved logins, username-first login,
password changes, current-code filling, expired requests, navigation, hidden or
replaced fields, foreign destinations, unavailable services and save rejection.
Verify keyboard-only operation and both color schemes. Use synthetic credentials
for automated tests; reserve real SEP/iCloud acceptance for deliberate user runs.

## Implementation status (2026-11-08)

- Shared compact account picker and toolbar are implemented, including direct
  selection, keyboard controls, light/dark styling, actual readiness, enable
  switch, and fixed native-app handoff when installed.
- Password/code matching includes subdomains within the same registrable domain,
  with private Public Suffix List entries isolating unrelated hosting tenants.
- Broker-scoped password/current-code filling is implemented for top-level HTTPS
  forms. Username-first filling uses public metadata only. Destination and field
  checks run before biometric/device access; original form/input checks run again
  before filling. Unprotected software entries are not offered implicitly.
- The shared unit and real Chromium/LibreWolf harnesses cover these read flows
  with synthetic credentials. Native hardware acceptance of the new browser fill
  operation remains a separate deliberate user check.
- Save/update, generation, QR enrollment and browser-autofill integration controls
  remain pending. No cosmetic save controls or local-success-as-iCloud-success
  states are shipped. The password write API needs independent CKKS encoding,
  update-conflict and fetched-record verification work before those flows can run.
