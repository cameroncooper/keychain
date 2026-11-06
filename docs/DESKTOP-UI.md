# Desktop app and authentication window

The native desktop stack is GPUI-kit 0.9.0, pinned in Cargo.toml/Cargo.lock.
There is no GTK dependency. The upstream [application recipe and architecture](https://github.com/longbridge/gpui-kit)
provide the GPUI/component initialization and platform backend. This is an optional
build: `desktop-ui` builds `keychain-gui`, and `desktop-agent` also builds the
separate authentication agent. The terminal-only build remains independent.

## Windows and interaction

`keychain gui` replaces its process with the adjacent `keychain-gui` executable,
without a shell or PATH lookup. Both entry points protect against core dumping.
The app refuses root execution. On Linux it uses the GPUI Wayland/X11 renderer;
the compositor remains responsible for placement, focus and decorations.

The [Apple Passwords reference](https://cdsassets.apple.com/live/7WUAS350/images/macos/sequoia/macos-sequoia-passwords-selected-website-edit-password.png)
informs the three-pane layout: quiet gray category tiles at left, searchable
credential list in the middle, and grouped detail cards at right. Categories are
All, Passwords, Passkeys and Codes; unsupported collections are omitted. The app
uses bundled icons instead of downloading favicons or contacting listed sites.
Category tiles and list items use GPUI Base buttons for keyboard and accessibility
behavior; search and action buttons use GPUI Component. Ctrl+F focuses search.
Narrow tiled windows replace the sidebar with a compact filter strip.

Details describe whether an item is synced or device-only separately from how
its local key is protected. The app reads the shared `inventory::visible_index`
used by the CLI, including the collision checks for broker-native items. It reads
the authenticated metadata index for normal browsing, not passwords, TOTP seeds
or passkey scalars. The existing index-less software-vault fallback still applies
to older caches; it is not used when protected-login routing exists.

Refresh means refresh the local inventory. Apple sign-in, join and network sync
remain explicit CLI operations. This first app has no editing, creation, deletion,
autofill or Apple record write buttons.

The authentication window is a separate, short-lived user-session process. It has
a narrow header with Keychain and Cancel, the broker's exact operation/account,
a fingerprint symbol, and the driver's progress guidance. There is no approve
button and no success callback from the UI. Closing, Escape, Cancel, malformed
input or disconnect cancels the broker request. Multiple overlapping requests are
refused. A new window must pass the presentation acknowledgement before capture.
No fingerprint capture occurs just because the GUI was opened.

## Reveal and memory limits

Inventory loading and reveals run off the UI thread. Each reveal revalidates the
selected metadata and routing. Protected reveals use the exact broker revision
and content binding and request only the chosen password, notes or current TOTP
code. Missing or changed protection never falls back to the software vault.
Software-backed reveals use the existing encrypted snapshot and explicitly refuse
protected records. As in the CLI, reading this older snapshot decrypts the whole
software vault transiently; the GUI does not add a new plaintext database.

Changing selection, search, filter, refreshing, Escape or closing invalidates the
pending reveal. Late responses are dropped. Revealed response owners wipe on drop.
Fields hide after 30 seconds, code expiry or window deactivation. A response arriving
while the app is inactive is held without rendering for at most two seconds for
the fingerprint window to close and focus to return, then discarded. Focusing the fingerprint window necessarily
deactivates the app: pending verification is allowed to finish, but it cannot display
fields in an inactive app window. No automatic clipboard writes or secret logging.

Rendering intentional plaintext necessarily passes copies into GPUI text/layout
and GPU resources; we cannot promise to wipe renderer, GPU, compositor, screenshot
or accessibility copies. Hiding is a display lifetime limit, not a claim of total
memory erasure. The existing software backend remains accessible to same-UID code.
Passkey scalars and TOTP seeds have no UI reveal path.

## Request identity

The agent accepts only kernel-verified root peers over its private socket. The
root broker still binds the request, selected credential and active Linux session,
and the SEP driver supplies biometric authorization. The agent has no SEP access
and cannot turn a visible/cancel event into a grant. D-Bus is only a lifecycle path.

The immediate client process is not proof of an ultimate browser, extension or
tab identity. The header therefore says Keychain, never a purported verified browser.
Metadata is rendered as plain text, with controls and bidi overrides removed from
presentation; domain fields use ASCII host serialization. The ordinary desktop
window is not a compositor-protected security surface.

The private prompt protocol carries an operation enum, selected account, typed
WebAuthn/login target and storage policy. The broker constructs these fields from
its validated request context and selected persisted metadata. The agent renders
its own action labels; human action text is not an input and no caller-provided
application label is accepted. Login records are labeled as a protected local
copy rather than claiming cloud provenance absent from their broker metadata.
Creation wording says "Save in iCloud", never that an upload already succeeded.

WebAuthn RP IDs must be canonical ASCII hostnames and origins must be canonical
HTTPS origins belonging to that RP. Control characters, bidi overrides, oversized
values and incompatible operation/target/storage combinations are refused before
capture. Passkey use/creation requires an origin; protection verification without
a browser request deliberately does not invent one. Details shows the complete RP
and full origin as "Requested origin · browser bridge"; it never calls the ultimate
browser a verified requester. Long values remain inspectable in the scrollable
content area; Cancel stays outside that area.

The private wire version is 2. Rebuild/install broker, agent and diagnostic tools
together; old or unknown wire versions fail closed without capture. This changes
neither the credential/cache formats nor the browser native-messaging version.
There is no compatibility fallback that reconstructs trusted data from prose.

## Validation and follow-up

Before switching installed services, compile the optional stack and run the normal
workspace tests plus desktop tests and clippy. Exercise the new rendering on the
actual Wayland/GPU stack; test presentation, Escape/Cancel, disconnect and successful
fingerprint operations separately. Rendering tests do not substitute for a live
biometric round trip. Keep the previous installed binaries until the replacement
has passed the presentation checks.

Follow-up: resizable panes and large-inventory
virtualization, comprehensive assistive-technology validation, deliberate clipboard
copy with a documented clipboard-manager policy, GUI sync/setup and supported editing
operations. Never expose an unsupported action just to reproduce a reference image.

### Hyprland placement

GPUI advertises a modal dialog, but Hyprland on this development machine still
places it as a tiled toplevel. `contrib/hyprland/keychain.lua` contains an optional
Hyprland 0.57+ rule, following the [current window-rule syntax](https://wiki.hypr.land/configuring/core/rules/window-rules/),
for the exact authentication app ID. It makes only that window floating, centered,
420 × 290 with 16-pixel rounded corners and an opaque background; it grants no trusted-surface identity or authorization. Load
the module after desktop defaults. On Omarchy, copy it to `~/.config/hypr/keychain.lua`
and add `require("hypr.keychain")` to `hyprland.lua`, then validate `hyprctl reload`
and `hyprctl configerrors`. This rule is applied to the development desktop with a
backup of the previous user config; the service installer does not alter desktop
configuration. Other compositors retain their own placement policies.

### Development-machine evidence (2026-11-06)

The release build with `desktop-agent` passed on Asahi/Wayland using Rust 1.98.1.
The normal workspace suite and desktop selected-field/metadata tests passed, as
did clippy with warnings denied and formatting. Both the three-pane app and its
compact tiled layout rendered with the existing five-item inventory (two logins,
three passkeys). No network sync, Apple item write or credential migration was
performed for this UI change.

Synthetic root presentation requests passed visible acknowledgement, user window
cancellation and broker-finished closure. The installed D-Bus/systemd agent also
passed a synthetic presentation/closure request. Hyprland reports no configuration
errors and the scoped rule produces a centered, opaque 420 × 340 dialog. These
checks never started fingerprint capture. A real fingerprint signing/reveal round
trip through this new UI remains to be checked with the user; earlier GTK hardware
evidence is not evidence of GPUI-specific behavior.

### Popup refinement and focus policy

The popup uses an original, embedded fine-line fingerprint SVG, a compact header,
quiet Cancel control, a short heading, and separate broker-supplied operation/account
text. It does not parse prose to invent a website, claim a verified application
identity, offer an unsupported password fallback, or display an approval button.

The prompt remains modal to its operation while allowing desktop app switching.
It deliberately does not set Hyprland `stay_focused` or install a global input grab.
After the window first becomes active, losing activation sends Cancel and closes
it. Returning to Keychain never resumes that capture; the requester must start a
new operation. The first Visible acknowledgement now requires both a rendered
frame and active-window focus. These are presentation checks, not a trusted desktop
surface or biometric authorization. The broker continues to enforce its own
session, cancellation and authorization checks.

### Desktop appearance

Both windows follow the generic XDG Desktop Portal Settings preference
`org.freedesktop.appearance/color-scheme`: 0 is no preference, 1 prefers dark, and
2 prefers light. GPUI's Linux platform already reads this setting and subscribes
to its change signal. Keychain synchronizes GPUI Component's theme when each
window opens and observes subsequent window-appearance changes. Custom surfaces,
text, dividers, error states and the fingerprint artwork use a shared light/dark
palette; components use the matching GPUI theme. Missing portal support/no
preference uses GPUI's light fallback. Appearance does not affect authorization.

No Omarchy config, GTK theme name or desktop-specific setting is read to select
appearance. The portal expresses a preference rather than a complete vendor color
palette. Reference: [Settings portal specification](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Settings.html).


Refinement validation on 2026-11-06: the installed agent rendered the new rounded
420 × 290 popup in dark mode with the session portal reporting `color-scheme=1`.
A synthetic request received Visible only after rendering/focus; explicitly
switching to a terminal produced Cancel and closed the window. No fingerprint
capture, signing, Apple request or credential reveal was performed in this check.
The desktop's actual theme was not changed for testing.


The first full debug-test rebuild exhausted RAM while several link jobs ran at
once on the 16 GB development machine; the kernel killed a linker in the terminal
scope. A serial `cargo test --locked --features desktop-agent --workspace -j 1`
subsequently passed. Desktop test instructions use one build job on this machine;
no swap, global Cargo setting or desktop memory policy was changed.

Structured-field validation on 2026-11-06: the workspace suite passed after the
broker constructors were switched, and seven focused prompt tests passed after
the shared agent decoder was added. These include wire-version refusal,
operation/target/storage mismatch, canonical RP/origin checks, control/bidi bounds,
spoofed application fields and creation wording. The serial release build,
clippy (warnings denied) and formatting passed.

The installed agent rejected root requests using the old wire version, an
outside-RP origin and a spoofed application label; ordinary-user connections were
also refused. A synthetic valid request displayed account/storage metadata;
keyboard Tab/Space opened Details with full RP and origin, while the driver-status
footer remained visible. Switching focus returned Cancel and closed the preview.
No SEP operation, Apple request or saved credential change occurred. Normal
inventory still contains the same five items; synced creation stays disabled.

Real GPUI signing acceptance on 2026-11-06: after fresh user readiness, a new
diagnostic process used the saved disposable SEP key to sign the public message
`GPUI appearance validation 2026-11-06`. Native biometric signing completed and
the diagnostic independently verified the signature against the saved public
key. The user confirmed that the popup was centered and floating, text and theme
were correct, and it closed after the touch. No saved passkey or Apple request
was involved. This establishes the new window's successful hardware path; live
cancellation/cleanup through this window and complete-chain reboot acceptance
remain separate checks.
