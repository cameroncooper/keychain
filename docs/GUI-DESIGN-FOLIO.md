# Keychain GUI design inspired by Folio

Date: 2026-11-12

Keychain can adopt Folio's restrained Qt Quick design while retaining its
credential-oriented layout and existing authorization boundaries. The proposed
main view is a searchable credential list with category navigation and a detail
pane. Selecting an item shows metadata; revealing a secret remains an explicit
action. The framework choice is covered in [the companion assessment](GUI-FRAMEWORK-ASSESSMENT.md).

## Folio visual design

This assessment uses Folio commit `ac9d14f263e2bef8b8c8d960386fd4500cabb7b3`
and its published grid, columns and preview screenshots. These are observations
of its source and reference images, rather than a live usability evaluation.

Folio's main window uses a continuous top bar and adjacent panes separated by
hairline rules. Its default size is 1280 by 800 logical pixels; the top bar is
60 high, with preferred widths of 190 for the sidebar and 300 for details. Details disappear
below a width threshold. The visual hierarchy comes from alignment and space
rather than separate raised cards. [Main.qml](https://github.com/omacom/folio/blob/ac9d14f263e2bef8b8c8d960386fd4500cabb7b3/src/Main.qml)

| Element | Folio observation | Proposed Keychain treatment |
| --- | --- | --- |
| Surfaces | Flat palette-based surfaces, with a darker details pane | Use shared background, detail surface and separator tokens; avoid nested cards around every field |
| Type | Application-wide monospace at 13 logical pixels | Follow the user's monospace font; slightly larger item titles and clear labels for long usernames |
| Color | Accent marks selection and the main action | Reserve accent for active navigation, selection and deliberate actions; use text and icons alongside security status |
| Icons | A coherent set of line drawings | Bundle local login, passkey, code and storage glyphs; do not fetch site favicons |
| Controls | Quiet toolbar buttons and filled primary actions | Keep search and navigation light; make Reveal, Hide and Cancel unambiguous |
| Density | Compact navigation with generous content margins | Use readable two-line credential rows, consistent spacing and ample room for details |

The type choice is explicit in [main.cpp](https://github.com/omacom/folio/blob/ac9d14f263e2bef8b8c8d960386fd4500cabb7b3/src/main.cpp).
Folio's buttons customize Qt Quick controls with their own backgrounds, focus
rings and label treatment; selecting the Material style alone will not reproduce
this appearance. Primary buttons have a 36-pixel implicit height and a minimum
width of 88. They omit ripple effects and animation. [PlainButton.qml](https://github.com/omacom/folio/blob/ac9d14f263e2bef8b8c8d960386fd4500cabb7b3/src/PlainButton.qml)

## Folio interaction design

Folio keeps navigation and actions close to the selected item. Arrows navigate,
Enter opens, Space previews, Tab moves between regions and `?` presents shortcut
help. Typing disables conflicting single-letter shortcuts. Its menus show action
names and shortcuts, and dialogs keep keyboard navigation inside the dialog.
Keyboard focus is visibly distinct from selection.
[Folio interaction overview](https://github.com/omacom/folio#keys),
[FolioDialog.qml](https://github.com/omacom/folio/blob/ac9d14f263e2bef8b8c8d960386fd4500cabb7b3/src/FolioDialog.qml)

For Keychain, reuse these interaction principles with credential-specific actions:

- Ctrl+F or Ctrl+K focuses search. Arrows move through results. Enter opens details.
- Tab moves through navigation, search, results and detail actions in a predictable order.
- Escape hides revealed fields first, then dismisses a menu/dialog or returns from details.
- `?` opens shortcut help when the user is not typing. Ordinary typing never invokes global actions.
- Selection never copies a password, requests a fingerprint or signs with a passkey.
- Password reveal and copy are separate explicit actions. Clipboard copying remains a follow-up until its lifetime and clipboard-manager behavior are implemented.

Space should not automatically reveal a secret merely because Folio uses it for
preview. A safe first version can use Space to toggle metadata details.

## Proposed Keychain layout

| Region | Contents |
| --- | --- |
| Top bar | Keychain title, search, clear local refresh status, minimal overflow menu |
| Left navigation | All, Logins, Passkeys and Codes, limited to supported item types |
| Credential list | Site/title, account name, credential type and selected-row treatment |
| Details | Full site and account, supported secret fields, storage destination and local protection information |

Start with approximately a 200-pixel category pane, a 300–360-pixel result list
and a flexible detail area. These are proposed starting sizes, not copied
requirements. On medium windows, collapse categories into a filter control.
On narrow windows, switch between results and details with Back navigation.
Test translated labels, long account names and fractional display scaling before
fixing breakpoints.

Use a virtualized list for credentials. Folio's grid, filesystem columns,
filesystem breadcrumbs, split browsing and file preview window do not add useful
first-version password-manager behavior. A single coherent list avoids hiding
passkeys behind a separate interface.

An item can be stored in iCloud while its local copy is protected with the SEP.
Show those as separate facts. A locally generated passkey can be device-only.
Do not infer cloud provenance for protected login metadata that does not record
it. Use the authenticated inventory and existing routing policy to determine
what the app can actually say.

## Theme behavior

Folio reads the whole Omarchy palette from
`~/.local/state/omarchy/current/theme/colors.toml`, follows light/dark mode and
re-arms watchers after symlink replacement. It obtains effective rounding from
Hyprland and derives secondary/accent text colors from the palette.
[theme.cpp](https://github.com/omacom/folio/blob/ac9d14f263e2bef8b8c8d960386fd4500cabb7b3/src/theme.cpp)

For Keychain, make theme selection an explicit preference: System, Omarchy and
optional Light/Dark overrides. System should use the desktop appearance portal
and Qt palette fallback. Omarchy should use Folio's palette and rounding approach
when present, with a neutral fallback elsewhere. An Auto default can select the
Omarchy provider when available and System otherwise. Keep that rule visible
and deterministic rather than silently mixing conflicting sources.

The proposed token set is background, detail surface, hover, selected background,
foreground, secondary foreground, accent, accent foreground, separator, error and
radius. Share tokens between the future Qt app and Qt authentication window.
Omarchy file formats and Hyprland commands belong in an optional adapter; the
rest of the application must run without either desktop component.

## Authentication and secret handling

Keep the authentication agent a separate unprivileged process. Reuse the visual
tokens, type and icon vocabulary, but retain a small floating prompt with the
validated operation, site, account, fingerprint guidance and persistent Cancel.
Keep the current focus, presentation acknowledgement and cancellation semantics,
and preserve the TouchBar1 D-Bus contract.

The current Keychain client requests authorization per operation. Reusable
authorization depends on an agreed kernel/broker session contract and client
integration. The first Qt GUI must retain existing requirements rather than
suggesting that opening the app unlocks every secret.

List models contain metadata only. Secrets are requested for the selected item
and field, kept out of search, QSettings, list delegates, logs and session restore,
and hidden on the existing timeout, selection changes, focus loss and cancellation.
QML text/layout and Qt strings create additional plaintext copies when a secret
is displayed; Rust zeroization cannot erase all renderer, GPU or compositor
copies. This limitation also exists in the current GPUI presentation.

Set untrusted account, site and note text explicitly to `Text.PlainText`.
Qt's default text detection can interpret styled content and load remote images.
Retain existing domain normalization and control/bidi checks.
[Qt Text documentation](https://doc.qt.io/qt-6/qml-qtquick-text.html#details)

## Design validation

Build the first layout with synthetic credentials. Check both themes, keyboard
navigation, visible focus, screen-reader labels, long strings, right-to-left
layout and narrow tiled windows. Test account selection without secret access,
then deliberate reveal/hide flows through a fake backend. Live fingerprint and
Touch Bar checks belong to the later integration stage.

Folio's code is MIT licensed. If components or drawing code are adapted, preserve
its copyright and license attribution with the adapted files.
[Folio license](https://github.com/omacom/folio/blob/ac9d14f263e2bef8b8c8d960386fd4500cabb7b3/LICENSE)

## Accepted implementation

The CXX-Qt prototype was accepted and is now the main app in
[`desktop/`](../desktop/README.md), replacing the GPUI credential browser.
The separate GPUI authentication agent remains installed and unchanged.
The shared Rust controller retains selected-field reveals, cancellation,
identity/revision checks and the existing focus/time limits.

The first usable app has automatic Omarchy-palette/Qt-appearance fallback,
metadata browsing and deliberate password/code/notes reveals. Theme preferences,
live corner-radius detection, translated catalogs and a Qt authentication popup
remain follow-up work. The synthetic encrypted-vault harness validates the actual
production QML and adapter; hardware acceptance is separate.
