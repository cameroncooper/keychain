# Keychain desktop: Folio lessons and overhaul plan

Date: 2026-11-14. Reference: Folio commit `61b7e20` (current `origin/main`),
all 34 QML components read in full, plus `theme.cpp`, `Format.js` and the
published screenshots. Our side: `desktop/qml/Main.qml` (680 lines),
`desktop/src/{backend,theme}.rs`, `src/gui/{controller,data}.rs`, `desktop/preview.png`.

The [earlier audit](../prototypes/qt/docs/FOLIO-STYLE-AUDIT.md) matched Folio's
*measurements* (font, row heights, insets, focus ring). The app now has the
right sizes, but it doesn't behave like Folio yet. Folio's quality comes from
a few consistent ideas about focus, hierarchy, state and wording. Those
ideas are not in our code. This document names them, checks our app against
each one and sets out a phased plan.

---

## Part 1 — What Folio actually does

### 1. One quiet window: hierarchy without decoration

- **Three text tones, one accent.** `brightForeground` for the thing you're on
  (current crumb, selected name, dialog titles, active sidebar row);
  `foreground` for content; `secondaryForeground` (fg mixed 0.68 toward bg)
  for everything descriptive. Accent marks only *selection*, *focus* and *the one
  main action*. Red is reserved for errors and erasing. Nothing else gets color.
- **Surfaces are flat.** The window has two surfaces: `background` and the
  darker `darkBackground` for the details pane. The panes are divided by
  hairlines at `fg α0.12`. There are no cards, shadows or gradients.
  Hover is `fg α0.05–0.08`, selection `accent α0.16–0.18`, and drop targets
  add a 2-pixel accent border. That is the whole state vocabulary.
- **Weight shows position.** The only demi-bold text is the last breadcrumb,
  the details title, dialog titles and filled buttons.
- **Folio avoids motion, deliberately.** It has no ripples, menu fades,
  tooltip fades or scrollbar fades (`enter: null`, `exit: null`,
  `transitions: []`). The single animation is a 100 ms opacity fade when the
  window first *settles*.
- **Radius follows the desktop.** It is read from Hyprland and capped at 4
  for rows and buttons, 6 for menus and the full value for dialogs. Glyph
  boxes round only when the theme rounds.

### 2. The top bar is *where you are*, not *what app this is*

The 60-pixel bar holds the breadcrumb (`~ / Pictures / Lisbon 2026`). It
starts at the window's left edge, over the sidebar, and the last crumb is
bright and demi-bold. The app name never appears. When you press `/`, a
search field **replaces** the breadcrumb in place. The field ends with a
scope hint that stays while you type ("Search Lisbon 2026 and below"). The
right side has only 36-pixel icon toggles, each with a tooltip that names
what a click *does* ("Show as list", not "List view"). Toggles show `active`
with an accent tint.

### 3. Focus moves between regions, not between every control

- `Tab` cycles **regions**: sidebar → file pane → details (only when details
  has something to operate). It is not a walk across every widget. Rows and
  icon buttons are `NoFocus`, and the sidebar owns one keyboard cursor.
- Inside a region, the arrows move a cursor, and **the selection follows the
  cursor**. `Enter` performs the primary action. `→` from the sidebar returns
  to the files. `Escape` returns focus to the main view.
- **Focus is visibly distinct from selection.** A selected item is tinted. A
  focused row inside a region gets a 1-pixel accent border. A focused button
  gets a 2-pixel ring with 3 pixels of clearance, so it reads even on an
  accent fill.
- **Single-key shortcuts back off while you're typing.** Each pane computes a
  `typing` boolean, and `Q`, `S`, `?`, `Space` and `Delete` are gated on it.
- **Escape works in layers:** stop work → dismiss the error → narrow a
  multi-selection → end search.
- **A click doesn't take focus away from where you were** (`PlainButton`
  uses `Qt.TabFocus`). When a dialog closes, it always calls `focusView()`.
- **Its menus teach the shortcuts.** Every context-menu entry shows its keys.
  `Alt+Enter`, `Menu` and `Shift+F10` open the same menu beside the
  keyboard's current item.
- `?` opens a data-driven shortcut sheet: keys in accent, descriptions in
  foreground, two or four columns depending on width, scrollable by arrows
  and Page Up/Down. A quiet circled `?` in the sidebar corner makes it
  discoverable.

### 4. Details: a calm preview with one main action

`PreviewPane` sits on the dark surface with 28-pixel insets and 22 pixels
between groups. Top to bottom:

1. a hero (thumbnail, text excerpt or a 72-pixel glyph at stroke 1.2);
2. the name (15, demi-bold, bright, up to three lines);
3. a summary line (12, secondary: "JPEG image · 27.1 KB");
4. a two-column fact grid (12; labels secondary on the left, values right-aligned);
5. a spacer;
6. **one** full-width accent button pinned to the bottom. Its label names the
   result ("Open with Plain") and it shows a `⏎` hint.

Nothing selected → a centered "Nothing selected" in secondary. There are no
rules between groups; spacing does that work.

### 5. State is spoken in the window, never swallowed or flashed

- **Banner** under the bar, 40 pixels high: red-tinted (`red α0.14`) for
  problems, with a dismiss ✕. Accent-tinted (`accent α0.10`) for slow work,
  with Cancel when the work can be stopped.
- **Slow-work delay:** work that finishes in under a second never shows the
  banner (`Timer { interval: 1000 }`), so nothing flashes.
- **Empty states depend on context:** "Nothing matches “x”", "This folder is
  empty" or a plugin's own text. They never show while a load is in progress.
- **Startup settles first.** The contents stay invisible and disabled until
  Hyprland's real size arrives (or 150 ms passes), so nothing jumps and
  nothing can be clicked early.
- **Selection survives changes.** The cursor is tracked by *path*, not row
  index, across re-reads and view switches.

### 6. Dialogs and fields

- `FolioDialog`: a 0.55 black scrim, a card with a 1-pixel accent edge (red
  for destructive dialogs), 28-pixel margins, a 16 demi-bold title, Tab
  trapped inside, and right-aligned buttons with a 10-pixel gap.
- **The default focus encodes risk.** Ordinary confirmations focus the
  primary button. Erasing a drive focuses **Cancel**, and the red button
  requires a deliberate choice. In the server-trust question, *no* answer
  is focused, so a stray Enter can't approve it.
- `MountPrompt` (Folio's own password prompt) clears the password every time
  it opens or closes, so a password typed for one host is never shown to
  the next.
- `PlainField` is a dark box with a hairline border that becomes accent on
  focus. The hint stays inside the field. Folio explicitly disables
  Material's floating placeholder.

### 7. Wording

Folio's labels are plain, sentence-case verbs that name the outcome:
"Drop to pin", "Show as columns", "Open with Plain", "Delete for good?".
Counts use the locale's digits. Uppercase comes from
`font.capitalization`, never from uppercase string literals, so
translations stay correct. Every right-to-left case sets explicit alignment.

### 8. Code shape

There is one file per component: `PlainButton`, `IconButton`, `PlainField`,
`Glyph`, `FolioMenu`/`FolioMenuItem`/`MenuLine`, `FolioScrollBar`,
`FolioDialog`, `HelpOverlay`, `Sidebar`, `PathBar`, `PreviewPane`, and so
on. The theme is a typed `QObject` with one property per token. Lists use
real `QAbstractListModel`s. Each file opens with a comment explaining the
design reason, not the mechanics.

---

## Part 2 — How our app measures up

Our sizes are right, but the behavior and hierarchy still look like a
generic three-pane app styled in Folio's colors. Ordered by user impact:

| # | Issue | Where | Folio principle |
|---|---|---|---|
| 1 | **Every account row is a Tab stop** (`focusPolicy: Qt.TabFocus` on the delegate), and so is every sidebar button. With 300 items, Tab is unusable. | `Main.qml:385`, `:308` | §3 regions |
| 2 | **Arrows don't select.** The keyboard cursor and `state.selected` are separate; Enter is required. After a refresh or search, `currentIndex` doesn't follow the selected id. | `:355–393` | §3, §5 |
| 3 | **While one reveal is pending, every Reveal button reads "Cancel"** (`state.busy ? "Cancel"`), and nothing says we're waiting for a fingerprint. | `:518`, `:561` | §5 |
| 4 | **The details pane has no hierarchy:** three identical grey 36-pixel "Reveal" slabs, rules between fields, masked dots at two sizes (18 vs 13), left-aligned values, no main action and an 11-pixel footnote. | `:470–620` | §4 |
| 5 | **Errors are tiny secondary text at the very bottom** of the window, easy to miss and impossible to dismiss. The theme has no `red`. | `:624`, `theme.rs` | §5 |
| 6 | **The top bar shows the app name**, which the title bar already shows, and a permanent box field with Material's floating placeholder. | `:223–249` | §2, §6 |
| 7 | **The sidebar has no glyphs or counts.** "LIBRARY" and "LOCAL INVENTORY" are hard-coded uppercase literals (a translation bug); the latter is a floating label with no meaning. | `:298–329` | §1, §7 |
| 8 | **Rows repeat themselves:** every login has the same globe and the word "Login" on the right. A login with a code or fingerprint protection looks the same as one without. | `:409–431` | §1 |
| 9 | **There are three responsive layouts** (≥1000, 800–1000 with a top filter strip, <800 with page swap), and a text "← Accounts" button. | `:267–284`, `:449` | §1 |
| 10 | The help popup has a fixed height of 300. Its rows are aligned with spaces inside `qsTr` strings, and it omits `?` and `Q`. | `:636–679` | §3, §7 |
| 11 | Empty, loading and "no match" all show "No matching accounts". | `:435` | §5 |
| 12 | There's no settle step, so the layout jumps when Hyprland resizes the window. | — | §5 |
| 13 | The theme reads 5 keys, polls the file every second and keeps radius at 0. | `theme.rs`, `:109` | §1 |
| 14 | It's one 680-line file, with JSON strings as the model, so every change to the rows rebuilds every delegate. | — | §8 |

What we already do right (keep it): `Text.PlainText` everywhere, layered
Escape, typing-gated `?`/`Q`, Folio button geometry and focus rings, the
scrollbar, Shapes glyphs and the RTL mirroring hooks.

---

## Part 3 — The plan

### Target layout (wide)

```
┌───────────────────────────────────────────────────────────────────────────┐
│ Keychain / Logins                                                    ↻    │ 60  top bar: scope/search, icon toggles
├──────────────┬──────────────────────────┬─────────────────────────────────┤
│ KEYCHAIN     │ ◍ github.com          ⏱ ◉ │            ◍  (56px glyph)      │
│ ◇ All     12 │   alice@example.com      │                                 │
│ ◍ Logins   9 │▐◍ example.com        ⏱  ▌│  example.com                    │ 15 demi bright
│ ⚿ Passkeys 3 │▐  alice@example.com     ▌│  Login · fingerprint required   │ 12 secondary
│ ⏱ Codes    4 │ ⚿ webauthn.io            │                                 │
│              │   bob                    │  Account     alice@example.com ⧉│ field rows: label · value · icon actions
│              │                          │  Password    ••••••••••   👁  ⧉ │
│              │                          │  Code        ••• •••  ◔ 21s 👁  │
│              │                          │  Notes       Hidden          👁 │
│              │                          │                                 │
│              │                          │  Website           example.com  │ fact grid, values right-aligned
│              │                          │  Saved in         iCloud-synced │
│              │                          │  Protection  Fingerprint req.   │
│ 12 items     │                          │                                 │
│ refreshed 2m │                          │ ┌─────────────────────────────┐ │
│ (?)          │                          │ │ Reveal password           ⏎ │ │ one primary action
└──────────────┴──────────────────────────┴─┴─────────────────────────────┴─┘
```

`◉` = fingerprint-protected and `⏱` = has a code. These are quiet secondary
glyphs and replace the "Login" text. The banner, when shown, sits directly
under the top bar and spans the content columns.

### Phase 0 — Foundations (no intended visual change) — done 2026-11-14

Status: implemented as described below, with two differences. (a) The
list uses a QML `ListModel` that the bridge's metadata array updates in
place (removals, insertions, per-row `set`), the way Folio's column view
maintains its trail. It does not use a CXX-Qt `QAbstractListModel`. This
gives the same stable delegates and cursor at a fraction of the bridge
code. Revisit if inventories grow into the thousands. (b) Palette and
rounding are polled once per second only while the window is active,
which is Folio's own rounding policy, instead of with a file watcher. The
rounding comes from Hyprland's request socket with 100 ms timeouts. Menu,
dialog, banner and field-row components arrive with the phases that use
them.

1. **Split `Main.qml`** into Folio-shaped components under `desktop/qml/`:
   `Theme`/`Metrics` (singletons), `PlainButton`, `IconButton`, `PlainField`,
   `Glyph`, `KeychainMenu`/`MenuEntry`/`MenuLine`, `QuietScrollBar`,
   `KeychainDialog`, `HelpOverlay`, `TopBar`, `Sidebar`, `AccountList`,
   `AccountRow`, `DetailPane`, `FieldRow`, `Banner`. Keep the `objectName`s
   that `tests/smoke.qml` asserts. Extend `THIRD-PARTY-NOTICES.md` for each
   adapted file.
2. **Use the full palette from `theme.rs`**: `red`, `yellow`, `green`,
   `blue`, `lighterBackground`, `light`, and `radius` read from Hyprland
   `decoration:rounding`, using Folio's approach with a 0 fallback. Replace
   the one-second poll with a file watcher that re-arms after the symlink is
   swapped (`notify`, or `QFileSystemWatcher` through the bridge). Keep the
   Qt colour-scheme fallback.
3. **Replace the JSON `rows` string with a CXX-Qt `QAbstractListModel`**
   (roles: id, site, account, kind, hasPassword, hasCode, hasNotes,
   protected). Selection becomes an id, and QML maps it to an index. This
   removes the delegate rebuilds on every update and makes cursor tracking
   reliable (#2, #14). The model remains metadata-only.
4. **Add to the snapshot:** per-category `counts`, `lastRefreshed`, the
   reveal's `hidesAt` (the 30-second deadline already exists in the
   controller) and `auth` (see "Authorization modes", always
   `per-operation` for now). Keep the `expires` code deadline.
5. **Add the settle step** from Folio's `Main.qml`: contents disabled with
   opacity 0 until the first resize after the first frame, or after 150 ms.

### Phase 1 — Interaction model — done 2026-11-14

Status: implemented, with these additions and differences:
- A search glyph in the top bar gives mouse users a way into search.
- Ctrl+R also refreshes.
- The details pane keeps its own explicit Tab order (main action, then each
  field's actions top to bottom), because Qt's focus chain wraps inside the
  pane.
- Alt+Enter is handled in the list's single key handler, so it can never also
  run the plain-Enter action.


1. **Regions:** sidebar → list → details, cycled with `Tab`/`Shift+Tab`
   through a window-level `moveKeyboard()`. Rows and sidebar entries become
   `NoFocus`, with one cursor per region. The search field is reached with
   `/`, `Ctrl+F` or `Ctrl+K`, not with Tab.
2. **The selection follows the arrows** in the list (selecting reveals
   metadata only, as the design doc already guarantees). `Home`/`End`/
   `PgUp`/`PgDn` work too. The selection stays on the same id across
   search, filter and refresh, and falls back to the nearest row.
3. **Start in search.** When the window opens, the search field has focus.
   `↓` or `Enter` moves into the results with the first match selected,
   which is Folio's `toResults()`. A password manager is search-first.
   Folio is browse-first, so this is a deliberate difference.
4. **`Enter` in the list triggers the details pane's primary action.** Its
   label is always visible with a `⏎` hint, so the user can predict it.
   The compact layout opens details instead. Today that action asks for the
   fingerprint. In an unlocked session it reveals without asking. The key
   binding is the same in both models, and only the button's label and hint
   change (see "Authorization modes").
5. **Escape layers:** close the overlay/menu → cancel pending verification
   → hide the revealed value → dismiss the banner → back from details
   (compact) → clear search → return focus to the list.
6. **Context menu** on right-click, `Alt+Enter`, `Menu` or `Shift+F10`,
   with each entry's keys shown: Reveal password, Reveal code, Reveal notes,
   Copy username, Open website, plus the copy actions from Phase 3 once
   they exist. Use Folio's menu chrome: no animation, a hairline border and
   the accent tint on the highlighted entry.
7. **Data-driven `HelpOverlay`** using Folio's component: keys in accent,
   `Format.keys()` spacing, a width-responsive column count, arrows and
   Page Up/Down scrolling, and a circled `?` in the sidebar corner.

Shortcut sheet after Phase 1:

| Key | Action |
|---|---|
| `/`, Ctrl+F, Ctrl+K | Search |
| ↓ / ⏎ in search | Go to the results |
| ↑ ↓ Home End PgUp PgDn | Move through accounts |
| ⏎ | Primary action (shown on the button) |
| Tab / Shift+Tab | Sidebar, accounts, details |
| Ctrl+1…4 | All, Logins, Passkeys, Codes |
| Alt+⏎, Menu | Account menu |
| Ctrl+Shift+U | Copy username |
| Ctrl+O | Open website |
| F5 | Refresh |
| Esc | Cancel, hide, dismiss, back |
| ? | Shortcuts |
| Q | Close (not while typing) |

### Phase 2 — Visual tightening — done 2026-11-14

Status: implemented, including the authorization-mode views (`UnlockView`,
lock button), which are exercised only by the smoke test. The code countdown
is text ("Changes in 21 s") rather than a ring glyph. The horizontal filter
strip and `NavButton` are gone.


1. **Top bar.** Remove the "Keychain" title. The left side starts at the
   window edge and shows the scope as a breadcrumb (`Keychain / Logins`,
   with the last crumb bright and demi-bold). When search is focused or
   has text, a `PlainField` replaces the breadcrumb; its hint reads
   "Search logins" and the scope "in Logins" stays at its end. Use a
   150 ms debounce. The right side holds icon buttons only: Refresh (which
   shows a busy glyph while loading) and, in the narrow band, Back. Help
   moves to the sidebar corner.
2. **Sidebar.** Give each row a glyph (All ◇, Logins ◍, Passkeys ⚿, Codes
   ⏱) and a secondary count on the right. The section label is "Keychain",
   uppercased with `font.capitalization`. The footer replaces "LOCAL
   INVENTORY" with a two-line status: "12 items" and "Refreshed 2 min ago",
   or "Refresh failed" in red. Put the circled `?` below it.
3. **Account rows** (keep the 56-pixel height). Use a different glyph for
   each kind: a web login is ◍, a passkey ⚿, and a login with only a code
   ⏱. The trailing slot holds capability glyphs (code, fingerprint) at 14
   pixels in secondary, with tooltips, instead of the word "Login". The
   selected row's site text is bright; the accent stays on the tint. Elide
   long accounts in the middle (`ElideMiddle`, as Folio does for names) so
   both the user part and the domain stay readable.
4. **Details pane** — the biggest visible change:
   - The hero is a 56-pixel glyph at stroke 1.2, then the title (15,
     demi-bold, bright, up to three lines), then a summary line (12,
     secondary): "Login · Fingerprint required".
   - **Field rows instead of slabs:** label (12, secondary) · value
     (body; revealed values bright at 15) · trailing 28-pixel `IconButton`s
     (eye/eye-off, and later copy). The masked text is the same width and
     size in every row. A field without a value reads "None" in secondary;
     hidden notes read "Hidden".
   - **Pending state belongs to the field.** Only the field being revealed
     shows its pending text in secondary ("Waiting for fingerprint…" in
     per-operation mode, "Revealing…" in a session, and only after the
     one-second slow-work delay), with its eye button
     becoming ✕ Cancel. The other fields' buttons are disabled, not
     relabeled (fixes #3).
   - **Lifetime is shown on the field:** "Hides in 24 s" next to a revealed
     value, and the code's remaining time as a 12-pixel ring glyph plus
     seconds. Both update on the existing 100 ms tick. Remove the
     30-second footnote.
   - The fact grid follows Folio's: 12-pixel labels on the left and values
     right-aligned, with no rules. Spacing alone separates the groups.
   - **One primary action** pinned to the bottom, full width, 40 pixels,
     accent, with `⏎`. For a login with a password it's "Reveal password";
     for a code-only login, "Show code"; for a passkey there's no button,
     just the secondary line "Use this passkey from your browser."
   - Empty states: "Select an account" when nothing is selected. Before the
     first load, the pane stays blank (no flash).
5. **Banner** (Folio's `FolderPane` banner): red-tinted with ✕ for
   controller messages and refresh failures; accent-tinted for a refresh
   that runs longer than a second. Remove the bottom message line.
6. **List header and empty states.** Remove "N accounts" (the count is now
   in the sidebar). In the list: "Loading…" after a one-second delay,
   "Nothing matches “x”", "No passkeys on this device" and so on for each
   category, and "Keychain is empty — run `keychain sync`" with the command
   shown as plain text.
7. **Responsive layout: two bands instead of three.**
   - ≥ 960: sidebar + list + details. There's no details toggle, because
     the details pane is where actions happen.
   - < 960: the sidebar collapses to a 52-pixel glyph rail (counts in
     tooltips). The list and details swap like a stack: `Back` is an
     `IconButton` in the top bar, along with `Alt+←` and `Escape`. This
     removes the separate horizontal filter strip. Raise `minimumWidth` to
     480 and check it in the narrow screenshot.

### Phase 3 — Capabilities the layout now has room for

Status: 1 (copy username, open website) and 3 (character-coloured
passwords) are done. 2 (copying passwords and codes) waits for the written
clipboard policy, as agreed.


These need explicit agreement, because they touch secret-handling policy.

1. **Copy username / Open website.** No secret is involved. Open website
   calls `xdg-open` on the canonical `https://` origin only, and never sends
   a request from Keychain itself.
2. **Copy password / copy code** (agreed: these wait for the clipboard policy): an `x-kde-passwordManagerHint: secret` MIME hint so clipboard
   managers skip it, automatic clearing after 30 s only if the clipboard
   still holds our value, no primary selection, and a banner saying "Copied
   — clears in 30 s". The same fingerprint/route checks as reveal apply.
3. **Readable revealed passwords** (optional): colour digits in `blue` and
   symbols in `red`/`magenta` from the palette, as dedicated password
   managers do. Monospace already distinguishes `0/O` and `l/1`.

### Phase 4 — Validation

Status, 2026-11-14:
- **Done:** the smoke test covers dark, light and narrow layouts, each in the
  default, revealed and locked states, and runs the keyboard script below.
- **Still to do:** RTL, very long strings, 200 % scale, a live Omarchy theme
  switch, a theme with radius > 0, and assistive-technology checks.
- **Not changed:** controller unit tests still cover stale results, focus loss
  and the hide timer.


- Extend `bin/check` screenshots to a matrix of {dark, light} × {wide, 960,
  narrow} × {nothing selected, selected, revealed, pending, error banner,
  empty, no match}, all with synthetic data.
- **Keyboard-only script** in `smoke.qml`: launch → type → ↓ → arrows → Tab
  through regions → Enter → Esc ladder. Assert focus owners and the selected
  id at each step.
- Check RTL (`LANGUAGE=ar`), very long site and account names, 200 % scale,
  the Omarchy theme swap while running, and the `radius > 0` theme.
- Accessibility: every `IconButton` has `Accessible.name` = its tooltip,
  rows expose "site, account, capabilities", and a pending reveal is
  announced.
- No regression in controller unit tests (stale results, focus loss, hide
  timer). The phases touch QML and presentation only, plus the snapshot
  fields from Phase 0.

---

## What we deliberately do *not* take from Folio

- **Space to preview.** Space must never be one key away from a fingerprint
  prompt or revealing a secret, so it stays unbound in the list.
- **Grid, columns, split panes, drag and drop, path editing.** These serve
  file hierarchies, and a credential list is flat.
- **Hidden details pane.** In Folio, details are optional. In Keychain, the
  details pane is where every action happens.
- **`NoFocus` toolbar icons.** We keep the details' icon actions reachable
  by Tab *inside* the details region (Folio reaches its details region only
  when it has something to operate; ours always does once an item is
  selected).
- **Browse-first launch.** Ours is search-first (Phase 1.3). In the
  `locked` mode, the window opens on the unlock view instead.

## Decisions (2026-11-14)

- **A. Enter performs the primary action.** Under the current
  per-operation model, that starts the fingerprint prompt. Under unlock
  sessions, it reveals directly. The design below keeps both models in
  view.
- **B. Copy username and Open website ship in Phase 1.** Copying passwords
  and codes waits for the written clipboard policy (Phase 3).
- **C. The window opens with search focused.**

## Authorization modes: design for unlock sessions now

The [unlock-session work](SEP-UNLOCK-SESSION-KERNEL-GAPS.md) moves Keychain
toward the macOS Passwords model. Touch or the account password unlocks
the app once. Reveals then go through the enclave without new prompts until
idle timeout, the hard maximum, explicit lock, app close, screen lock,
suspend or logout. Passkey assertions still need fresh verification every
time. The overhaul should avoid hard-coding "every reveal asks for a
fingerprint" into the layout. Later, that would mean a second redesign.

**Contract.** The controller adds one field to the snapshot:
`auth: { mode: "per-operation" | "locked" | "unlocked", method?, endsAt? }`.
Today it always reports `per-operation`. The QML decides every
authorization-related label, glyph and state from this field and never
infers them. The GUI does not own the session's lifetime: the
broker/kernel enforce it, and the GUI reflects what they report. As the
kernel doc requires, background code refresh and timers must not count as
user activity.

| Element | Per-operation (today) | Locked | Unlocked |
|---|---|---|---|
| Content area | Normal browsing | Unlock view (below) | Normal browsing |
| Primary action | "Reveal password · fingerprint ⏎" | "Unlock ⏎" | "Reveal password ⏎" |
| Field pending text | "Waiting for fingerprint…" | — | "Revealing…" (after 1 s) |
| Row protection glyph | Fingerprint glyph on protected rows | Hidden | Hidden (everything is behind the session) |
| Top bar | — | Lock glyph (static) | **Lock button** (open-lock glyph, `Ctrl+L`), tooltip "Lock · idle lock in 4 min" |
| Sidebar footer | "Refreshed 2 min ago" | — | Adds "Unlocked · locks after 5 min idle" |
| Passkey rows | "Use this passkey from your browser." | same | same, plus "Each use asks for your fingerprint." |
| Reveal lifetime | "Hides in 24 s" | — | Same 30 s field hide; a session doesn't keep a value on screen longer |

**Unlock view.** This follows Folio's dialog grammar, but fills the content
area instead of floating over it, so locked metadata can't show through a
scrim. It has a centred 72-pixel fingerprint glyph (stroke 1.2), the title
"Keychain is locked" (16, demi-bold, bright) and one secondary line, "Touch
the sensor or enter your password". Below those sit a `PlainField`
password field and a primary "Unlock ⏎" button. The password field clears
every time the view appears or disappears, as Folio's `MountPrompt` does.
A failed attempt shows red text under the field, and focus stays in the
field. The fingerprint attempt is offered automatically only when the
window is active. It never starts while the window is in the background,
which matches the current focus policy. Locking hides every revealed value
and the details immediately, and it doesn't animate.

**Decided (2026-11-14): a locked app shows nothing.** No sites, accounts,
counts or category totals appear until unlock, as in macOS Passwords. This
requires the metadata index to be readable only after unlock, which is a
broker change that ships with the session milestone. Until then,
per-operation mode keeps today's metadata browsing. The `locked` mode in
the GUI must still be built to render nothing but the unlock view, so the
broker change only removes data and never requires a GUI change.

**What to build now (Phase 0/2), so the switch is a backend change:**
- Add the `auth` snapshot field, fixed at `per-operation`, and route every
  "fingerprint" string and glyph through it.
- Build `UnlockView` and the lock button behind the `locked`/`unlocked`
  modes, and exercise them in `smoke.qml` with a synthetic controller state.
  They're not reachable in production until the broker reports them.
- Add `Ctrl+L` (lock) to the shortcut sheet only when the mode is
  `unlocked`.

## Order of work

Phase 0 is required first, because the list model, the component split
and the `auth` field make everything else smaller. After that, Phases 1
and 2 can ship together in roughly four commits: interaction, top bar +
sidebar, rows + details, banner + empty states + responsive. The unlock
view and lock button follow as a fifth, test-only commit. Copying
passwords and codes waits for the clipboard policy. Refresh
`desktop/preview.png` and `docs/DESKTOP-UI.md` with each visible step.
