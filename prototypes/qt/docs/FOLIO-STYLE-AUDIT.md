# Folio typography and spacing audit

Date: 2026-11-12. Reference: Folio commit
`61b7e20cf0325bae472514b80a8ffdb639e585f8`, checked out locally at
`/home/cameron/Work/folio`.

The initial prototype followed Folio's broad visual direction, but it did not
consistently follow its component measurements. This pass aligns typography,
control geometry, spacing and focus treatment with the current source. Folio's
measurements are application conventions rather than a published Qt-wide design
standard. Keychain-specific differences are retained deliberately below.

## Measurements and corrections

All dimensions are Qt logical pixels, not physical display pixels.

| Element | Folio source | Initial prototype | Current prototype |
| --- | --- | --- | --- |
| Base font | `monospace`, 13; application-level Monospace hint | Window and text components use `monospace`, 13 | Same effective face and size, verified at runtime |
| Search/path text | 14 | Inherited control font | Explicit monospace 14 |
| Top bar | 60 high | 60 | 60 |
| Sidebar width | Preferred 190, with internal insets | 190 plus 24 outside margins | 190 total, with internal 12-pixel row insets |
| Sidebar labels | 11, uppercase, letter spacing 1.3; 6 below | 11, but 12 below | 11, spacing 1.3; 6 below |
| Navigation rows | 34 high; 14 text padding; 1 between rows | 36 high; no text padding; 4 between rows | 34 high; 14 padding; 1 between rows |
| Action buttons | 36 high; minimum width 88 or label + 32 | Generic minimum 36 or label + 24 | Action dimensions match Folio; navigation and toolbar are separate variants |
| Toolbar icon buttons | 36 square, tooltip delay 600 ms | Text buttons with varying widths | 36 square glyph controls, 600 ms tooltips |
| Standard glyphs | Qt Quick Shapes curve renderer, 18, stroke 1.6 on a 24-unit grid | Raster Canvas, 24, stroke 1.5 | Qt Quick Shapes, 18, stroke 1.6; paths scale independently of stroke |
| Detail title | 15, demi-bold | 20 | 15, demi-bold |
| Metadata and field labels | 12 | Mixture of 10 and 11 | 12, with normal-case field labels |
| Detail content | 28 inset; 22 between groups | 28 inset; 20 between groups | 28 inset; 22 between groups |
| Metadata grid | 16 between columns; 12 between rows | 32 and 18 | 16 and 12 |
| Separators | Foreground alpha 0.12 | 0.13 | 0.12 |
| Selected rows | Accent tint; file rows inset 4 horizontally | Full-width background, weaker tint | 4-pixel inset; file-row selection tint 0.18 |
| Secondary text | Foreground mixed 0.68 toward background | Per-widget foreground opacity | Shared derived secondary color |
| Action focus | 2-pixel outer ring, 3-pixel clearance | 1-pixel inner border | Outer ring for actions; inset 1-pixel navigation focus |
| Scrollbar | 4-pixel thumb, 2 padding, no fade | Default Material scrollbar | Folio-style thin scrollbar with no transition |

The centralized `metrics` object in `qml/Main.qml` names these values, so future
components can use the same dimensions rather than introducing unrelated
numbers. Colors continue to come from the shared palette adapter.

## Font verification

A small offscreen Qt probe replicated Folio's actual `QFont("monospace")`,
`QFont::Monospace` style hint, 13-pixel size and application font setup. It resolved
to **JetBrainsMono Nerd Font**, pixel size **13**, fixed pitch, with an `M` advance
of **7.797** logical pixels on this host.

Both Rust bridge smoke runs report the rendered QML face as **JetBrainsMono Nerd
Font**, with body size **13** and search size **14**. The system fontconfig
`monospace` alias also resolves to that family. The font is not hard-coded to
JetBrains: changing the user's monospace alias can select a different face.

Folio sets a global application font. The prototype sets its single
ApplicationWindow font and the text/search component fonts explicitly. This
matches the tested window; it is not a claim that future independent windows or
native dialogs will inherit a global font automatically. Application-wide font
initialization remains part of production frontend integration.

## Intentional differences

- Credential rows are **56 high**, with 13-pixel site text and a 12-pixel account
  line. Folio's file rows are **32 high** and single-line; its own two-line sidebar
  rows are 44. The prototype's previous 76-pixel credential rows were unnecessarily
  tall. Two lines with an 8-pixel vertical inset and 4-pixel gap remain readable
  at 56 without copying a single-line file row's density.
- The credential list remains **340 wide** and details remain flexible. Folio's
  filesystem columns are 260 and its optional preview pane is 300; those widths
  serve different information. Copying them would crowd accounts and credentials.
- Secret/code values remain **18 pixels** for recognition. They are content, not
  metadata headings.
- Toolbar actions remain reachable by Tab. Folio's IconButton uses NoFocus and
  relies on other keyboard routes. Keychain retains direct keyboard access to
  its actions.
- Selection text retains the prototype's contrast fallback, instead of blindly
  applying an accent that becomes unreadable in a light theme.
- The prototype's corner token is still zero, and live Hyprland rounding,
  application-wide font setup, portal appearance and translations remain later
  integration work. This audit does not imply all Omarchy conventions are finished.

## Verification

The existing shared model and lifecycle checks run through both Rust adapters.
Rendered checks additionally assert monospace body 13, search 14, sidebar total
width 190 and credential row height 56. The smoke logs include the resolved font.
Light, dark and narrow renders are inspected and stored alongside this report.
Four model tests, six offscreen UI runs and strict Clippy passed. The CXX-Qt
variant also passed the same smoke sequence with the native Wayland renderer
after the vector-icon change. The previously recorded host-portal app-ID warning
remains. These checks cover visual metrics and geometry; they do not replace input-event
or assistive-technology testing.

## Source references

- [Application font](https://github.com/omacom/folio/blob/61b7e20cf0325bae472514b80a8ffdb639e585f8/src/main.cpp)
- [Window and pane sizing](https://github.com/omacom/folio/blob/61b7e20cf0325bae472514b80a8ffdb639e585f8/src/Main.qml)
- [Sidebar](https://github.com/omacom/folio/blob/61b7e20cf0325bae472514b80a8ffdb639e585f8/src/Sidebar.qml)
- [File rows](https://github.com/omacom/folio/blob/61b7e20cf0325bae472514b80a8ffdb639e585f8/src/FileRow.qml)
- [Detail typography and spacing](https://github.com/omacom/folio/blob/61b7e20cf0325bae472514b80a8ffdb639e585f8/src/PreviewPane.qml)
- [Buttons](https://github.com/omacom/folio/blob/61b7e20cf0325bae472514b80a8ffdb639e585f8/src/PlainButton.qml), [toolbar controls](https://github.com/omacom/folio/blob/61b7e20cf0325bae472514b80a8ffdb639e585f8/src/IconButton.qml), [glyphs](https://github.com/omacom/folio/blob/61b7e20cf0325bae472514b80a8ffdb639e585f8/src/Glyph.qml), [scrollbars](https://github.com/omacom/folio/blob/61b7e20cf0325bae472514b80a8ffdb639e585f8/src/FolioScrollBar.qml)
