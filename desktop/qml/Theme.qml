// Palette derivation and measurements adapted from Folio (MIT); see
// ../THIRD-PARTY-NOTICES.md.
pragma Singleton
import QtQuick

// The window's one source of color and size. Main binds `tokens` to the
// palette the backend reads (Omarchy's colors.toml, or the Qt-preference
// fallback); everything else here is derived or fixed. Components use these
// names rather than their own numbers, so a measurement changes in one place.
QtObject {
    property var tokens: ({})

    readonly property bool light: tokens.light === true
    readonly property color background: tokens.background || "#16161a"
    // The details surface. Some themes make it the background itself; the
    // hairline between the panes still separates them.
    readonly property color detail: tokens.detail || background
    readonly property color lighter: tokens.lighter || background
    readonly property color foreground: tokens.foreground || "#c8c8d0"
    readonly property color bright: tokens.bright || foreground
    readonly property color secondary: tokens.secondary || foreground
    readonly property color accent: tokens.accent || "#ffd60a"
    // Not "onAccent": QML reads on… names as signal handlers, and the binding
    // would never update (Folio notes the same in its FileMenu).
    readonly property color accentText: tokens.onAccent || "#000000"
    // The accent when it reads on the surface, otherwise the bright foreground.
    readonly property color selectionInk: tokens.selectionInk || accent
    // Theme colors are whatever the theme says; some make "red" teal. Never
    // let color alone say something went wrong: pair it with words or a glyph.
    readonly property color red: tokens.red || "#f7768e"
    readonly property color yellow: tokens.yellow || "#e0af68"
    readonly property color green: tokens.green || "#9ece6a"
    readonly property color blue: tokens.blue || "#7aa2f7"
    readonly property color line: Qt.alpha(foreground, 0.12)
    // The compositor's rounding, capped per element as Folio does.
    readonly property int radius: tokens.radius || 0
    readonly property int rowRadius: Math.min(4, radius)
    readonly property int menuRadius: Math.min(6, radius)

    // Folio 61b7e20 measurements; Keychain-specific dimensions are marked.
    readonly property string family: "monospace"
    readonly property int body: 13
    readonly property int small: 12
    readonly property int section: 11
    readonly property int pathTitle: 14
    readonly property int detailTitle: 15
    readonly property int dialogTitle: 16
    readonly property int secretText: 18 // Keychain: revealed values are content.
    readonly property int topBar: 60
    readonly property int sidebar: 190
    readonly property int sidebarRow: 34
    readonly property int control: 36
    readonly property int actionMinimum: 88
    readonly property int icon: 18
    readonly property real iconStroke: 1.6
    readonly property int inset: 14
    readonly property int detailInset: 28
    readonly property int detailGap: 22
    readonly property int credentialRow: 56 // Keychain: two lines, not a 32-pixel file row.
    readonly property int credentialPane: 340 // Keychain: room for long accounts.
    readonly property int tooltipDelay: 600
    readonly property int rail: 52 // Keychain: the sidebar's glyph-only form.
    readonly property int wideWindow: 960 // Below this, the rail and a list/details stack.
    readonly property int fieldLabel: 104 // Keychain: the details' label column.
    readonly property int smallControl: 28
    // Work that ends within this never shows as progress, so nothing flashes.
    readonly property int slowWork: 1000

    // "Ctrl+Shift+U" reads as "Ctrl + Shift + U", as in Folio's menus and help.
    function keys(text) {
        return text.replace(/(\S)\+(?=\S)/g, "$1 + ")
    }
}
