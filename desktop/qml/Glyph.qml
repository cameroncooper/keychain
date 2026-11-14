// Vector glyph rendering adapted from Folio (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Shapes
import KeychainBackend

// One family of line icons on a 24-unit grid with one stroke, so the sidebar,
// rows, toolbar and details match. The path is scaled, not the stroke, so lines
// stay crisp at any size. Drawings are embedded: no favicons, no requests.
Item {
    id: glyph

    property string name: "Login"
    property color color: Theme.foreground
    property real size: Theme.icon
    property real stroke: Theme.iconStroke

    implicitWidth: size
    implicitHeight: size

    readonly property var drawings: ({
        "Login": "M21 12a9 9 0 1 0-18 0a9 9 0 1 0 18 0M15 12a3 9 0 1 0-6 0a3 9 0 1 0 6 0M3 12H21",
        "Passkey": "M13 8a5 5 0 1 0-10 0a5 5 0 1 0 10 0M11.5 11.5L22 22M18 18L21 15",
        "Code": "M21 12a9 9 0 1 0-18 0a9 9 0 1 0 18 0M12 6V12L16 14",
        "Refresh": "M20 7a8 8 0 1 0 0 10M14 7H20V1",
        "Help": "M8 8a4 4 0 1 1 4 4V15M12 19V20",
        "All": "M4 6H20M4 12H20M4 18H20",
        "Search": "M17 10.5a6.5 6.5 0 1 0-13 0a6.5 6.5 0 1 0 13 0M15.2 15.2L21 21",
        "Back": "M15 5L8 12L15 19",
        "Forward": "M9 5L16 12L9 19",
        "Eye": "M2 12C5 6.5 8.5 5 12 5S19 6.5 22 12C19 17.5 15.5 19 12 19S5 17.5 2 12ZM15 12a3 3 0 1 0-6 0a3 3 0 1 0 6 0",
        "EyeOff": "M2 12C5 6.5 8.5 5 12 5S19 6.5 22 12C19 17.5 15.5 19 12 19S5 17.5 2 12ZM15 12a3 3 0 1 0-6 0a3 3 0 1 0 6 0M4 4L20 20",
        "Copy": "M9 9H20V20H9ZM15 9V4H4V15H9",
        "Close": "M6 6L18 18M18 6L6 18",
        "Lock": "M5 11H19V21H5ZM8 11V7a4 4 0 0 1 8 0V11",
        "Unlocked": "M5 11H19V21H5ZM8 11V7a4 4 0 0 1 7.5-2",
        "Fingerprint": "M6.5 9.5a5.5 5.5 0 0 1 11 0V12M9.5 20c.9-2 1.3-4.2 1.3-7V10a1.2 1.2 0 0 1 2.4 0V13c0 3.2-.6 5.5-1.6 7.5M15.6 19.8c.9-2.1 1.4-4.4 1.6-6.8M6.5 13c0 2.2-.6 4-1.6 5.4M9 5a7 7 0 0 1 9.5 2.5",
        "Alert": "M21 12a9 9 0 1 0-18 0a9 9 0 1 0 18 0M12 7V13M12 16.5V17",
        "Open": "M14 4H20V10M20 4L11 13M18 14V20H4V6H10"
    })

    Shape {
        anchors.fill: parent
        preferredRendererType: Shape.CurveRenderer
        ShapePath {
            strokeColor: glyph.color
            fillColor: "transparent"
            strokeWidth: glyph.stroke
            // Square ends on square themes, round on rounded ones.
            capStyle: Theme.radius > 0 ? ShapePath.RoundCap : ShapePath.SquareCap
            joinStyle: Theme.radius > 0 ? ShapePath.RoundJoin : ShapePath.MiterJoin
            scale: Qt.size(glyph.width / 24, glyph.height / 24)
            PathSvg {
                path: glyph.drawings[glyph.name] || glyph.drawings.Login
            }
        }
    }
}
