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
        "Help": "M8 8a4 4 0 1 1 4 4V15M12 19V20"
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
