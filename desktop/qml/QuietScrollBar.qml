// Adapted from Folio's FolioScrollBar (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import KeychainBackend

// A thin scroll bar that shows while scrolling or hovered, and simply appears
// and disappears: no fading.
ScrollBar {
    id: bar
    padding: 2
    contentItem: Rectangle {
        implicitWidth: 4
        implicitHeight: 4
        radius: Math.min(2, Theme.radius)
        color: Qt.alpha(Theme.foreground, bar.pressed ? 0.5 : 0.28)
        visible: bar.size < 1 && (bar.active || bar.hovered)
    }
    background: null
    // Material fades the bar in and out of its active state; drop that.
    transitions: []
}
