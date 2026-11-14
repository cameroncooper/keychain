// Adapted from Folio's FolioMenuItem (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import KeychainBackend

// A menu entry: its label, and on the right the key that does the same, so
// the menu also teaches the shortcuts. Highlighted (by pointer or keyboard)
// it takes a tint of the accent; no ripple, no animation.
MenuItem {
    id: entry

    property string keys
    // Hidden entries take no room, and the arrow keys pass over them, so
    // Return can't run one nobody can see.
    property bool shown: true

    hoverEnabled: true
    visible: shown
    height: shown ? implicitHeight : 0
    activeFocusOnTab: shown
    implicitHeight: 32
    leftPadding: 14
    rightPadding: 14

    background: Rectangle {
        implicitWidth: 220
        x: 4
        width: parent.width - 8
        radius: Theme.rowRadius
        color: entry.highlighted && entry.enabled ? Qt.alpha(Theme.accent, 0.18) : "transparent"
    }
    contentItem: Item {
        implicitWidth: label.implicitWidth + hint.implicitWidth + 40
        implicitHeight: label.implicitHeight
        Words {
            id: label
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            text: entry.text
            color: !entry.enabled ? Theme.secondary : entry.highlighted ? Theme.bright : Theme.foreground
        }
        Words {
            id: hint
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            text: Theme.keys(entry.keys)
            color: Theme.secondary
            font.pixelSize: Theme.section
        }
    }
}
