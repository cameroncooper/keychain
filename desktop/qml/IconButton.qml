// Toolbar control adapted from Folio's IconButton (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import KeychainBackend

// A square toolbar button holding one glyph. `text` is its accessible name
// and tooltip, never drawn; it names what a click does. Unlike Folio's, it
// stays reachable by Tab (Keychain keeps direct keyboard access to actions).
AbstractButton {
    id: button

    property string glyph
    property bool active: false
    property real glyphSize: Theme.icon

    implicitWidth: Theme.control
    implicitHeight: Theme.control
    focusPolicy: Qt.TabFocus
    hoverEnabled: true
    Accessible.name: text
    Keys.onShortcutOverride: event => event.accepted = !(event.modifiers & (Qt.ControlModifier | Qt.AltModifier))
                                                       && [Qt.Key_Space, Qt.Key_Return, Qt.Key_Enter].includes(event.key)
    Keys.onReturnPressed: clicked()
    Keys.onEnterPressed: clicked()

    // Its own tooltip, so it appears without fading in or out.
    ToolTip {
        visible: button.hovered && button.text.length > 0
        delay: Theme.tooltipDelay
        text: button.text
        enter: null
        exit: null
    }

    background: Rectangle {
        radius: Theme.rowRadius
        color: button.active ? Qt.alpha(Theme.accent, 0.16)
             : button.hovered && button.enabled ? Qt.alpha(Theme.foreground, 0.08)
             : "transparent"
        Rectangle {
            visible: button.activeFocus
            anchors.fill: parent
            anchors.margins: -3
            radius: parent.radius + 3
            color: "transparent"
            border.width: 2
            border.color: Theme.selectionInk
        }
    }
    contentItem: Item {
        Glyph {
            anchors.centerIn: parent
            name: button.glyph
            size: button.glyphSize
            color: !button.enabled ? Qt.alpha(Theme.foreground, 0.35)
                 : button.active ? Theme.bright : Theme.foreground
        }
    }
}
