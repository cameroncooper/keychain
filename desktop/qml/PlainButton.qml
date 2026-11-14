// Button geometry and focus ring adapted from Folio (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import KeychainBackend

// An action button: the accent when it's the main choice, red when it erases
// something, quiet otherwise. No ripple, no animation.
AbstractButton {
    id: button

    property bool primary: false
    property bool destructive: false
    readonly property bool filled: primary || destructive
    readonly property color fill: destructive ? Theme.red : Theme.accent

    implicitWidth: Math.max(Theme.actionMinimum, label.implicitWidth + 32)
    implicitHeight: Theme.control
    leftPadding: 16
    rightPadding: 16
    hoverEnabled: true
    Accessible.name: text
    // Tab reaches it; a click acts and leaves the keyboard where it was.
    focusPolicy: Qt.TabFocus
    // Return and Enter press it as Space does, and a button with the keyboard
    // keeps those keys from the window's shortcuts.
    Keys.onShortcutOverride: event => event.accepted = !(event.modifiers & (Qt.ControlModifier | Qt.AltModifier))
                                                       && [Qt.Key_Space, Qt.Key_Return, Qt.Key_Enter].includes(event.key)
    Keys.onReturnPressed: clicked()
    Keys.onEnterPressed: clicked()

    background: Rectangle {
        radius: Theme.rowRadius
        color: button.filled ? (button.hovered ? Qt.lighter(button.fill, 1.08) : button.fill)
             : button.hovered ? Qt.alpha(Theme.foreground, 0.10)
             : Qt.alpha(Theme.foreground, 0.05)
        // A ring clear of the button, so it shows on an accent fill too.
        Rectangle {
            visible: button.activeFocus
            anchors.fill: parent
            anchors.margins: -3
            radius: parent.radius + 3
            color: "transparent"
            border.width: 2
            border.color: button.destructive ? Theme.red : Theme.selectionInk
        }
    }
    contentItem: Words {
        id: label
        text: button.text
        color: button.destructive ? Theme.background : button.primary ? Theme.accentText : Theme.foreground
        font.weight: button.filled ? Font.DemiBold : Font.Normal
        horizontalAlignment: Text.AlignHCenter
    }
}
