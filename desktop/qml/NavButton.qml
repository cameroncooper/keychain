// Navigation row styling adapted from Folio's sidebar (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import KeychainBackend

// A category in the sidebar or the compact filter strip. Selected rows take a
// tint of the accent; the keyboard shows as a thin accent edge inside the row,
// so focus and selection never look the same.
AbstractButton {
    id: button

    property bool selected: false
    property bool leading: false

    implicitHeight: Theme.sidebarRow
    implicitWidth: caption.implicitWidth + 28
    leftPadding: Theme.inset
    rightPadding: Theme.inset
    hoverEnabled: true
    focusPolicy: Qt.TabFocus
    Accessible.name: text
    Keys.onShortcutOverride: event => event.accepted = !(event.modifiers & (Qt.ControlModifier | Qt.AltModifier))
                                                       && [Qt.Key_Space, Qt.Key_Return, Qt.Key_Enter].includes(event.key)
    Keys.onReturnPressed: clicked()
    Keys.onEnterPressed: clicked()

    background: Rectangle {
        radius: Theme.rowRadius
        color: button.selected ? Qt.alpha(Theme.accent, 0.16)
             : button.hovered ? Qt.alpha(Theme.foreground, 0.06)
             : "transparent"
        border.width: button.activeFocus ? 1 : 0
        border.color: Theme.selectionInk
    }
    contentItem: Words {
        id: caption
        text: button.text
        color: button.selected ? Theme.bright : Theme.foreground
        horizontalAlignment: button.leading ? Text.AlignLeft : Text.AlignHCenter
    }
}
