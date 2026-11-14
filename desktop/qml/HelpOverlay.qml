import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import KeychainBackend

// Every shortcut, one keypress away (?).
Popup {
    id: help

    parent: Overlay.overlay
    anchors.centerIn: parent
    width: Math.min(460, parent ? parent.width - 48 : 460)
    height: 300
    padding: Theme.detailInset
    modal: true
    focus: true
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
    Overlay.modal: Rectangle {
        color: "#b0000000"
    }
    background: Rectangle {
        color: Theme.background
        border.width: 1
        border.color: Theme.accent
        radius: Theme.radius
    }
    contentItem: ColumnLayout {
        spacing: 16
        Words {
            text: qsTr("Keyboard shortcuts")
            font.pixelSize: Theme.dialogTitle
        }
        Words {
            text: qsTr("Ctrl+F / Ctrl+K    Search")
        }
        Words {
            text: qsTr("Tab / Shift+Tab   Move focus")
        }
        Words {
            text: qsTr("Enter             Open account")
        }
        Words {
            text: qsTr("Escape            Hide / cancel / back")
        }
        PlainButton {
            text: qsTr("Close")
            onClicked: help.close()
        }
    }
}
