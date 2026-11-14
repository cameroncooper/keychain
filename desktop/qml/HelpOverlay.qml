// Adapted from Folio's HelpOverlay (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import KeychainBackend

// Every shortcut, one keypress away (?). It has the keyboard while it's
// shown, so the arrows scroll it rather than move through the accounts, and
// Tab stays here rather than reaching a button behind it.
Rectangle {
    id: overlay

    // [[keys, what they do]] from Main, which knows which apply right now.
    property var shortcuts: []
    signal dismissed()

    color: Qt.rgba(0, 0, 0, 0.55)
    focus: visible
    onVisibleChanged: if (visible)
        forceActiveFocus()

    Keys.onPressed: event => {
        if (event.key === Qt.Key_Escape || event.key === Qt.Key_Question) {
            overlay.dismissed();
            event.accepted = true;
            return;
        }
        if (event.key === Qt.Key_Tab || event.key === Qt.Key_Backtab) {
            event.accepted = true;
            return;
        }
        const page = flick.height - 40;
        const by = {
            [Qt.Key_Up]: -40,
            [Qt.Key_Down]: 40,
            [Qt.Key_PageUp]: -page,
            [Qt.Key_PageDown]: page,
            [Qt.Key_Home]: -flick.contentHeight,
            [Qt.Key_End]: flick.contentHeight
        }[event.key];
        if (by === undefined)
            return;
        flick.contentY = Math.max(0, Math.min(flick.contentHeight - flick.height, flick.contentY + by));
        event.accepted = true;
    }

    MouseArea {
        anchors.fill: parent
        onClicked: overlay.dismissed()
    }

    // Sized to what it holds: two pairs a row when the window is wide enough,
    // scrolling when it's too short.
    Rectangle {
        anchors.centerIn: parent
        width: Math.min(parent.width - 64, content.implicitWidth + 56)
        height: Math.min(parent.height - 64, content.implicitHeight + 56)
        color: Theme.background
        border.width: 1
        border.color: Theme.accent
        radius: Theme.radius
        MouseArea {
            anchors.fill: parent
        }

        Flickable {
            id: flick
            anchors.fill: parent
            anchors.margins: Theme.detailInset
            contentWidth: width
            contentHeight: content.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: QuietScrollBar {}

            ColumnLayout {
                id: content
                width: parent.width
                spacing: 14
                Words {
                    text: qsTr("Keyboard shortcuts")
                    color: Theme.bright
                    font.pixelSize: Theme.dialogTitle
                    font.weight: Font.DemiBold
                }
                GridLayout {
                    columns: overlay.width >= 1200 ? 4 : 2
                    rowSpacing: 10
                    columnSpacing: 28
                    // Each key, then what it does: the grid fills in order.
                    Repeater {
                        model: [].concat(...overlay.shortcuts)
                        delegate: Words {
                            required property var modelData
                            required property int index
                            Layout.maximumWidth: index % 2 ? 300 : -1
                            text: index % 2 ? modelData : Theme.keys(modelData)
                            wrapMode: Text.WordWrap
                            elide: Text.ElideNone
                            color: index % 2 ? Theme.foreground : Theme.accent
                        }
                    }
                }
            }
        }
    }
}
