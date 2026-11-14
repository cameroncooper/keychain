// Adapted from the problems banner in Folio's FolderPane (MIT); see
// ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Layouts
import KeychainBackend

// Problems and slow work are said in the window, under the bar, not
// swallowed. A problem is tinted and marked with a glyph (a theme's "red" can
// be any color), and stays until dismissed. Work that ends within a second, as
// most loads do, never shows at all, so nothing flashes.
Rectangle {
    id: banner

    property string text: ""
    // "error", "notice" or "progress".
    property string tone: "notice"
    property bool dismissable: tone !== "progress"
    signal dismissed()

    // Progress waits; the timer starts when the work does, so updates to its
    // wording don't keep putting it off.
    property bool shown: false
    readonly property bool waiting: tone === "progress" && text.length > 0
    onWaitingChanged: {
        if (!waiting)
            slow.stop();
        else if (!slow.running)
            slow.start();
        shown = false;
    }
    Timer {
        id: slow
        interval: Theme.slowWork
        onTriggered: banner.shown = banner.waiting
    }

    visible: text.length > 0 && (tone !== "progress" || shown)
    implicitHeight: 40
    color: tone === "error" ? Qt.alpha(Theme.red, 0.14) : Qt.alpha(Theme.accent, 0.10)
    Accessible.role: Accessible.AlertMessage
    Accessible.name: text

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 24
        anchors.rightMargin: 12
        spacing: 12
        Glyph {
            visible: banner.tone === "error"
            name: "Alert"
            size: 16
            color: Theme.red
        }
        Words {
            Layout.fillWidth: true
            text: banner.text
            color: Theme.bright
        }
        IconButton {
            visible: banner.dismissable
            focusPolicy: Qt.NoFocus
            implicitWidth: Theme.smallControl
            implicitHeight: Theme.smallControl
            glyphSize: 14
            glyph: "Close"
            text: qsTr("Dismiss (Esc)")
            onClicked: banner.dismissed()
        }
    }
}
