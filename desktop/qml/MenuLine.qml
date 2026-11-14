// Adapted from Folio's MenuLine (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import KeychainBackend

// A thin rule between groups of menu entries, with little room around it.
MenuSeparator {
    property bool shown: true
    visible: shown
    height: shown ? implicitHeight : 0
    topPadding: 4
    bottomPadding: 4
    contentItem: Rectangle {
        implicitWidth: 200
        implicitHeight: 1
        color: Theme.line
    }
}
