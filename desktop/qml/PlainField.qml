// Adapted from Folio's PlainField (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import KeychainBackend

// A text field with the hint inside it, where it stays. Material would float
// its own placeholder up onto the edge as a label, so that one is hidden and
// this hint takes its place.
TextField {
    id: field

    font.family: Theme.family
    font.pixelSize: Theme.body
    color: Theme.bright
    selectionColor: Theme.accent
    selectedTextColor: Theme.onAccent
    placeholderTextColor: "transparent"
    leftPadding: 12
    rightPadding: 12
    topPadding: 9
    bottomPadding: 9
    background: Rectangle {
        implicitHeight: 38
        radius: Theme.rowRadius
        color: Qt.alpha(Theme.foreground, 0.05)
        border.width: field.activeFocus ? 1 : 0
        border.color: Theme.accent
    }

    Words {
        x: field.leftPadding
        width: field.width - field.leftPadding - field.rightPadding
        anchors.verticalCenter: parent.verticalCenter
        visible: field.length === 0 && field.preeditText.length === 0
        text: field.placeholderText
        color: Theme.secondary
        font: field.font
    }
}
