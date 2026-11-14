import QtQuick
import QtQuick.Layouts
import KeychainBackend

// The bar across the top of the window: the title, search and the window's
// own actions, with a hairline under it.
Rectangle {
    id: bar

    property bool loading: false
    readonly property alias field: search
    signal searchEdited(string text)
    signal refreshRequested()
    signal helpRequested()

    implicitHeight: Theme.topBar
    color: Theme.background

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 22
        anchors.rightMargin: 18
        spacing: 14
        Words {
            text: qsTr("Keychain")
            font.weight: Font.DemiBold
            font.pixelSize: Theme.pathTitle
        }
        Item {
            Layout.fillWidth: true
        }
        PlainField {
            id: search
            objectName: "search"
            Layout.preferredWidth: Math.min(320, bar.width * 0.35)
            font.pixelSize: Theme.pathTitle
            placeholderText: qsTr("Search accounts")
            Accessible.name: qsTr("Search accounts")
            onTextChanged: bar.searchEdited(text)
        }
        IconButton {
            glyph: "Refresh"
            text: qsTr("Refresh")
            enabled: !bar.loading
            onClicked: bar.refreshRequested()
        }
        IconButton {
            glyph: "Help"
            text: qsTr("Keyboard shortcuts")
            onClicked: bar.helpRequested()
        }
    }
    Rectangle {
        anchors.bottom: parent.bottom
        width: parent.width
        height: 1
        color: Theme.line
    }
}
