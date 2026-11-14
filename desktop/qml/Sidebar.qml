// Section label and row treatment adapted from Folio's Sidebar (MIT); see
// ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Layouts
import KeychainBackend

// The categories: what the list shows. The chosen one stays lit.
Rectangle {
    id: sidebar

    // [{key, label}] from Main, in display order.
    property var categories: []
    property string category: "All"
    signal chosen(string key)

    color: Theme.background
    implicitWidth: Theme.sidebar

    component SectionLabel: Words {
        Layout.leftMargin: 26
        color: Theme.secondary
        font.pixelSize: Theme.section
        font.letterSpacing: 1.3
        // Uppercase by the font, not the string, so translations stay correct.
        font.capitalization: Font.AllUppercase
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: 20
        spacing: 1
        SectionLabel {
            text: qsTr("Library")
            Layout.bottomMargin: 6
        }
        Repeater {
            model: sidebar.categories
            NavButton {
                required property var modelData
                Layout.fillWidth: true
                Layout.leftMargin: 12
                Layout.rightMargin: 12
                leading: true
                text: modelData.label
                selected: sidebar.category === modelData.key
                onClicked: sidebar.chosen(modelData.key)
            }
        }
        Item {
            Layout.fillHeight: true
        }
        SectionLabel {
            text: qsTr("Local inventory")
            Layout.bottomMargin: 20
        }
    }
}
