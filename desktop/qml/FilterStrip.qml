import QtQuick
import QtQuick.Layouts
import KeychainBackend

// The categories as a row, for windows too narrow for the sidebar.
RowLayout {
    id: strip

    property var categories: []
    property string category: "All"
    signal chosen(string key)

    spacing: 4
    Repeater {
        model: strip.categories
        NavButton {
            required property var modelData
            text: modelData.short
            selected: strip.category === modelData.key
            onClicked: strip.chosen(modelData.key)
        }
    }
}
