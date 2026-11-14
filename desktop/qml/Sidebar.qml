// Rows, keyboard cursor, section label and the corner help button adapted
// from Folio's Sidebar (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import KeychainBackend

// The categories: what the list shows, each with how many it holds for the
// current search. Tab brings the keyboard here as one stop: ↑ ↓ move, ⏎ or →
// choose and hand the keyboard back to the accounts, Escape just goes back.
// In a narrow window it is a rail of glyphs, the names in tooltips.
FocusScope {
    id: sidebar

    // [{key, label, glyph}] from Main, in display order.
    property var categories: []
    property string category: "All"
    property var counts: ({})
    property bool rail: false
    // The footer's quiet status lines, and whether the first is a problem.
    property string status: ""
    property string detail: ""
    property bool trouble: false
    property int cursor: 0
    signal chosen(string key)
    signal finished()
    signal helpRequested()

    implicitWidth: rail ? Theme.rail : Theme.sidebar
    Accessible.role: Accessible.List
    Accessible.name: qsTr("Categories")

    function focusSidebar() {
        cursor = Math.max(0, categories.findIndex(c => c.key === category));
        forceActiveFocus(Qt.TabFocusReason);
    }
    function activate(index) {
        const entry = categories[index];
        if (entry)
            chosen(entry.key);
        finished();
    }
    Keys.onUpPressed: cursor = Math.max(0, cursor - 1)
    Keys.onDownPressed: cursor = Math.min(categories.length - 1, cursor + 1)
    Keys.onReturnPressed: activate(cursor)
    Keys.onEnterPressed: activate(cursor)
    Keys.onSpacePressed: activate(cursor)
    // The way to the accounts: left, when mirrored.
    Keys.onRightPressed: if (!LayoutMirroring.enabled)
        activate(cursor)
    Keys.onLeftPressed: if (LayoutMirroring.enabled)
        activate(cursor)

    Rectangle {
        anchors.fill: parent
        color: Theme.background
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.topMargin: 20
        anchors.leftMargin: sidebar.rail ? 6 : 12
        anchors.rightMargin: sidebar.rail ? 6 : 12
        anchors.bottomMargin: 12
        spacing: 1

        Words {
            visible: !sidebar.rail
            Layout.leftMargin: 14
            Layout.bottomMargin: 6
            text: qsTr("Keychain")
            color: Theme.secondary
            font.pixelSize: Theme.section
            font.letterSpacing: 1.3
            // Uppercase by the font, not the string, so translations stay correct.
            font.capitalization: Font.AllUppercase
        }
        Repeater {
            model: sidebar.categories
            AbstractButton {
                id: row
                required property var modelData
                required property int index
                readonly property bool active: sidebar.category === modelData.key
                readonly property bool keyed: sidebar.activeFocus && sidebar.cursor === index
                readonly property int count: sidebar.counts[modelData.key] || 0

                Layout.fillWidth: true
                implicitHeight: Theme.sidebarRow
                leftPadding: sidebar.rail ? 0 : Theme.inset
                rightPadding: sidebar.rail ? 0 : Theme.inset
                hoverEnabled: true
                focusPolicy: Qt.NoFocus
                text: modelData.label
                Accessible.name: qsTr("%1, %2").arg(modelData.label).arg(count)
                onClicked: {
                    sidebar.cursor = index;
                    sidebar.activate(index);
                }
                ToolTip {
                    visible: sidebar.rail && row.hovered
                    delay: Theme.tooltipDelay
                    text: qsTr("%1 · %2").arg(row.modelData.label).arg(row.count.toLocaleString(Qt.locale(), "f", 0))
                    enter: null
                    exit: null
                }
                background: Rectangle {
                    radius: Theme.rowRadius
                    color: row.active ? Qt.alpha(Theme.accent, 0.16)
                         : row.hovered ? Qt.alpha(Theme.foreground, 0.06)
                         : "transparent"
                    // The keyboard's row: a thin edge, so it never looks like the chosen one.
                    border.width: row.keyed ? 1 : 0
                    border.color: Theme.selectionInk
                }
                contentItem: RowLayout {
                    spacing: 14
                    Item {
                        Layout.fillWidth: sidebar.rail
                        implicitWidth: Theme.icon
                        implicitHeight: Theme.icon
                        Glyph {
                            anchors.centerIn: parent
                            name: row.modelData.glyph
                            color: row.active ? Theme.bright : Theme.foreground
                        }
                    }
                    Words {
                        visible: !sidebar.rail
                        Layout.fillWidth: true
                        text: row.modelData.label
                        color: row.active ? Theme.bright : Theme.foreground
                    }
                    // How many, quietly, in the language's digits.
                    Words {
                        visible: !sidebar.rail
                        text: row.count.toLocaleString(Qt.locale(), "f", 0)
                        color: Theme.secondary
                        font.pixelSize: Theme.section
                    }
                }
            }
        }
        Item {
            Layout.fillHeight: true
        }
        Words {
            visible: !sidebar.rail && sidebar.status.length > 0
            Layout.fillWidth: true
            Layout.leftMargin: 14
            text: sidebar.status
            color: sidebar.trouble ? Theme.red : Theme.secondary
            font.pixelSize: Theme.section
        }
        Words {
            visible: !sidebar.rail && sidebar.detail.length > 0
            Layout.fillWidth: true
            Layout.leftMargin: 14
            Layout.bottomMargin: 10
            text: sidebar.detail
            color: Theme.secondary
            font.pixelSize: Theme.section
        }
        // A quiet ? in the corner, for finding the shortcuts without knowing
        // the key that shows them.
        AbstractButton {
            id: help
            objectName: "help"
            Layout.leftMargin: sidebar.rail ? 0 : 6
            Layout.alignment: sidebar.rail ? Qt.AlignHCenter : Qt.AlignLeft
            implicitWidth: 24
            implicitHeight: 24
            focusPolicy: Qt.NoFocus
            hoverEnabled: true
            text: qsTr("Keyboard shortcuts (?)")
            Accessible.name: text
            onClicked: sidebar.helpRequested()
            ToolTip {
                visible: help.hovered
                delay: Theme.tooltipDelay
                text: help.text
                enter: null
                exit: null
            }
            contentItem: Words {
                text: "?"
                horizontalAlignment: Text.AlignHCenter
                color: help.hovered ? Theme.foreground : Qt.alpha(Theme.secondary, 0.6)
            }
            background: Rectangle {
                radius: width / 2
                color: "transparent"
                border.width: 1
                border.color: help.hovered ? Theme.foreground : Qt.alpha(Theme.secondary, 0.4)
            }
        }
    }
}
