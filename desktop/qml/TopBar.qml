// Breadcrumb, in-place search and toolbar treatment adapted from Folio's
// PathBar (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Layouts
import KeychainBackend

// The bar across the top says where you are (Keychain / Logins / the account
// open in a narrow window), not what app this is. Search replaces that path in
// place while it's in use, and says where it looks at its end. On the right,
// only the window's own actions, as glyphs that name what a click does.
Rectangle {
    id: bar

    property var crumbs: []
    property string scope: ""
    property bool loading: false
    property bool canGoBack: false
    property bool canSearch: true
    property bool canRefresh: true
    property bool showLock: false
    readonly property alias field: search
    readonly property bool searching: search.activeFocus || search.text.length > 0
    signal searchEdited(string text)
    signal toResults()
    signal crumbChosen(int index)
    signal backRequested()
    signal refreshRequested()
    signal lockRequested()

    implicitHeight: Theme.topBar
    color: Theme.background

    // Typing settles for a moment before the list follows it.
    Timer {
        id: searchDelay
        interval: 150
        onTriggered: bar.searchEdited(search.text)
    }
    function flushSearch() {
        if (searchDelay.running) {
            searchDelay.stop();
            bar.searchEdited(search.text);
        }
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: bar.canGoBack ? 12 : 26
        anchors.rightMargin: 18
        spacing: 4

        IconButton {
            // Each has a key of its own; Tab moves between the regions below.
            focusPolicy: Qt.NoFocus
            visible: bar.canGoBack
            glyph: "Back"
            text: qsTr("Back to accounts")
            onClicked: bar.backRequested()
        }
        Item {
            visible: bar.canGoBack
            implicitWidth: 6
        }

        // The path: the last crumb is where you are.
        Row {
            id: path
            visible: !bar.searching || !bar.canSearch
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            clip: true
            spacing: 10
            Repeater {
                model: bar.crumbs
                Row {
                    id: crumb
                    required property string modelData
                    required property int index
                    readonly property bool last: index === bar.crumbs.length - 1
                    spacing: 10
                    Words {
                        visible: crumb.index > 0
                        text: "/"
                        color: Qt.alpha(Theme.foreground, 0.35)
                        font.pixelSize: Theme.pathTitle
                    }
                    Words {
                        text: crumb.modelData
                        width: Math.min(implicitWidth, Math.max(80, bar.width * 0.4))
                        color: crumb.last ? Theme.bright : crumbMouse.containsMouse ? Theme.foreground : Theme.secondary
                        font.pixelSize: Theme.pathTitle
                        font.weight: crumb.last ? Font.DemiBold : Font.Normal
                        MouseArea {
                            id: crumbMouse
                            anchors.fill: parent
                            anchors.margins: -4
                            hoverEnabled: true
                            enabled: !crumb.last
                            cursorShape: Qt.PointingHandCursor
                            onClicked: bar.crumbChosen(crumb.index)
                        }
                    }
                }
            }
        }

        PlainField {
            id: search
            objectName: "search"
            visible: bar.searching && bar.canSearch
            Layout.fillWidth: true
            font.pixelSize: Theme.pathTitle
            placeholderText: qsTr("Search accounts")
            Accessible.name: qsTr("Search accounts")
            // Room at the end for where it searches; padding isn't mirrored.
            leftPadding: LayoutMirroring.enabled ? scopeText.implicitWidth + 24 : 12
            rightPadding: LayoutMirroring.enabled ? 12 : scopeText.implicitWidth + 24
            onTextChanged: searchDelay.restart()
            // Enter, ↓ or Tab go to the results, leaving the search up.
            onAccepted: {
                bar.flushSearch();
                bar.toResults();
            }
            Keys.onDownPressed: {
                bar.flushSearch();
                bar.toResults();
            }
            Keys.onTabPressed: {
                bar.flushSearch();
                bar.toResults();
            }
            // Unlike a placeholder, it stays while typing.
            Words {
                id: scopeText
                anchors.right: parent.right
                anchors.rightMargin: 12
                anchors.verticalCenter: parent.verticalCenter
                text: bar.scope
                color: Theme.secondary
                font.pixelSize: Theme.small
            }
        }

        Item {
            implicitWidth: 16
        }
        IconButton {
            // Each has a key of its own; Tab moves between the regions below.
            focusPolicy: Qt.NoFocus
            visible: bar.canSearch && !bar.searching
            glyph: "Search"
            text: qsTr("Search (/)")
            onClicked: search.forceActiveFocus()
        }
        IconButton {
            // Each has a key of its own; Tab moves between the regions below.
            focusPolicy: Qt.NoFocus
            visible: bar.canRefresh
            glyph: "Refresh"
            text: bar.loading ? qsTr("Refreshing…") : qsTr("Refresh (F5)")
            enabled: !bar.loading
            onClicked: bar.refreshRequested()
        }
        IconButton {
            // Each has a key of its own; Tab moves between the regions below.
            focusPolicy: Qt.NoFocus
            objectName: "lock"
            visible: bar.showLock
            glyph: "Unlocked"
            text: qsTr("Lock Keychain (Ctrl+L)")
            onClicked: bar.lockRequested()
        }
    }
    Rectangle {
        anchors.bottom: parent.bottom
        width: parent.width
        height: 1
        color: Theme.line
    }
}
