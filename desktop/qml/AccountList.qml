// Row selection treatment adapted from Folio's FileRow (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import KeychainBackend

// The accounts the search and category leave, metadata only.
ColumnLayout {
    id: pane

    // The backend's rows, a sorted metadata array. Only the differences reach
    // the list model, so typing in search removes and inserts rows instead of
    // rebuilding every delegate, and rows keep their place.
    property var rows: []
    property string selectedId: ""
    readonly property alias view: accounts
    signal chosen(string key)

    spacing: 0

    ListModel {
        id: rowsModel
    }
    onRowsChanged: sync()
    Component.onCompleted: sync()

    function entry(row) {
        return {
            key: row.id,
            site: row.site,
            account: row.account,
            kind: row.kind,
            hasPassword: row.password === true,
            hasCode: row.totp === true,
            hasNotes: row.notes === true,
            protectedItem: row.protected === true
        }
    }
    function same(a, b) {
        for (const role in b)
            if (a[role] !== b[role])
                return false
        return true
    }
    // The backend filters one sorted inventory, so old and new rows share an
    // order: remove what went, then walk both and insert what came. A refresh
    // that reorders (a renamed account) falls back to rebuilding.
    function sync() {
        const wanted = new Set(pane.rows.map(row => row.id))
        for (let i = rowsModel.count - 1; i >= 0; --i)
            if (!wanted.has(rowsModel.get(i).key))
                rowsModel.remove(i)
        const present = new Set()
        for (let i = 0; i < rowsModel.count; ++i)
            present.add(rowsModel.get(i).key)
        let at = 0
        for (const row of pane.rows) {
            const next = entry(row)
            if (at < rowsModel.count && rowsModel.get(at).key === row.id) {
                if (!same(rowsModel.get(at), next))
                    rowsModel.set(at, next)
            } else if (present.has(row.id)) {
                rowsModel.clear()
                for (const all of pane.rows)
                    rowsModel.append(entry(all))
                return
            } else {
                rowsModel.insert(at, next)
            }
            ++at
        }
    }

    Words {
        text: qsTr("%n accounts", "", accounts.count)
        color: Theme.secondary
        font.pixelSize: Theme.small
        Layout.leftMargin: Theme.inset
        Layout.rightMargin: Theme.inset
        Layout.topMargin: 12
        Layout.bottomMargin: 12
    }
    ListView {
        id: accounts
        objectName: "accounts"
        Layout.fillWidth: true
        Layout.fillHeight: true
        clip: true
        model: rowsModel
        boundsBehavior: Flickable.StopAtBounds
        ScrollBar.vertical: QuietScrollBar {}
        Keys.onReturnPressed: if (currentItem)
            pane.chosen(currentItem.key)

        delegate: AbstractButton {
            id: row
            required property int index
            required property string key
            required property string site
            required property string account
            required property string kind
            readonly property bool selected: pane.selectedId === key

            width: ListView.view.width
            height: Theme.credentialRow
            hoverEnabled: true
            focusPolicy: Qt.TabFocus
            Accessible.name: site + " " + account
            onClicked: {
                accounts.currentIndex = index
                pane.chosen(key)
            }
            onActiveFocusChanged: if (activeFocus)
                accounts.currentIndex = index
            Keys.onReturnPressed: pane.chosen(key)

            background: Rectangle {
                x: 4
                width: parent.width - 8
                radius: Theme.rowRadius
                color: row.selected ? Qt.alpha(Theme.accent, 0.18)
                     : row.hovered ? Qt.alpha(Theme.foreground, 0.05)
                     : "transparent"
                border.width: row.activeFocus ? 1 : 0
                border.color: Theme.accent
            }
            contentItem: RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.inset
                anchors.rightMargin: Theme.inset
                anchors.topMargin: 8
                anchors.bottomMargin: 8
                spacing: 12
                Glyph {
                    name: row.kind
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4
                    Words {
                        Layout.fillWidth: true
                        text: row.site
                        color: row.selected ? Theme.selectionInk : Theme.foreground
                    }
                    Words {
                        Layout.fillWidth: true
                        text: row.account
                        font.pixelSize: Theme.small
                        color: Theme.secondary
                    }
                }
                Words {
                    text: row.kind
                    color: Theme.secondary
                    font.pixelSize: Theme.small
                }
            }
        }
    }
    Words {
        visible: accounts.count === 0
        text: qsTr("No matching accounts")
        Layout.margins: 24
    }
}
