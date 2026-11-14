// Row selection treatment, cursor handling and the in-place model adapted
// from Folio's FileRow, Selecting and FolderColumns (MIT); see
// ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import KeychainBackend

// The accounts the search and category leave, metadata only. The list is one
// keyboard stop: the arrows move the cursor and the selection follows it
// (selecting shows metadata; it never asks for a fingerprint), ⏎ or a double
// click does the account's main action, and the menu key opens its menu.
FocusScope {
    id: pane

    // The backend's rows, a sorted metadata array. Only the differences reach
    // the list model, so typing in search removes and inserts rows instead of
    // rebuilding every delegate, and rows keep their place.
    property var rows: []
    property string selectedId: ""
    // What the list is empty of, said in its place.
    property string emptyTitle: ""
    property string emptyDetail: ""
    readonly property alias view: accounts
    signal moved(string key)
    signal clicked(string key)
    signal activated(string key)
    signal menuRequested(string key, Item near, point at)

    function focusView() {
        accounts.forceActiveFocus(Qt.TabFocusReason);
    }
    // ↓ from search: the first result, or the selected one if it's there.
    function enterFromSearch() {
        if (pane.indexOf(selectedId) < 0 && rowsModel.count > 0)
            moved(rowsModel.get(0).key);
        focusView();
    }

    ListModel {
        id: rowsModel
    }
    onRowsChanged: sync()
    onSelectedIdChanged: follow()
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
        };
    }
    function same(a, b) {
        for (const role in b)
            if (a[role] !== b[role])
                return false;
        return true;
    }
    function indexOf(key) {
        for (let i = 0; i < rowsModel.count; ++i)
            if (rowsModel.get(i).key === key)
                return i;
        return -1;
    }
    // The backend filters one sorted inventory, so old and new rows share an
    // order: remove what went, then walk both and insert what came. A refresh
    // that reorders (a renamed account) falls back to rebuilding.
    function sync() {
        const wanted = new Set(pane.rows.map(row => row.id));
        for (let i = rowsModel.count - 1; i >= 0; --i)
            if (!wanted.has(rowsModel.get(i).key))
                rowsModel.remove(i);
        const present = new Set();
        for (let i = 0; i < rowsModel.count; ++i)
            present.add(rowsModel.get(i).key);
        let at = 0;
        for (const row of pane.rows) {
            const next = entry(row);
            if (at < rowsModel.count && rowsModel.get(at).key === row.id) {
                if (!same(rowsModel.get(at), next))
                    rowsModel.set(at, next);
            } else if (present.has(row.id)) {
                rowsModel.clear();
                for (const all of pane.rows)
                    rowsModel.append(entry(all));
                break;
            } else {
                rowsModel.insert(at, next);
            }
            ++at;
        }
        follow();
    }
    // The cursor sits on the selected account, wherever search, a category
    // or a refresh has moved it; following doesn't select again.
    property bool following: false
    function follow() {
        following = true;
        accounts.currentIndex = indexOf(selectedId);
        if (accounts.currentIndex >= 0)
            accounts.positionViewAtIndex(accounts.currentIndex, ListView.Contain);
        following = false;
    }
    function moveTo(index) {
        if (rowsModel.count === 0)
            return;
        const at = Math.max(0, Math.min(rowsModel.count - 1, index));
        moved(rowsModel.get(at).key);
    }

    ListView {
        id: accounts
        objectName: "accounts"
        anchors.fill: parent
        anchors.topMargin: 8
        clip: true
        focus: true
        model: rowsModel
        currentIndex: -1
        keyNavigationEnabled: false
        highlightFollowsCurrentItem: false
        boundsBehavior: Flickable.StopAtBounds
        Accessible.role: Accessible.List
        Accessible.name: qsTr("Accounts")
        ScrollBar.vertical: QuietScrollBar {}

        readonly property int page: Math.max(1, Math.floor(height / Theme.credentialRow) - 1)
        Keys.onUpPressed: pane.moveTo(currentIndex < 0 ? 0 : currentIndex - 1)
        Keys.onDownPressed: pane.moveTo(currentIndex + 1)
        // One handler, so Alt+⏎ opens the menu and never also runs ⏎.
        Keys.onPressed: event => {
            if (pane.menuKey(event)) {
                if (currentItem)
                    pane.menuRequested(currentItem.key, currentItem, Qt.point(0, 0));
                event.accepted = true;
                return;
            }
            if (event.modifiers & (Qt.ControlModifier | Qt.AltModifier))
                return;
            if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                if (currentItem)
                    pane.activated(currentItem.key);
                event.accepted = true;
                return;
            }
            const to = {
                [Qt.Key_Home]: 0,
                [Qt.Key_End]: count - 1,
                [Qt.Key_PageUp]: currentIndex - page,
                [Qt.Key_PageDown]: currentIndex + page
            }[event.key];
            if (to === undefined)
                return;
            pane.moveTo(to);
            event.accepted = true;
        }
        // Keeps the menu keys from the window's shortcuts while the list has them.
        Keys.onShortcutOverride: event => event.accepted = pane.menuKey(event)

        delegate: AbstractButton {
            id: row
            required property int index
            required property string key
            required property string site
            required property string account
            required property string kind
            required property bool hasPassword
            required property bool hasCode
            required property bool protectedItem
            readonly property bool selected: pane.selectedId === key
            // A login with only a code reads as a code.
            readonly property string glyph: kind === "Login" && !hasPassword && hasCode ? "Code" : kind

            width: ListView.view.width
            height: Theme.credentialRow
            hoverEnabled: true
            focusPolicy: Qt.NoFocus
            Accessible.role: Accessible.ListItem
            Accessible.name: [site, account, kind === "Passkey" ? qsTr("passkey") : qsTr("login"),
                hasCode ? qsTr("has a verification code") : "",
                protectedItem ? qsTr("fingerprint required") : ""].filter(s => s).join(", ")
            Accessible.selected: selected
            onClicked: {
                accounts.forceActiveFocus(Qt.MouseFocusReason);
                pane.clicked(key);
            }
            onDoubleClicked: pane.activated(key)
            TapHandler {
                acceptedButtons: Qt.RightButton
                onTapped: point => {
                    accounts.forceActiveFocus(Qt.MouseFocusReason);
                    if (!row.selected)
                        pane.moved(row.key);
                    pane.menuRequested(row.key, null, point.scenePosition);
                }
            }

            background: Rectangle {
                x: 4
                width: parent.width - 8
                radius: Theme.rowRadius
                color: row.selected ? Qt.alpha(Theme.accent, 0.18)
                     : row.hovered ? Qt.alpha(Theme.foreground, 0.05)
                     : "transparent"
                // The keyboard's place, distinct from the selection's tint.
                border.width: accounts.activeFocus && row.ListView.isCurrentItem ? 1 : 0
                border.color: Theme.selectionInk
            }
            contentItem: RowLayout {
                anchors.fill: parent
                anchors.leftMargin: Theme.inset
                anchors.rightMargin: Theme.inset
                anchors.topMargin: 8
                anchors.bottomMargin: 8
                spacing: 12
                Glyph {
                    name: row.glyph
                    color: row.selected ? Theme.bright : Theme.foreground
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4
                    Words {
                        Layout.fillWidth: true
                        text: row.site
                        color: row.selected ? Theme.bright : Theme.foreground
                        font.weight: row.selected ? Font.DemiBold : Font.Normal
                    }
                    // Both ends of a long address stay readable.
                    Words {
                        Layout.fillWidth: true
                        text: row.account
                        elide: Text.ElideMiddle
                        font.pixelSize: Theme.small
                        color: Theme.secondary
                    }
                }
                // What the account has, quietly: the names are in the details.
                Glyph {
                    visible: row.hasCode && row.glyph !== "Code"
                    name: "Code"
                    size: 14
                    color: Theme.secondary
                }
                Glyph {
                    visible: row.protectedItem
                    name: "Fingerprint"
                    size: 14
                    color: Theme.secondary
                }
            }
        }
    }

    Column {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top
        anchors.topMargin: 48
        width: parent.width - 48
        visible: accounts.count === 0 && pane.emptyTitle.length > 0
        spacing: 8
        Words {
            width: parent.width
            text: pane.emptyTitle
            color: Theme.secondary
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
        }
        Words {
            width: parent.width
            visible: pane.emptyDetail.length > 0
            text: pane.emptyDetail
            color: Theme.secondary
            font.pixelSize: Theme.small
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
        }
    }

    function menuKey(event) {
        return ((event.key === Qt.Key_Return || event.key === Qt.Key_Enter) && (event.modifiers & Qt.AltModifier)) || event.key === Qt.Key_Menu || (event.key === Qt.Key_F10 && (event.modifiers & Qt.ShiftModifier));
    }
}
