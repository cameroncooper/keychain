// Window structure, keyboard regions, settling and styling adapted from
// Folio (MIT). Copyright (c) 2026 David Heinemeier Hansson; see
// ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts
import KeychainBackend

// The window: a bar across the top that says where you are; under it the
// categories, the accounts and the selected account's details. A narrow
// window keeps the categories as a rail of glyphs and shows the accounts or
// the details, one at a time.
//
// The keyboard moves between three regions with Tab: the categories, the
// accounts and the details. The window opens in search; ↓ or ⏎ goes to the
// results. ⏎ on an account runs the main action its details show. Escape
// stops, hides, dismisses and goes back, one step at a time.
ApplicationWindow {
    id: win
    width: 1200
    height: 760
    minimumWidth: 480
    minimumHeight: 420
    visible: true
    title: qsTr("Keychain")
    font.family: Theme.family
    font.pixelSize: Theme.body

    property QtObject backend: Backend {}
    property var state: JSON.parse(backend.snapshot)
    property var items: JSON.parse(backend.rows)
    readonly property var tokens: state.theme
    Binding {
        target: Theme
        property: "tokens"
        value: win.state.theme
    }
    // Every reveal asks the broker today. Unlock sessions will report
    // "locked" and "unlocked"; the window follows what it's told.
    property string authMode: (state.auth && state.auth.mode) || "per-operation"
    readonly property bool locked: authMode === "locked"
    readonly property var selected: locked ? null : state.selected
    readonly property var counts: state.counts || ({})

    readonly property var categories: [
        {
            key: "All",
            label: qsTr("All items"),
            glyph: "All"
        },
        {
            key: "Login",
            label: qsTr("Logins"),
            glyph: "Login"
        },
        {
            key: "Passkey",
            label: qsTr("Passkeys"),
            glyph: "Passkey"
        },
        {
            key: "Code",
            label: qsTr("Codes"),
            glyph: "Code"
        }
    ]
    readonly property var category: categories.find(c => c.key === state.category) || categories[0]
    readonly property bool compact: width < Theme.wideWindow
    property bool detailsOpen: false
    onCompactChanged: if (!compact)
        detailsOpen = false
    onSelectedChanged: if (!selected)
        detailsOpen = false
    property bool helpOpen: false
    onHelpOpenChanged: if (!helpOpen)
        Qt.callLater(focusList)
    property alias search: topBar.field
    readonly property bool typing: search.activeFocus || unlockView.activeFocus
    readonly property string query: search.text.trim()

    color: Theme.background
    Material.theme: Theme.light ? Material.Light : Material.Dark
    Material.accent: Theme.accent
    Material.foreground: Theme.foreground
    Material.background: Theme.background
    Material.roundedScale: Theme.radius
    LayoutMirroring.enabled: Qt.application.layoutDirection === Qt.RightToLeft
    LayoutMirroring.childrenInherit: true

    // Hyprland sizes a new window only once it's on screen: the first frames
    // are drawn at the size asked for above, then the real size arrives and
    // everything moves. The contents stay hidden until that size is in, or
    // until it's clear none is coming, so they first appear where they'll
    // stay. Until then they take no clicks or keys either.
    property bool settled: false
    property bool drawn: false
    onFrameSwapped: if (!drawn) {
        drawn = true;
        settleTimer.start();
    }
    onWidthChanged: if (drawn)
        settled = true
    onHeightChanged: if (drawn)
        settled = true
    onSettledChanged: if (settled)
        startFocus()
    Timer {
        id: settleTimer
        interval: 150
        onTriggered: win.settled = true
    }

    function act(action, arg) {
        backend.command(action, arg || "");
    }
    function choose(id) {
        act("select", id);
        if (compact)
            openDetails();
    }
    function filter(key) {
        if (compact)
            detailsOpen = false;
        act("filter", key);
    }
    function openDetails() {
        if (!selected)
            return;
        detailsOpen = true;
        Qt.callLater(() => detailPane.focusKeyboard());
    }
    function closeDetails() {
        detailsOpen = false;
        Qt.callLater(focusList);
    }
    function startFocus() {
        if (locked)
            unlockView.forceActiveFocus();
        else
            search.forceActiveFocus();
    }
    function focusList() {
        if (!locked && (!compact || !detailsOpen))
            credentialPane.focusView();
    }
    function focusSearch() {
        if (locked)
            return;
        if (compact)
            detailsOpen = false;
        search.forceActiveFocus();
        search.selectAll();
    }
    // ⏎ on an account: in a wide window, the details' main action; in a
    // narrow one, the details themselves.
    function activate(key) {
        if (key !== (selected && selected.id))
            act("select", key);
        if (compact)
            openDetails();
        else
            detailPane.runPrimary();
    }

    // Tab moves the keyboard between the regions, and through the details'
    // own controls while it is there. Shift+Tab goes back.
    function holds(region, item) {
        for (let at = item; at; at = at.parent)
            if (at === region)
                return true;
        return false;
    }
    function moveKeyboard(step) {
        const here = activeFocusItem;
        if (holds(detailPane, here) && detailPane.step(step > 0))
            return;
        const stops = [categoryPane];
        if (!compact || !detailsOpen)
            stops.push(credentialPane);
        if (selected && (!compact || detailsOpen))
            stops.push(detailPane);
        const at = holds(categoryPane, here) ? 0 : holds(detailPane, here) ? stops.indexOf(detailPane) : stops.indexOf(credentialPane);
        const next = stops[((at < 0 ? 0 : at) + step + stops.length) % stops.length];
        if (next === categoryPane)
            categoryPane.focusSidebar();
        else if (next === detailPane)
            detailPane.focusKeyboard();
        else
            credentialPane.focusView();
    }
    // Escape: one step at a time, from the most urgent.
    function dismiss() {
        if (helpOpen)
            helpOpen = false;
        else if (state.busy || backend.revealed.length)
            act("cancel");
        else if (state.message.length && state.tone !== "progress")
            act("dismiss");
        else if (notice.length)
            notice = "";
        else if (compact && detailsOpen)
            closeDetails();
        else if (search.text.length) {
            search.clear();
            focusList();
        } else
            focusList();
    }

    // A short, local confirmation ("Username copied") in the banner.
    property string notice: ""
    Timer {
        id: noticeTimer
        interval: 3000
        onTriggered: win.notice = ""
    }
    function say(text) {
        notice = text;
        noticeTimer.restart();
    }
    // A username isn't a secret; passwords and codes wait for the clipboard
    // policy (docs/GUI-FOLIO-OVERHAUL-PLAN.md).
    TextEdit {
        id: clipboard
        visible: false
        textFormat: TextEdit.PlainText
    }
    function copyUsername() {
        if (!selected || !selected.account)
            return;
        clipboard.text = selected.account;
        clipboard.selectAll();
        clipboard.copy();
        clipboard.clear();
        say(qsTr("Username copied"));
    }
    // Only a canonical host, and only to the user's own browser; Keychain
    // itself never requests the site.
    function openWebsite() {
        if (selected && detailPane.canOpenWebsite)
            Qt.openUrlExternally("https://" + selected.domain + "/");
    }

    Shortcut {
        sequences: ["/", "Ctrl+F", "Ctrl+K"]
        enabled: !win.typing
        onActivated: win.focusSearch()
    }
    Shortcut {
        sequence: "Escape"
        onActivated: win.dismiss()
    }
    Shortcut {
        sequence: "?"
        enabled: !win.typing
        onActivated: win.helpOpen = !win.helpOpen
    }
    Shortcut {
        sequence: "Q"
        enabled: !win.typing
        onActivated: win.close()
    }
    Shortcut {
        sequence: "Tab"
        enabled: !win.typing && !win.helpOpen && !win.locked
        onActivated: win.moveKeyboard(1)
    }
    Shortcut {
        sequence: "Shift+Backtab"
        enabled: !win.typing && !win.helpOpen && !win.locked
        onActivated: win.moveKeyboard(-1)
    }
    Repeater {
        model: win.categories
        Item {
            required property var modelData
            required property int index
            Shortcut {
                sequence: "Ctrl+" + (index + 1)
                enabled: !win.locked
                onActivated: win.filter(modelData.key)
            }
        }
    }
    Shortcut {
        sequence: "Ctrl+Shift+U"
        enabled: !!win.selected
        onActivated: win.copyUsername()
    }
    Shortcut {
        sequence: "Ctrl+O"
        enabled: !!win.selected
        onActivated: win.openWebsite()
    }
    Shortcut {
        sequences: ["F5", "Ctrl+R"]
        enabled: !win.locked
        onActivated: win.act("refresh")
    }
    Shortcut {
        sequence: "Ctrl+L"
        enabled: win.authMode === "unlocked"
        onActivated: win.act("lock")
    }
    Shortcut {
        sequences: ["Alt+Left", "Back"]
        enabled: win.compact && win.detailsOpen
        onActivated: win.closeDetails()
    }

    // What ? shows: only keys that do something here.
    readonly property var shortcuts: [
        ["/  Ctrl+F", qsTr("Search")],
        ["↓  ⏎", qsTr("From search to the results")],
        ["↑ ↓  Home  End", qsTr("Move through the accounts")],
        ["⏎", qsTr("The account's main action, shown at the bottom of its details")],
        ["Tab  Shift+Tab", qsTr("Categories, accounts and details")],
        ["Ctrl+1 / 2 / 3 / 4", qsTr("All items, logins, passkeys or codes")],
        ["Alt+⏎  Menu", qsTr("The account's menu")],
        ["Ctrl+Shift+U", qsTr("Copy the username")],
        ["Ctrl+O", qsTr("Open the website in your browser")],
        ["F5", qsTr("Reload the accounts on this computer")]
    ].concat(authMode === "unlocked" ? [["Ctrl+L", qsTr("Lock Keychain")]] : []).concat(compact ? [["Alt+←", qsTr("Back to the accounts")]] : []).concat([["Escape", qsTr("Stop, hide, dismiss, go back")], ["?", qsTr("Show these shortcuts")], ["Q", qsTr("Close the window")]])

    Component.onCompleted: {
        act("focus", active ? "true" : "false");
        refreshTheme();
        act("refresh");
    }
    onActiveChanged: act("focus", active ? "true" : "false")
    onClosing: act("cancel")
    function refreshTheme() {
        act("theme", Qt.styleHints.colorScheme === Qt.ColorScheme.Light ? "light" : "dark");
    }
    // The theme and the compositor's rounding are followed while Keychain is
    // in use, and read again the moment it's back.
    Timer {
        interval: 1000
        running: win.active
        repeat: true
        triggeredOnStart: true
        onTriggered: win.refreshTheme()
    }
    Timer {
        interval: 100
        running: true
        repeat: true
        onTriggered: win.act("tick")
    }
    // For "Refreshed 2 min ago".
    property real clock: Date.now() / 1000
    Timer {
        interval: 15000
        running: true
        repeat: true
        onTriggered: win.clock = Date.now() / 1000
    }
    function refreshedText() {
        if (!state.refreshedAt)
            return "";
        const ago = Math.max(0, clock - state.refreshedAt);
        return ago < 60 ? qsTr("Refreshed just now") : ago < 3600 ? qsTr("Refreshed %n min ago", "", Math.floor(ago / 60)) : qsTr("Refreshed at %1").arg(new Date(state.refreshedAt * 1000).toLocaleTimeString(Qt.locale(), Locale.ShortFormat));
    }

    Rectangle {
        id: surface
        anchors.fill: parent
        color: win.color
        enabled: win.settled
        opacity: win.settled ? 1 : 0
        Behavior on opacity {
            NumberAnimation {
                duration: 100
            }
        }

        ColumnLayout {
            anchors.fill: parent
            spacing: 0

            TopBar {
                id: topBar
                Layout.fillWidth: true
                crumbs: {
                    const path = [qsTr("Keychain")];
                    if (win.locked)
                        return path;
                    if (win.category.key !== "All")
                        path.push(win.category.label);
                    if (win.compact && win.detailsOpen && win.selected)
                        path.push(win.selected.site);
                    return path;
                }
                scope: win.category.key === "All" ? qsTr("in all items") : qsTr("in %1").arg(win.category.label.toLowerCase())
                loading: !!win.state.loading
                canGoBack: win.compact && win.detailsOpen
                canSearch: !win.locked
                canRefresh: !win.locked
                showLock: win.authMode === "unlocked"
                onSearchEdited: text => win.act("search", text)
                onToResults: credentialPane.enterFromSearch()
                onCrumbChosen: index => {
                    if (index === 0)
                        win.filter("All");
                    else if (win.detailsOpen)
                        win.closeDetails();
                }
                onBackRequested: win.closeDetails()
                onRefreshRequested: win.act("refresh")
                onLockRequested: win.act("lock")
            }

            Banner {
                id: banner
                Layout.fillWidth: true
                text: win.state.message.length && !(win.state.busy && win.state.tone === "progress") ? win.state.message : win.notice
                tone: win.state.message.length && !(win.state.busy && win.state.tone === "progress") ? win.state.tone : "notice"
                onDismissed: {
                    if (win.state.message.length)
                        win.act("dismiss");
                    else
                        win.notice = "";
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 0
                visible: !win.locked

                Sidebar {
                    id: categoryPane
                    Layout.fillHeight: true
                    Layout.preferredWidth: implicitWidth
                    rail: win.compact
                    categories: win.categories
                    category: win.category.key
                    counts: win.counts
                    status: win.state.refreshedAt ? qsTr("%n items", "", win.counts.All || 0) : win.state.loading ? qsTr("Loading…") : ""
                    detail: {
                        win.clock;
                        if (win.authMode === "unlocked")
                            return win.state.auth.endsAt ? qsTr("Unlocked until %1").arg(new Date(win.state.auth.endsAt * 1000).toLocaleTimeString(Qt.locale(), Locale.ShortFormat)) : qsTr("Unlocked");
                        return win.refreshedText();
                    }
                    onChosen: key => win.filter(key)
                    onFinished: win.focusList()
                    onHelpRequested: win.helpOpen = true
                }
                Rectangle {
                    Layout.fillHeight: true
                    implicitWidth: 1
                    color: Theme.line
                }
                AccountList {
                    id: credentialPane
                    visible: !win.compact || !win.detailsOpen
                    Layout.fillHeight: true
                    Layout.fillWidth: win.compact
                    Layout.preferredWidth: win.compact ? -1 : Theme.credentialPane
                    Layout.maximumWidth: win.compact ? 100000 : Theme.credentialPane
                    rows: win.locked ? [] : win.items
                    selectedId: win.selected ? win.selected.id : ""
                    emptyTitle: {
                        if (!win.state.refreshedAt)
                            return "";
                        if (win.query.length)
                            return qsTr("Nothing matches “%1”").arg(win.query);
                        if (!win.counts.All)
                            return qsTr("Keychain is empty");
                        return win.category.key === "Login" ? qsTr("No logins") : win.category.key === "Passkey" ? qsTr("No passkeys") : qsTr("No codes");
                    }
                    emptyDetail: win.state.refreshedAt && !win.query.length && !win.counts.All ? qsTr("Run “keychain sync” to bring in your iCloud Keychain.") : ""
                    onMoved: key => win.act("select", key)
                    onClicked: key => win.choose(key)
                    onActivated: key => win.activate(key)
                    onMenuRequested: (key, near, at) => accountMenu.show(near, at)
                }
                Rectangle {
                    visible: !win.compact
                    Layout.fillHeight: true
                    implicitWidth: 1
                    color: Theme.line
                }
                DetailPane {
                    id: detailPane
                    visible: !win.compact || win.detailsOpen
                    Layout.minimumWidth: win.compact ? 0 : 280
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    selected: win.selected
                    status: win.state
                    revealed: win.backend.revealed
                    authMode: win.authMode
                    hasAccounts: (win.counts.All || 0) > 0
                    onAct: (action, arg) => win.act(action, arg)
                    onCopyUsername: win.copyUsername()
                    onOpenWebsite: win.openWebsite()
                }
            }

            UnlockView {
                id: unlockView
                objectName: "unlockView"
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: win.locked
                problem: win.state.auth && win.state.auth.problem ? win.state.auth.problem : ""
                onFingerprintRequested: win.act("unlock", "fingerprint")
                // The broker contract decides how a password travels.
                onPasswordSubmitted: win.act("unlock", "password")
            }
        }

        // The account's menu: every action, with the key that does the same.
        KeychainMenu {
            id: accountMenu
            readonly property var item: win.selected
            readonly property string primaryField: detailPane.primaryField
            function show(near, at) {
                if (!item)
                    return;
                if (near)
                    popup(near, Math.min(near.width / 2, 120), near.height / 2);
                else
                    popup(at.x, at.y);
            }
            Repeater {
                model: ["password", "totp", "notes"]
                MenuEntry {
                    required property string modelData
                    shown: !!accountMenu.item && accountMenu.item[modelData] === true
                    text: win.state.revealedField === modelData ? detailPane.hideLabel(modelData) : detailPane.revealLabel(modelData)
                    keys: accountMenu.primaryField === modelData ? "⏎" : ""
                    enabled: !win.state.busy
                    onTriggered: detailPane.toggle(modelData)
                }
            }
            MenuLine {
                shown: !!accountMenu.item && accountMenu.item.kind === "Login"
            }
            MenuEntry {
                text: qsTr("Copy username")
                keys: "Ctrl+Shift+U"
                onTriggered: win.copyUsername()
            }
            MenuEntry {
                text: qsTr("Open website")
                keys: "Ctrl+O"
                enabled: detailPane.canOpenWebsite
                onTriggered: win.openWebsite()
            }
        }

        HelpOverlay {
            id: help
            anchors.fill: parent
            visible: win.helpOpen
            shortcuts: win.shortcuts
            onDismissed: win.helpOpen = false
        }
    }
}
