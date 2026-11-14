// Window structure, settling and styling adapted from Folio (MIT).
// Copyright (c) 2026 David Heinemeier Hansson; see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts
import KeychainBackend

// The window: a bar across the top; under it the categories, the accounts
// and the selected account's details. Narrow windows trade the sidebar for a
// strip of categories, then show the accounts or the details, one at a time.
ApplicationWindow {
    id: win
    width: 1200
    height: 760
    minimumWidth: 540
    minimumHeight: 420
    visible: true
    title: qsTr("Keychain")
    font.family: Theme.family
    font.pixelSize: Theme.body

    property QtObject backend: Backend {}
    property var state: JSON.parse(backend.snapshot)
    property var items: JSON.parse(backend.rows)
    onStateChanged: if (!state.selected)
        detailsOpen = false
    readonly property var tokens: state.theme
    Binding {
        target: Theme
        property: "tokens"
        value: win.state.theme
    }
    readonly property var categories: [
        { key: "All", label: qsTr("All items"), short: qsTr("All") },
        { key: "Login", label: qsTr("Logins"), short: qsTr("Logins") },
        { key: "Passkey", label: qsTr("Passkeys"), short: qsTr("Passkeys") },
        { key: "Code", label: qsTr("Codes"), short: qsTr("Codes") }
    ]
    property bool compact: width < 800
    readonly property bool wide: width >= 1000
    property bool detailsOpen: false
    property bool helpOpen: false
    property alias search: topBar.field
    property bool typing: search.activeFocus

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
    Timer {
        id: settleTimer
        interval: 150
        onTriggered: win.settled = true
    }

    function act(action, arg) {
        if (compact && (action === "search" || action === "filter"))
            detailsOpen = false;
        backend.command(action, arg || "");
    }
    function choose(id) {
        act("select", id);
        if (compact)
            detailsOpen = true;
    }
    function dismiss() {
        if (helpOpen)
            helpOpen = false;
        else if (backend.revealed.length || state.busy)
            act("cancel");
        else if (detailsOpen)
            detailsOpen = false;
        else
            search.clear();
    }
    function refreshTheme() {
        act("theme", Qt.styleHints.colorScheme === Qt.ColorScheme.Light ? "light" : "dark");
    }
    Shortcut {
        sequence: "Ctrl+F"
        onActivated: search.forceActiveFocus()
    }
    Shortcut {
        sequence: "Ctrl+K"
        onActivated: search.forceActiveFocus()
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
    Component.onCompleted: {
        act("focus", active ? "true" : "false");
        refreshTheme();
        act("refresh");
    }
    onActiveChanged: act("focus", active ? "true" : "false")
    onClosing: act("cancel")
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
                loading: !!win.state.loading
                onSearchEdited: text => win.act("search", text)
                onRefreshRequested: win.act("refresh")
                onHelpRequested: win.helpOpen = true
            }
            FilterStrip {
                visible: !win.wide
                Layout.fillWidth: true
                Layout.leftMargin: 12
                Layout.topMargin: 8
                Layout.bottomMargin: 8
                categories: win.categories
                category: win.state.category
                onChosen: key => win.act("filter", key)
            }
            RowLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 0
                Sidebar {
                    id: categoryPane
                    visible: win.wide
                    Layout.preferredWidth: Theme.sidebar
                    Layout.minimumWidth: Theme.sidebar
                    Layout.maximumWidth: Theme.sidebar
                    Layout.fillHeight: true
                    categories: win.categories
                    category: win.state.category
                    onChosen: key => win.act("filter", key)
                }
                Rectangle {
                    visible: win.wide
                    Layout.fillHeight: true
                    implicitWidth: 1
                    color: Theme.line
                }
                AccountList {
                    id: credentialPane
                    visible: !win.compact || !win.detailsOpen
                    Layout.minimumWidth: win.compact ? 0 : Theme.credentialPane
                    Layout.maximumWidth: win.compact ? 100000 : Theme.credentialPane
                    Layout.preferredWidth: win.compact ? win.width : Theme.credentialPane
                    Layout.fillWidth: win.compact
                    Layout.fillHeight: true
                    rows: win.items
                    selectedId: win.state.selected ? win.state.selected.id : ""
                    onChosen: key => win.choose(key)
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
                    selected: win.state.selected
                    status: win.state
                    revealed: win.backend.revealed
                    compact: win.compact
                    onAct: (action, arg) => win.act(action, arg)
                    onBack: win.detailsOpen = false
                }
            }
            Words {
                visible: win.state.message.length > 0
                text: win.state.message
                Layout.fillWidth: true
                Layout.margins: 14
                wrapMode: Text.Wrap
                elide: Text.ElideNone
                color: Theme.secondary
                font.pixelSize: Theme.small
            }
        }
    }
    HelpOverlay {
        visible: win.helpOpen
        onClosed: win.helpOpen = false
    }
}
