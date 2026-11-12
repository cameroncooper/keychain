// Control focus and scrollbar styling adapted from Folio (MIT).
// Copyright (c) 2026 David Heinemeier Hansson; see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts
import QtQuick.Shapes
import KeychainBackend

ApplicationWindow {
    id: win
    width: 1200
    height: 760
    minimumWidth: 540
    minimumHeight: 420
    visible: true
    title: qsTr("Keychain")
    font.family: "monospace"
    font.pixelSize: metrics.body
    // Folio 61b7e20 measurements; Keychain-specific dimensions are explicit.
    readonly property QtObject metrics: QtObject {
        readonly property int body: 13
        readonly property int secondary: 12
        readonly property int section: 11
        readonly property int pathTitle: 14
        readonly property int detailTitle: 15
        readonly property int dialogTitle: 16
        readonly property int topBar: 60
        readonly property int sidebar: 190
        readonly property int sidebarRow: 34
        readonly property int control: 36
        readonly property int actionMinimum: 88
        readonly property int icon: 18
        readonly property real iconStroke: 1.6
        readonly property int inset: 14
        readonly property int detailInset: 28
        readonly property int detailGap: 22
        readonly property int credentialRow: 56 // Two lines rather than Folio's 32-pixel file row.
        readonly property int credentialPane: 340
    }
    property QtObject backend: Backend {}
    property var state: JSON.parse(backend.snapshot)
    property var items: JSON.parse(backend.rows)
    onStateChanged: if (!state.selected)
        detailsOpen = false
    property var tokens: state.theme
    property color ink: tokens.foreground
    property color accent: tokens.accent
    property color line: Qt.alpha(ink, 0.12)
    property bool compact: width < 800
    property bool detailsOpen: false
    property bool helpOpen: false
    property bool typing: search.activeFocus
    color: tokens.background
    Material.theme: color.hslLightness > 0.5 ? Material.Light : Material.Dark
    Material.accent: accent
    Material.foreground: ink
    Material.background: tokens.background
    LayoutMirroring.enabled: Qt.application.layoutDirection === Qt.RightToLeft
    LayoutMirroring.childrenInherit: true
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
        act("refresh");
    }
    onActiveChanged: act("focus", active ? "true" : "false")
    onClosing: act("cancel")
    Timer {
        interval: 1000
        running: true
        repeat: true
        onTriggered: win.act("theme", Qt.styleHints.colorScheme === Qt.ColorScheme.Light ? "light" : "dark")
    }
    Timer {
        interval: 100
        running: true
        repeat: true
        onTriggered: win.act("tick")
    }

    component Words: Text {
        color: win.ink
        textFormat: Text.PlainText
        font.family: "monospace"
        font.pixelSize: win.metrics.body
        elide: Text.ElideRight
        verticalAlignment: Text.AlignVCenter
    }
    component QuietButton: AbstractButton {
        id: button
        property bool leading: false
        property bool primary: false
        property bool selected: false
        property bool navigation: false
        property bool toolbar: false
        implicitHeight: navigation ? win.metrics.sidebarRow : win.metrics.control
        implicitWidth: toolbar ? win.metrics.control : navigation ? caption.implicitWidth + 28 : Math.max(win.metrics.actionMinimum, caption.implicitWidth + 32)
        leftPadding: navigation ? win.metrics.inset : toolbar ? 0 : 16
        rightPadding: leftPadding
        hoverEnabled: true
        focusPolicy: Qt.TabFocus
        Accessible.name: text
        Keys.onShortcutOverride: event => {
            if (!(event.modifiers & (Qt.ControlModifier | Qt.AltModifier)) && [Qt.Key_Return, Qt.Key_Enter, Qt.Key_Space].includes(event.key))
                event.accepted = true;
        }
        Keys.onReturnPressed: clicked()
        Keys.onEnterPressed: clicked()
        background: Rectangle {
            color: button.primary ? win.accent : button.selected ? Qt.alpha(win.accent, 0.16) : button.hovered ? Qt.alpha(win.ink, button.navigation ? 0.06 : button.toolbar ? 0.08 : 0.10) : button.navigation || button.toolbar ? "transparent" : Qt.alpha(win.ink, 0.05)
            radius: Math.min(4, win.tokens.radius)
            Rectangle {
                visible: button.activeFocus
                anchors.fill: parent
                anchors.margins: button.navigation ? 0 : -3
                color: "transparent"
                radius: parent.radius + 3
                border.width: button.navigation ? 1 : 2
                border.color: win.tokens.selectionInk
            }
        }
        contentItem: Words {
            id: caption
            text: button.text
            color: button.primary ? win.tokens.onAccent : button.selected ? win.tokens.bright : win.ink
            horizontalAlignment: button.leading ? Text.AlignLeft : Text.AlignHCenter
        }
    }
    component ToolbarAction: QuietButton {
        id: action
        property string glyph
        toolbar: true
        contentItem: Item {
            Mark {
                anchors.centerIn: parent
                kind: action.glyph
            }
        }
        ToolTip {
            visible: action.hovered
            delay: 600
            text: action.text
            enter: null
            exit: null
        }
    }
    component Mark: Item {
        id: mark
        property string kind: "Login"
        implicitWidth: win.metrics.icon
        implicitHeight: win.metrics.icon
        readonly property string drawing: kind === "Passkey" ? "M13 8a5 5 0 1 0-10 0a5 5 0 1 0 10 0M11.5 11.5L22 22M18 18L21 15" : kind === "Code" ? "M21 12a9 9 0 1 0-18 0a9 9 0 1 0 18 0M12 6V12L16 14" : kind === "Refresh" ? "M20 7a8 8 0 1 0 0 10M14 7H20V1" : kind === "Help" ? "M8 8a4 4 0 1 1 4 4V15M12 19V20" : "M21 12a9 9 0 1 0-18 0a9 9 0 1 0 18 0M15 12a3 9 0 1 0-6 0a3 9 0 1 0 6 0M3 12H21"
        Shape {
            anchors.fill: parent
            preferredRendererType: Shape.CurveRenderer
            ShapePath {
                strokeColor: win.ink
                fillColor: "transparent"
                strokeWidth: win.metrics.iconStroke
                capStyle: win.tokens.radius > 0 ? ShapePath.RoundCap : ShapePath.SquareCap
                joinStyle: win.tokens.radius > 0 ? ShapePath.RoundJoin : ShapePath.MiterJoin
                scale: Qt.size(mark.width / 24, mark.height / 24)
                PathSvg {
                    path: mark.drawing
                }
            }
        }
    }
    Rectangle {
        id: surface
        anchors.fill: parent
        color: win.color
        ColumnLayout {
            anchors.fill: parent
            spacing: 0
            RowLayout {
                Layout.fillWidth: true
                Layout.preferredHeight: win.metrics.topBar
                Layout.leftMargin: 22
                Layout.rightMargin: 18
                spacing: 14
                Words {
                    text: qsTr("Keychain")
                    font.weight: Font.DemiBold
                    font.pixelSize: win.metrics.pathTitle
                }
                Item {
                    Layout.fillWidth: true
                }
                TextField {
                    id: search
                    objectName: "search"
                    Layout.preferredWidth: Math.min(320, win.width * 0.35)
                    font.family: "monospace"
                    font.pixelSize: win.metrics.pathTitle
                    color: win.ink
                    placeholderTextColor: win.tokens.secondary
                    selectionColor: win.accent
                    selectedTextColor: win.tokens.onAccent
                    placeholderText: qsTr("Search accounts")
                    Accessible.name: qsTr("Search accounts")
                    onTextChanged: win.act("search", text)
                    background: Rectangle {
                        color: Qt.alpha(win.ink, 0.05)
                        border.width: search.activeFocus ? 1 : 0
                        border.color: win.accent
                    }
                }
                ToolbarAction {
                    glyph: "Refresh"
                    text: qsTr("Refresh")
                    enabled: !win.state.loading
                    onClicked: win.act("refresh")
                }
                ToolbarAction {
                    glyph: "Help"
                    text: qsTr("Keyboard shortcuts")
                    onClicked: win.helpOpen = true
                }
            }
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: 1
                color: win.line
            }
            RowLayout {
                Layout.fillWidth: true
                visible: win.width < 1000
                spacing: 4
                Layout.leftMargin: 12
                Layout.topMargin: 8
                Layout.bottomMargin: 8
                Repeater {
                    model: ["All", "Login", "Passkey", "Code"]
                    QuietButton {
                        required property string modelData
                        navigation: true
                        text: modelData === "All" ? qsTr("All") : modelData === "Login" ? qsTr("Logins") : modelData === "Passkey" ? qsTr("Passkeys") : qsTr("Codes")
                        selected: win.state.category === modelData
                        onClicked: win.act("filter", modelData)
                    }
                }
            }
            RowLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 0
                ColumnLayout {
                    id: categoryPane
                    visible: win.width >= 1000
                    Layout.minimumWidth: win.metrics.sidebar
                    Layout.maximumWidth: win.metrics.sidebar
                    Layout.preferredWidth: win.metrics.sidebar
                    Layout.fillHeight: true
                    Layout.topMargin: 20
                    spacing: 1
                    Words {
                        text: qsTr("LIBRARY")
                        color: win.tokens.secondary
                        font.letterSpacing: 1.3
                        font.pixelSize: win.metrics.section
                        Layout.leftMargin: 26
                        Layout.bottomMargin: 6
                    }
                    Repeater {
                        model: ["All", "Login", "Passkey", "Code"]
                        QuietButton {
                            required property string modelData
                            Layout.fillWidth: true
                            leading: true
                            navigation: true
                            Layout.leftMargin: 12
                            Layout.rightMargin: 12
                            text: modelData === "All" ? qsTr("All items") : modelData === "Login" ? qsTr("Logins") : modelData === "Passkey" ? qsTr("Passkeys") : qsTr("Codes")
                            selected: win.state.category === modelData
                            onClicked: win.act("filter", modelData)
                        }
                    }
                    Item {
                        Layout.fillHeight: true
                    }
                    Words {
                        text: qsTr("LOCAL INVENTORY")
                        font.pixelSize: win.metrics.section
                        color: win.tokens.secondary
                        Layout.leftMargin: 26
                        Layout.bottomMargin: 20
                    }
                }
                Rectangle {
                    visible: win.width >= 1000
                    Layout.fillHeight: true
                    implicitWidth: 1
                    color: win.line
                }
                ColumnLayout {
                    id: credentialPane
                    visible: !win.compact || !win.detailsOpen
                    Layout.minimumWidth: win.compact ? 0 : win.metrics.credentialPane
                    Layout.maximumWidth: win.compact ? 100000 : win.metrics.credentialPane
                    Layout.fillHeight: true
                    Layout.fillWidth: win.compact
                    Layout.preferredWidth: win.compact ? win.width : win.metrics.credentialPane
                    spacing: 0
                    Words {
                        text: qsTr("%n accounts", "", win.items.length)
                        color: win.tokens.secondary
                        Layout.leftMargin: win.metrics.inset
                        Layout.rightMargin: win.metrics.inset
                        Layout.topMargin: 12
                        Layout.bottomMargin: 12
                        font.pixelSize: win.metrics.secondary
                    }
                    ListView {
                        id: accounts
                        objectName: "accounts"
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        model: win.items
                        spacing: 0
                        ScrollBar.vertical: ScrollBar {
                            id: bar
                            padding: 2
                            contentItem: Rectangle {
                                implicitWidth: 4
                                implicitHeight: 4
                                radius: Math.min(2, win.tokens.radius)
                                color: Qt.alpha(win.ink, bar.pressed ? 0.5 : 0.28)
                                visible: bar.size < 1 && (bar.active || bar.hovered)
                            }
                            background: null
                            transitions: []
                        }
                        Keys.onReturnPressed: if (currentItem)
                            win.choose(currentItem.modelData.id)
                        delegate: AbstractButton {
                            id: row
                            required property var modelData
                            required property int index
                            width: ListView.view.width
                            height: win.metrics.credentialRow
                            hoverEnabled: true
                            focusPolicy: Qt.TabFocus
                            Accessible.name: modelData.site + " " + modelData.account
                            onClicked: {
                                accounts.currentIndex = index;
                                win.choose(modelData.id);
                            }
                            onActiveFocusChanged: if (activeFocus)
                                accounts.currentIndex = index
                            Keys.onReturnPressed: win.choose(modelData.id)
                            background: Rectangle {
                                x: 4
                                width: parent.width - 8
                                radius: Math.min(4, win.tokens.radius)
                                color: win.state.selected && win.state.selected.id === row.modelData.id ? Qt.alpha(win.accent, 0.18) : row.hovered ? Qt.alpha(win.ink, 0.05) : "transparent"
                                border.width: row.activeFocus ? 1 : 0
                                border.color: win.accent
                            }
                            contentItem: RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: win.metrics.inset
                                anchors.rightMargin: win.metrics.inset
                                anchors.topMargin: 8
                                anchors.bottomMargin: 8
                                spacing: 12
                                Mark {
                                    kind: row.modelData.kind
                                }
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 4
                                    Words {
                                        Layout.fillWidth: true
                                        text: row.modelData.site
                                        color: win.state.selected && win.state.selected.id === row.modelData.id ? win.tokens.selectionInk : win.ink
                                    }
                                    Words {
                                        Layout.fillWidth: true
                                        text: row.modelData.account
                                        font.pixelSize: win.metrics.secondary
                                        color: win.tokens.secondary
                                    }
                                }
                                Words {
                                    text: row.modelData.kind
                                    color: win.tokens.secondary
                                    font.pixelSize: win.metrics.secondary
                                }
                            }
                        }
                    }
                    Words {
                        visible: !win.items.length
                        text: qsTr("No matching accounts")
                        Layout.margins: 24
                    }
                }
                Rectangle {
                    visible: !win.compact
                    Layout.fillHeight: true
                    implicitWidth: 1
                    color: win.line
                }
                Rectangle {
                    id: detailPane
                    visible: !win.compact || win.detailsOpen
                    Layout.minimumWidth: win.compact ? 0 : 280
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    color: win.tokens.detail
                    Words {
                        anchors.centerIn: parent
                        visible: !win.state.selected
                        text: qsTr("Select an account")
                        color: win.tokens.secondary
                    }
                    ScrollView {
                        id: detailScroll
                        visible: !!win.state.selected
                        anchors.fill: parent
                        anchors.margins: win.metrics.detailInset
                        clip: true
                        contentWidth: availableWidth
                        ColumnLayout {
                            width: detailScroll.availableWidth
                            spacing: win.metrics.detailGap
                            QuietButton {
                                visible: win.compact
                                text: qsTr("← Accounts")
                                onClicked: win.detailsOpen = false
                            }
                            RowLayout {
                                visible: !!win.state.selected
                                spacing: 14
                                Mark {
                                    kind: win.state.selected ? win.state.selected.kind : "Login"
                                }
                                Words {
                                    Layout.fillWidth: true
                                    font.pixelSize: win.metrics.detailTitle
                                    font.weight: Font.DemiBold
                                    text: win.state.selected ? win.state.selected.site : ""
                                    wrapMode: Text.Wrap
                                    elide: Text.ElideNone
                                }
                            }
                            Words {
                                text: qsTr("Account")
                                font.pixelSize: win.metrics.secondary
                                color: win.tokens.secondary
                            }
                            Words {
                                Layout.fillWidth: true
                                text: win.state.selected ? win.state.selected.account : ""
                                wrapMode: Text.WrapAnywhere
                                elide: Text.ElideNone
                            }
                            Rectangle {
                                Layout.fillWidth: true
                                implicitHeight: 1
                                color: win.line
                            }
                            RowLayout {
                                Layout.fillWidth: true
                                Words {
                                    text: win.state.selected && win.state.selected.kind === "Passkey" ? qsTr("Passkey") : qsTr("Password")
                                    font.pixelSize: win.metrics.secondary
                                    color: win.tokens.secondary
                                }
                                Item {
                                    Layout.fillWidth: true
                                }
                                QuietButton {
                                    visible: !!win.state.selected && win.state.selected.password
                                    text: win.state.busy ? qsTr("Cancel") : win.state.revealedField === "password" ? qsTr("Hide") : qsTr("Reveal")
                                    onClicked: win.act(win.state.busy || win.state.revealedField === "password" ? "cancel" : "reveal", "password")
                                }
                            }
                            Words {
                                Layout.fillWidth: true
                                font.pixelSize: 18
                                wrapMode: Text.WrapAnywhere
                                elide: Text.ElideNone
                                text: !win.state.selected ? "" : win.state.selected.kind === "Passkey" ? qsTr("Use this passkey from your browser.") : win.state.revealedField === "password" ? backend.revealed : "••••••••••••"
                            }
                            Rectangle {
                                Layout.fillWidth: true
                                implicitHeight: 1
                                color: win.line
                            }
                            Repeater {
                                model: [
                                    {
                                        field: "totp",
                                        label: qsTr("Verification code")
                                    },
                                    {
                                        field: "notes",
                                        label: qsTr("Notes")
                                    }
                                ]
                                ColumnLayout {
                                    required property var modelData
                                    visible: !!win.state.selected && !!win.state.selected[modelData.field]
                                    Layout.fillWidth: true
                                    spacing: 12
                                    RowLayout {
                                        Layout.fillWidth: true
                                        Words {
                                            text: modelData.label
                                            color: win.tokens.secondary
                                            font.pixelSize: win.metrics.secondary
                                        }
                                        Item {
                                            Layout.fillWidth: true
                                        }
                                        QuietButton {
                                            text: win.state.busy ? qsTr("Cancel") : win.state.revealedField === modelData.field ? qsTr("Hide") : qsTr("Reveal")
                                            onClicked: win.act(win.state.busy || win.state.revealedField === modelData.field ? "cancel" : "reveal", modelData.field)
                                        }
                                    }
                                    Words {
                                        Layout.fillWidth: true
                                        text: win.state.revealedField === modelData.field ? backend.revealed : "••••••••••••"
                                        wrapMode: Text.WrapAnywhere
                                        elide: Text.ElideNone
                                    }
                                }
                            }
                            GridLayout {
                                Layout.fillWidth: true
                                Layout.minimumWidth: 0
                                columns: 2
                                columnSpacing: 16
                                rowSpacing: 12
                                Words {
                                    text: qsTr("Website")
                                    color: win.tokens.secondary
                                }
                                Words {
                                    Layout.fillWidth: true
                                    text: win.state.selected ? win.state.selected.domain : ""
                                    wrapMode: Text.WrapAnywhere
                                    elide: Text.ElideNone
                                }
                                Words {
                                    text: qsTr("Saved in")
                                    color: win.tokens.secondary
                                }
                                Words {
                                    Layout.fillWidth: true
                                    text: win.state.selected ? win.state.selected.storage : ""
                                    wrapMode: Text.Wrap
                                    elide: Text.ElideNone
                                }
                                Words {
                                    text: qsTr("Protection")
                                    color: win.tokens.secondary
                                }
                                Words {
                                    Layout.fillWidth: true
                                    text: win.state.selected ? win.state.selected.protection : ""
                                    wrapMode: Text.Wrap
                                    elide: Text.ElideNone
                                }
                            }
                            Item {
                                Layout.fillHeight: true
                            }
                            Words {
                                Layout.fillWidth: true
                                text: qsTr("Secrets hide when you leave Keychain or after 30 seconds.")
                                color: win.tokens.secondary
                                font.pixelSize: win.metrics.section
                                wrapMode: Text.Wrap
                            }
                        }
                    }
                }
            }
            Words {
                visible: win.state.message.length > 0
                text: win.state.message
                Layout.fillWidth: true
                Layout.margins: 14
                wrapMode: Text.Wrap
                elide: Text.ElideNone
                color: win.tokens.secondary
                font.pixelSize: win.metrics.secondary
            }
        }
    }
    Popup {
        id: help
        parent: Overlay.overlay
        anchors.centerIn: parent
        width: Math.min(460, win.width - 48)
        height: 300
        padding: win.metrics.detailInset
        visible: win.helpOpen
        modal: true
        focus: true
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        onClosed: win.helpOpen = false
        Overlay.modal: Rectangle {
            color: "#b0000000"
        }
        background: Rectangle {
            color: win.tokens.background
            border.width: 1
            border.color: win.accent
        }
        contentItem: ColumnLayout {
            spacing: 16
            Words {
                text: qsTr("Keyboard shortcuts")
                font.pixelSize: win.metrics.dialogTitle
            }
            Words {
                text: qsTr("Ctrl+F / Ctrl+K    Search")
            }
            Words {
                text: qsTr("Tab / Shift+Tab   Move focus")
            }
            Words {
                text: qsTr("Enter             Open account")
            }
            Words {
                text: qsTr("Escape            Hide / cancel / back")
            }
            QuietButton {
                text: qsTr("Close")
                onClicked: win.helpOpen = false
            }
        }
    }
}
