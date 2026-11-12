import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts
import PrototypeBackend

ApplicationWindow {
    id: win
    width: 1200
    height: 760
    minimumWidth: 540
    minimumHeight: 420
    visible: true
    title: qsTr("Keychain Preview")
    font.family: "monospace"
    font.pixelSize: 13
    property QtObject backend: Backend {}
    property var state: JSON.parse(backend.snapshot)
    onStateChanged: if (!state.selected)
        detailsOpen = false
    property var tokens: state.theme
    property color ink: tokens.foreground
    property color accent: tokens.accent
    property color line: Qt.alpha(ink, 0.13)
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
    Component.onCompleted: width = state.previewWidth
    onActiveChanged: if (!active)
        act("cancel")
    Timer {
        interval: 1000
        running: true
        repeat: true
        onTriggered: win.act("theme")
    }
    Timer {
        interval: 10000
        running: backend.revealed.length > 0
        onTriggered: win.act("cancel")
    }

    component Words: Text {
        color: win.ink
        textFormat: Text.PlainText
        font.family: "monospace"
        font.pixelSize: 13
        elide: Text.ElideRight
        verticalAlignment: Text.AlignVCenter
    }
    component QuietButton: AbstractButton {
        id: button
        property bool leading: false
        property bool primary: false
        property bool selected: false
        implicitHeight: 36
        implicitWidth: Math.max(36, caption.implicitWidth + 24)
        hoverEnabled: true
        focusPolicy: Qt.TabFocus
        Accessible.name: text
        background: Rectangle {
            color: button.primary ? win.accent : button.selected ? Qt.alpha(win.accent, 0.16) : button.hovered ? Qt.alpha(win.ink, 0.08) : "transparent"
            border.width: button.activeFocus ? 1 : 0
            border.color: win.accent
            radius: win.tokens.radius
        }
        contentItem: Words {
            id: caption
            text: button.text
            color: button.primary ? win.tokens.onAccent : button.selected ? win.tokens.selectionInk : win.ink
            horizontalAlignment: button.leading ? Text.AlignLeft : Text.AlignHCenter
        }
    }
    component Mark: Canvas {
        property string kind: "Login"
        implicitWidth: 24
        implicitHeight: 24
        onKindChanged: requestPaint()
        Connections {
            target: win
            function onInkChanged() {
                requestPaint();
            }
        }
        onPaint: {
            const c = getContext("2d");
            c.reset();
            c.strokeStyle = win.ink;
            c.lineWidth = 1.5;
            c.beginPath();
            c.arc(10, 10, 6, 0, Math.PI * 2);
            c.stroke();
            if (kind === "Passkey") {
                c.beginPath();
                c.moveTo(14, 14);
                c.lineTo(22, 22);
                c.moveTo(18, 18);
                c.lineTo(21, 15);
                c.stroke();
            } else if (kind === "Code") {
                c.beginPath();
                c.moveTo(10, 6);
                c.lineTo(10, 10);
                c.lineTo(13, 12);
                c.stroke();
            } else {
                c.beginPath();
                c.ellipse(7, 4, 6, 12);
                c.moveTo(4, 10);
                c.lineTo(16, 10);
                c.stroke();
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
                Layout.preferredHeight: 60
                Layout.leftMargin: 22
                Layout.rightMargin: 18
                spacing: 14
                Words {
                    text: qsTr("Keychain")
                    font.weight: Font.DemiBold
                    font.pixelSize: 16
                }
                Item {
                    Layout.fillWidth: true
                }
                TextField {
                    id: search
                    objectName: "search"
                    Layout.preferredWidth: Math.min(320, win.width * 0.35)
                    placeholderText: qsTr("Search accounts")
                    Accessible.name: qsTr("Search accounts")
                    onTextChanged: win.act("search", text)
                    background: Rectangle {
                        color: Qt.alpha(win.ink, 0.05)
                        border.width: search.activeFocus ? 1 : 0
                        border.color: win.accent
                    }
                }
                QuietButton {
                    text: qsTr("Refresh")
                    onClicked: win.act("refresh")
                }
                QuietButton {
                    text: "?"
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
                    Layout.minimumWidth: 190
                    Layout.maximumWidth: 190
                    Layout.preferredWidth: 190
                    Layout.fillHeight: true
                    Layout.topMargin: 24
                    Layout.leftMargin: 12
                    Layout.rightMargin: 12
                    spacing: 4
                    Words {
                        text: qsTr("LIBRARY")
                        color: Qt.alpha(win.ink, 0.65)
                        font.pixelSize: 11
                        font.letterSpacing: 1.3
                        Layout.leftMargin: 12
                        Layout.bottomMargin: 12
                    }
                    Repeater {
                        model: ["All", "Login", "Passkey", "Code"]
                        QuietButton {
                            required property string modelData
                            Layout.fillWidth: true
                            leading: true
                            text: modelData === "All" ? qsTr("All items") : modelData === "Login" ? qsTr("Logins") : modelData === "Passkey" ? qsTr("Passkeys") : qsTr("Codes")
                            selected: win.state.category === modelData
                            onClicked: win.act("filter", modelData)
                        }
                    }
                    Item {
                        Layout.fillHeight: true
                    }
                    Words {
                        text: qsTr("SAMPLE LIBRARY")
                        font.pixelSize: 10
                        color: Qt.alpha(win.ink, 0.6)
                        Layout.leftMargin: 12
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
                    Layout.minimumWidth: win.compact ? 0 : 340
                    Layout.maximumWidth: win.compact ? 100000 : 340
                    Layout.fillHeight: true
                    Layout.fillWidth: win.compact
                    Layout.preferredWidth: win.compact ? win.width : 340
                    spacing: 0
                    Words {
                        text: qsTr("%n accounts", "", win.state.items.length)
                        color: Qt.alpha(win.ink, 0.65)
                        Layout.margins: 20
                        font.pixelSize: 11
                    }
                    ListView {
                        id: accounts
                        objectName: "accounts"
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        model: win.state.items
                        spacing: 2
                        ScrollBar.vertical: ScrollBar {}
                        Keys.onReturnPressed: if (currentItem)
                            win.choose(currentItem.modelData.id)
                        delegate: AbstractButton {
                            id: row
                            required property var modelData
                            required property int index
                            width: ListView.view.width
                            height: 76
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
                                color: win.state.selected && win.state.selected.id === row.modelData.id ? Qt.alpha(win.accent, 0.13) : row.hovered ? Qt.alpha(win.ink, 0.05) : "transparent"
                                border.width: row.activeFocus ? 1 : 0
                                border.color: win.accent
                            }
                            contentItem: RowLayout {
                                anchors.fill: parent
                                anchors.margins: 18
                                spacing: 14
                                Mark {
                                    kind: row.modelData.kind
                                }
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 5
                                    Words {
                                        Layout.fillWidth: true
                                        text: row.modelData.site
                                        color: win.state.selected && win.state.selected.id === row.modelData.id ? win.tokens.selectionInk : win.ink
                                    }
                                    Words {
                                        Layout.fillWidth: true
                                        text: row.modelData.account
                                        font.pixelSize: 11
                                        color: Qt.alpha(win.ink, 0.65)
                                    }
                                }
                                Words {
                                    text: row.modelData.kind
                                    color: Qt.alpha(win.ink, 0.6)
                                    font.pixelSize: 10
                                }
                            }
                        }
                    }
                    Words {
                        visible: !win.state.items.length
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
                        color: Qt.alpha(win.ink, 0.65)
                    }
                    ColumnLayout {
                        visible: !!win.state.selected
                        anchors.fill: parent
                        anchors.margins: 28
                        spacing: 20
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
                                font.pixelSize: 20
                                font.weight: Font.DemiBold
                                text: win.state.selected ? win.state.selected.site : ""
                                wrapMode: Text.Wrap
                                elide: Text.ElideNone
                            }
                        }
                        Words {
                            text: qsTr("ACCOUNT")
                            font.pixelSize: 10
                            color: Qt.alpha(win.ink, 0.6)
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
                                text: win.state.selected && win.state.selected.kind === "Code" ? qsTr("VERIFICATION CODE") : win.state.selected && win.state.selected.kind === "Passkey" ? qsTr("PASSKEY") : qsTr("PASSWORD")
                                font.pixelSize: 10
                                color: Qt.alpha(win.ink, 0.6)
                            }
                            Item {
                                Layout.fillWidth: true
                            }
                            QuietButton {
                                visible: !!win.state.selected && win.state.selected.kind !== "Passkey"
                                text: win.state.busy ? qsTr("Cancel") : backend.revealed.length ? qsTr("Hide") : qsTr("Reveal")
                                onClicked: win.act(win.state.busy || backend.revealed.length ? "cancel" : "reveal")
                            }
                        }
                        Words {
                            Layout.fillWidth: true
                            font.pixelSize: 18
                            wrapMode: Text.WrapAnywhere
                            elide: Text.ElideNone
                            text: !win.state.selected ? "" : win.state.selected.kind === "Passkey" ? qsTr("Use this passkey from your browser.") : backend.revealed.length ? backend.revealed : "••••••••••••"
                        }
                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: 1
                            color: win.line
                        }
                        GridLayout {
                            columns: 2
                            columnSpacing: 32
                            rowSpacing: 18
                            Words {
                                text: qsTr("Saved in")
                                color: Qt.alpha(win.ink, 0.65)
                            }
                            Words {
                                text: win.state.selected ? win.state.selected.storage : ""
                            }
                            Words {
                                text: qsTr("Protection")
                                color: Qt.alpha(win.ink, 0.65)
                            }
                            Words {
                                text: qsTr("Touch ID · preview")
                            }
                        }
                        Words {
                            Layout.fillWidth: true
                            text: win.state.message
                            wrapMode: Text.Wrap
                            elide: Text.ElideNone
                            color: Qt.alpha(win.ink, 0.7)
                            font.pixelSize: 11
                        }
                        Item {
                            Layout.fillHeight: true
                        }
                        Words {
                            Layout.fillWidth: true
                            text: qsTr("Design preview · sample accounts only")
                            color: Qt.alpha(win.ink, 0.55)
                            font.pixelSize: 11
                            wrapMode: Text.Wrap
                        }
                    }
                }
            }
        }
    }
    Popup {
        id: help
        parent: Overlay.overlay
        anchors.centerIn: parent
        width: Math.min(460, win.width - 48)
        height: 300
        padding: 28
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
            spacing: 20
            Words {
                text: qsTr("Keyboard shortcuts")
                font.pixelSize: 17
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
    // Runs through the real Rust adapters and Qt event loop, with synthetic data.
    Component {
        id: disposable
        Backend {}
    }
    property int liveBefore: 0
    property int smokeStep: 0
    function verify(ok, label) {
        if (!ok) {
            console.error("SMOKE FAIL: " + label);
            smoke.stop();
            win.close();
        }
    }
    Timer {
        id: smoke
        interval: 450
        repeat: true
        running: win.state.smoke
        onTriggered: {
            switch (win.smokeStep++) {
            case 0:
                win.verify(win.state.items.length === 6, "initial rows");
                win.verify(win.compact ? credentialPane.width >= win.width - 4 : detailPane.width >= 280 && credentialPane.width <= 360 && (!categoryPane.visible || categoryPane.width <= 220), "pane geometry");
                search.text = "webauthn";
                break;
            case 1:
                win.verify(win.state.items.length === 1, "search");
                search.clear();
                win.act("filter", "Login");
                win.act("reveal");
                win.act("select", "4");
                break;
            case 2:
                win.verify(!backend.revealed.length && !win.state.busy, "stale selected result");
                win.act("reveal");
                win.act("cancel");
                break;
            case 3:
                win.verify(!backend.revealed.length, "cancel");
                win.act("fail-next");
                win.act("reveal");
                break;
            case 4:
                win.verify(!backend.revealed.length && win.state.message.length > 0, "failure");
                win.act("reveal");
                break;
            case 5:
                win.verify(backend.revealed.length > 0, "worker completion");
                win.act("cancel");
                win.act("remove");
                break;
            case 6:
                win.verify(win.state.items.length === 2, "remove");
                win.act("add");
                break;
            case 7:
                win.verify(win.state.items.length === 3, "insert");
                win.act("filter", "All");
                win.act("refresh");
                win.act("select", "1");
                break;
            case 8:
                if (win.compact)
                    win.choose("1");
                win.liveBefore = win.state.liveModels;
                const temporary = disposable.createObject(win);
                temporary.command("reveal", "");
                temporary.destroy();
                break;
            case 9:
                win.act("theme");
                win.verify(win.state.liveModels === win.liveBefore, "QObject destruction with pending work");
                if (win.compact)
                    win.verify(detailPane.width >= win.width - 4 && !credentialPane.visible, "compact details");
                smoke.stop();
                if (win.state.screenshot.length)
                    surface.grabToImage(function (result) {
                        win.verify(result.saveToFile(win.state.screenshot), "screenshot");
                        console.log("SMOKE PASS");
                        win.act("reveal");
                        win.close();
                    });
                else {
                    console.log("SMOKE PASS");
                    win.act("reveal");
                    win.close();
                }
                break;
            }
        }
    }
}
