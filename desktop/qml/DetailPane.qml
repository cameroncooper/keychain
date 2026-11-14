// Layout of hero, summary, fact grid and the one pinned action adapted from
// Folio's PreviewPane (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import KeychainBackend

// The selected account: what it is, its fields with their own small actions,
// the facts about where it lives, and one main action at the bottom that ⏎
// also runs. Values reach this pane only through `revealed`, one field at a
// time; the pending, lifetime and fingerprint wording comes from the
// controller's state, never from guessing.
FocusScope {
    id: pane

    property var selected: null
    property var status: ({})
    property string revealed: ""
    property string authMode: "per-operation"
    property bool hasAccounts: false
    signal act(string action, string arg)
    signal copyUsername()
    signal openWebsite()

    readonly property bool busy: status.busy === true
    readonly property string pendingField: status.pendingField || ""
    readonly property string revealedField: status.revealedField || ""
    readonly property bool asksFingerprint: authMode === "per-operation" && !!selected && selected.protected === true
    // The field the main action is about: the password if there is one.
    readonly property string primaryField: !selected ? "" : selected.password ? "password" : selected.totp ? "totp" : selected.notes ? "notes" : ""
    readonly property bool canOpenWebsite: !!selected && /^[a-z0-9.-]+(:[0-9]{1,5})?$/i.test(selected.domain || "")

    // The controls Tab visits here, top to bottom after the main action. Qt's
    // own focus chain wraps inside the pane, so the order is kept explicitly.
    function keyboardStops() {
        const stops = [primary, accountRow.action];
        for (let i = 0; i < secretRows.count; ++i) {
            const row = secretRows.itemAt(i);
            if (row && row.visible)
                stops.push(row.action);
        }
        stops.push(websiteRow.action);
        return stops.filter(stop => stop.visible && stop.enabled);
    }
    function focusKeyboard() {
        const stops = keyboardStops();
        if (stops.length)
            stops[0].forceActiveFocus(Qt.TabFocusReason);
    }
    // Moves to the next control here; false when that leaves the pane.
    function step(forward) {
        const stops = keyboardStops();
        const at = stops.findIndex(stop => stop.activeFocus);
        const next = at + (forward ? 1 : -1);
        if (at < 0 || next < 0 || next >= stops.length)
            return false;
        stops[next].forceActiveFocus(forward ? Qt.TabFocusReason : Qt.BacktabFocusReason);
        return true;
    }
    function fieldLabel(field) {
        return field === "password" ? qsTr("Password") : field === "totp" ? qsTr("Code") : qsTr("Notes");
    }
    function revealLabel(field) {
        return field === "password" ? qsTr("Reveal password") : field === "totp" ? qsTr("Show code") : qsTr("Reveal notes");
    }
    function hideLabel(field) {
        return field === "password" ? qsTr("Hide password") : field === "totp" ? qsTr("Hide code") : qsTr("Hide notes");
    }
    // Reveal, hide or stop: the same choice the field's own button offers.
    function toggle(field) {
        if (busy || revealedField === field)
            act("cancel", "");
        else
            act("reveal", field);
    }
    function runPrimary() {
        if (primaryField.length > 0)
            toggle(primaryField);
    }

    // Software-backed reveals usually finish at once; their pending text waits
    // a second so it never flashes. A fingerprint prompt says so immediately.
    property bool slow: false
    onBusyChanged: {
        slow = false;
        if (busy)
            slowTimer.restart();
        else
            slowTimer.stop();
    }
    Timer {
        id: slowTimer
        interval: Theme.slowWork
        onTriggered: pane.slow = true
    }
    // The code's countdown, read from the clock while one is shown.
    property real now: Date.now() / 1000
    Timer {
        interval: 250
        repeat: true
        running: pane.revealedField === "totp"
        onTriggered: pane.now = Date.now() / 1000
    }

    Rectangle {
        anchors.fill: parent
        color: Theme.detail
    }

    Words {
        anchors.centerIn: parent
        visible: !pane.selected && pane.hasAccounts
        text: qsTr("Select an account")
        color: Theme.secondary
    }

    // A label, a value and the small actions that belong to it.
    component FieldRow: RowLayout {
        id: fieldRow
        property string label
        property alias value: valueText.text
        property color valueColor: Theme.foreground
        property alias valueSize: valueText.font.pixelSize
        property bool wrap: false
        property string note: ""
        property alias action: firstAction
        property string glyph: ""
        property string glyphText: ""
        property bool glyphEnabled: true
        property string characters: ""
        signal triggered()

        Layout.fillWidth: true
        spacing: 12
        Words {
            Layout.preferredWidth: Theme.fieldLabel
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 6
            text: fieldRow.label
            color: Theme.secondary
            font.pixelSize: Theme.small
        }
        ColumnLayout {
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignTop
            Layout.topMargin: 4
            spacing: 4
            Words {
                id: valueText
                Layout.fillWidth: true
                color: fieldRow.valueColor
                wrapMode: fieldRow.wrap ? Text.WrapAnywhere : Text.NoWrap
                elide: fieldRow.wrap ? Text.ElideNone : Text.ElideMiddle
                visible: text.length > 0
            }
            // Letters, digits and symbols in different inks, so a password
            // can be read out or typed without mistakes. Each character is
            // its own plain-text item; nothing is interpreted as markup.
            Flow {
                Layout.fillWidth: true
                visible: fieldRow.characters.length > 0
                Repeater {
                    model: fieldRow.characters.length
                    Words {
                        required property int index
                        readonly property string character: fieldRow.characters.charAt(index)
                        text: character
                        font.pixelSize: Theme.secretText
                        color: /[0-9]/.test(character) ? Theme.blue : /[A-Za-z]/.test(character) ? Theme.bright : Theme.red
                    }
                }
            }
            Words {
                visible: fieldRow.note.length > 0
                text: fieldRow.note
                color: Theme.secondary
                font.pixelSize: Theme.section
            }
        }
        IconButton {
            id: firstAction
            Layout.alignment: Qt.AlignTop
            visible: fieldRow.glyph.length > 0
            implicitWidth: Theme.smallControl
            implicitHeight: Theme.smallControl
            glyphSize: 16
            glyph: fieldRow.glyph
            text: fieldRow.glyphText
            enabled: fieldRow.glyphEnabled
            onClicked: fieldRow.triggered()
        }
    }

    // The one action that matters, pinned to the bottom; ⏎ in the list runs it.
    // Declared first, so the keyboard arrives here and Tab then walks down
    // through the fields' own actions before leaving the details.
    AbstractButton {
        id: primary
        objectName: "primaryAction"
        visible: !!pane.selected && pane.primaryField.length > 0
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.margins: Theme.detailInset
        implicitHeight: 40
        hoverEnabled: true
        focusPolicy: Qt.TabFocus
        text: pane.busy ? qsTr("Cancel") : pane.revealedField === pane.primaryField ? pane.hideLabel(pane.primaryField) : pane.revealLabel(pane.primaryField)
        Accessible.name: pane.asksFingerprint && !pane.busy && pane.revealedField !== pane.primaryField ? qsTr("%1, asks for your fingerprint").arg(text) : text
        Keys.onReturnPressed: clicked()
        Keys.onEnterPressed: clicked()
        onClicked: pane.runPrimary()
        background: Rectangle {
            radius: Theme.rowRadius
            color: primary.hovered ? Qt.lighter(Theme.accent, 1.08) : Theme.accent
            Rectangle {
                visible: primary.activeFocus
                anchors.fill: parent
                anchors.margins: -3
                radius: parent.radius + 3
                color: "transparent"
                border.width: 2
                border.color: Theme.selectionInk
            }
        }
        contentItem: RowLayout {
            spacing: 10
            Words {
                Layout.leftMargin: 14
                Layout.fillWidth: true
                text: primary.text
                color: Theme.accentText
                font.weight: Font.DemiBold
            }
            Glyph {
                visible: pane.asksFingerprint && !pane.busy && pane.revealedField !== pane.primaryField
                name: "Fingerprint"
                size: 16
                color: Theme.accentText
            }
            Words {
                Layout.rightMargin: 14
                text: pane.busy ? qsTr("Esc") : "⏎"
                color: Theme.accentText
            }
        }
    }
    ScrollView {
        id: scroll
        visible: !!pane.selected
        anchors.fill: parent
        anchors.margins: Theme.detailInset
        anchors.bottomMargin: Theme.detailInset + (primary.visible ? primary.height + 16 : 0)
        clip: true
        contentWidth: availableWidth
        ScrollBar.vertical: QuietScrollBar {}

        ColumnLayout {
            width: scroll.availableWidth
            spacing: Theme.detailGap

            // What it is.
            RowLayout {
                Layout.fillWidth: true
                spacing: 16
                Glyph {
                    Layout.alignment: Qt.AlignTop
                    name: !pane.selected ? "Login" : pane.selected.kind === "Login" && !pane.selected.password && pane.selected.totp ? "Code" : pane.selected.kind
                    size: 40
                    stroke: 1.2
                    color: Theme.secondary
                }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4
                    Words {
                        Layout.fillWidth: true
                        text: pane.selected ? pane.selected.site : ""
                        color: Theme.bright
                        font.pixelSize: Theme.detailTitle
                        font.weight: Font.DemiBold
                        wrapMode: Text.WrapAnywhere
                        maximumLineCount: 3
                    }
                    Words {
                        Layout.fillWidth: true
                        text: !pane.selected ? "" : [pane.selected.kind === "Passkey" ? qsTr("Passkey") : qsTr("Login"),
                            pane.selected.protected ? qsTr("Fingerprint required") : pane.selected.storage].join(" · ")
                        color: Theme.secondary
                        font.pixelSize: Theme.small
                    }
                }
            }

            // Its fields.
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 14

                FieldRow {
                    id: accountRow
                    label: qsTr("Account")
                    value: pane.selected ? pane.selected.account : ""
                    wrap: true
                    glyph: "Copy"
                    glyphText: qsTr("Copy username (Ctrl+Shift+U)")
                    onTriggered: pane.copyUsername()
                }

                Repeater {
                    id: secretRows
                    model: ["password", "totp", "notes"]
                    FieldRow {
                        id: secretRow
                        required property string modelData
                        readonly property bool pending: pane.pendingField === modelData
                        readonly property bool shown: pane.revealedField === modelData
                        visible: !!pane.selected && pane.selected[modelData] === true
                        label: pane.fieldLabel(modelData)
                        valueSize: shown && modelData !== "notes" ? Theme.detailTitle : Theme.body
                        valueColor: shown ? Theme.bright : Theme.secondary
                        wrap: modelData === "notes" || shown
                        // The revealed password is drawn character by character below.
                        value: secretRow.pending ? (pane.asksFingerprint ? qsTr("Waiting for fingerprint…") : pane.slow ? qsTr("Revealing…") : "")
                             : secretRow.shown ? (modelData === "password" ? "" : modelData === "totp" ? pane.revealed.replace(/^(\d{3})(\d{3})$/, "$1 $2") : pane.revealed)
                             : modelData === "password" ? "••••••••••••" : modelData === "totp" ? "••• •••" : qsTr("Hidden")
                        note: !secretRow.shown ? ""
                            : modelData === "totp" && pane.status.expires ? qsTr("Changes in %1 s").arg(Math.max(0, Math.ceil(pane.status.expires - pane.now)))
                            : pane.status.hidesIn ? qsTr("Hides in %1 s").arg(pane.status.hidesIn) : ""
                        glyph: secretRow.pending ? "Close" : secretRow.shown ? "EyeOff" : "Eye"
                        glyphText: secretRow.pending ? qsTr("Cancel (Esc)") : secretRow.shown ? pane.hideLabel(modelData) : pane.revealLabel(modelData)
                        glyphEnabled: !pane.busy || secretRow.pending
                        onTriggered: pane.toggle(modelData)
                        characters: shown && modelData === "password" ? pane.revealed : ""

                    }
                }

                FieldRow {
                    visible: !!pane.selected && pane.selected.kind === "Passkey"
                    label: qsTr("Sign in")
                    value: pane.selected && pane.selected.protected ? qsTr("Use this passkey from your browser. Each use asks for your fingerprint.") : qsTr("Use this passkey from your browser.")
                    valueColor: Theme.secondary
                    wrap: true
                }

                FieldRow {
                    id: websiteRow
                    label: qsTr("Website")
                    value: pane.selected ? pane.selected.domain : ""
                    glyph: pane.canOpenWebsite ? "Open" : ""
                    glyphText: qsTr("Open website (Ctrl+O)")
                    onTriggered: pane.openWebsite()
                }
            }

            // Where it lives and how it's kept: facts, values to the right.
            GridLayout {
                Layout.fillWidth: true
                columns: 2
                rowSpacing: 12
                columnSpacing: 16
                Words {
                    text: qsTr("Saved in")
                    color: Theme.secondary
                    font.pixelSize: Theme.small
                }
                Words {
                    Layout.fillWidth: true
                    horizontalAlignment: Text.AlignRight
                    text: pane.selected ? pane.selected.storage : ""
                    font.pixelSize: Theme.small
                }
                Words {
                    text: qsTr("Protection")
                    color: Theme.secondary
                    font.pixelSize: Theme.small
                }
                Words {
                    Layout.fillWidth: true
                    horizontalAlignment: Text.AlignRight
                    text: pane.selected ? pane.selected.protection : ""
                    font.pixelSize: Theme.small
                    wrapMode: Text.Wrap
                }
            }
        }
    }

}
