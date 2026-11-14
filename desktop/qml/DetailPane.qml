import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import KeychainBackend

// The selected account's metadata and its deliberate reveals. Values reach
// this pane only through `revealed`, for one field at a time.
Rectangle {
    id: pane

    property var selected: null
    property var status: ({})
    property string revealed: ""
    property bool compact: false
    signal act(string action, string arg)
    signal back()

    color: Theme.detail

    Words {
        anchors.centerIn: parent
        visible: !pane.selected
        text: qsTr("Select an account")
        color: Theme.secondary
    }
    ScrollView {
        id: scroll
        visible: !!pane.selected
        anchors.fill: parent
        anchors.margins: Theme.detailInset
        clip: true
        contentWidth: availableWidth
        ColumnLayout {
            width: scroll.availableWidth
            spacing: Theme.detailGap
            PlainButton {
                visible: pane.compact
                text: qsTr("← Accounts")
                onClicked: pane.back()
            }
            RowLayout {
                spacing: 14
                Glyph {
                    name: pane.selected ? pane.selected.kind : "Login"
                }
                Words {
                    Layout.fillWidth: true
                    font.pixelSize: Theme.detailTitle
                    font.weight: Font.DemiBold
                    text: pane.selected ? pane.selected.site : ""
                    wrapMode: Text.Wrap
                    elide: Text.ElideNone
                }
            }
            Words {
                text: qsTr("Account")
                font.pixelSize: Theme.small
                color: Theme.secondary
            }
            Words {
                Layout.fillWidth: true
                text: pane.selected ? pane.selected.account : ""
                wrapMode: Text.WrapAnywhere
                elide: Text.ElideNone
            }
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: 1
                color: Theme.line
            }
            RowLayout {
                Layout.fillWidth: true
                Words {
                    text: pane.selected && pane.selected.kind === "Passkey" ? qsTr("Passkey") : qsTr("Password")
                    font.pixelSize: Theme.small
                    color: Theme.secondary
                }
                Item {
                    Layout.fillWidth: true
                }
                PlainButton {
                    visible: !!pane.selected && pane.selected.password
                    text: pane.status.busy ? qsTr("Cancel") : pane.status.revealedField === "password" ? qsTr("Hide") : qsTr("Reveal")
                    onClicked: pane.act(pane.status.busy || pane.status.revealedField === "password" ? "cancel" : "reveal", "password")
                }
            }
            Words {
                Layout.fillWidth: true
                font.pixelSize: Theme.secretText
                wrapMode: Text.WrapAnywhere
                elide: Text.ElideNone
                text: !pane.selected ? "" : pane.selected.kind === "Passkey" ? qsTr("Use this passkey from your browser.") : pane.status.revealedField === "password" ? pane.revealed : "••••••••••••"
            }
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: 1
                color: Theme.line
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
                    id: field
                    required property var modelData
                    visible: !!pane.selected && !!pane.selected[modelData.field]
                    Layout.fillWidth: true
                    spacing: 12
                    RowLayout {
                        Layout.fillWidth: true
                        Words {
                            text: field.modelData.label
                            color: Theme.secondary
                            font.pixelSize: Theme.small
                        }
                        Item {
                            Layout.fillWidth: true
                        }
                        PlainButton {
                            text: pane.status.busy ? qsTr("Cancel") : pane.status.revealedField === field.modelData.field ? qsTr("Hide") : qsTr("Reveal")
                            onClicked: pane.act(pane.status.busy || pane.status.revealedField === field.modelData.field ? "cancel" : "reveal", field.modelData.field)
                        }
                    }
                    Words {
                        Layout.fillWidth: true
                        text: pane.status.revealedField === field.modelData.field ? pane.revealed : "••••••••••••"
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
                    color: Theme.secondary
                }
                Words {
                    Layout.fillWidth: true
                    text: pane.selected ? pane.selected.domain : ""
                    wrapMode: Text.WrapAnywhere
                    elide: Text.ElideNone
                }
                Words {
                    text: qsTr("Saved in")
                    color: Theme.secondary
                }
                Words {
                    Layout.fillWidth: true
                    text: pane.selected ? pane.selected.storage : ""
                    wrapMode: Text.Wrap
                    elide: Text.ElideNone
                }
                Words {
                    text: qsTr("Protection")
                    color: Theme.secondary
                }
                Words {
                    Layout.fillWidth: true
                    text: pane.selected ? pane.selected.protection : ""
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
                color: Theme.secondary
                font.pixelSize: Theme.section
                wrapMode: Text.Wrap
            }
        }
    }
}
