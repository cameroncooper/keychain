// Dialog grammar and the password field's lifetime adapted from Folio's
// FolioDialog and MountPrompt (MIT); see ../THIRD-PARTY-NOTICES.md.
import QtQuick
import QtQuick.Layouts
import KeychainBackend

// The locked app. It fills the content area rather than floating over it, so
// nothing behind it can show through: a locked Keychain shows no sites,
// accounts or counts. Touch or the account password unlocks it.
//
// Reached only when the broker reports a "locked" unlock session, which it
// does not yet; see docs/GUI-FOLIO-OVERHAUL-PLAN.md. How the password travels
// to the broker belongs to that contract, so this view never forwards it.
FocusScope {
    id: view

    property string problem: ""
    signal fingerprintRequested()
    signal passwordSubmitted()

    // Each time it appears or goes, the field starts empty, so a password is
    // never kept once the view has closed.
    onVisibleChanged: {
        password.clear();
        if (visible)
            password.forceActiveFocus();
    }
    function submit() {
        password.clear();
        passwordSubmitted();
    }

    Rectangle {
        anchors.fill: parent
        color: Theme.background
    }

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(parent.width - 64, 360)
        spacing: 16
        Glyph {
            Layout.alignment: Qt.AlignHCenter
            name: "Fingerprint"
            size: 72
            stroke: 1.2
            color: Theme.secondary
        }
        Words {
            Layout.fillWidth: true
            Layout.topMargin: 8
            horizontalAlignment: Text.AlignHCenter
            text: qsTr("Keychain is locked")
            color: Theme.bright
            font.pixelSize: Theme.dialogTitle
            font.weight: Font.DemiBold
        }
        Words {
            Layout.fillWidth: true
            horizontalAlignment: Text.AlignHCenter
            text: qsTr("Touch the sensor or enter your password")
            color: Theme.secondary
            wrapMode: Text.Wrap
        }
        PlainField {
            id: password
            objectName: "unlockPassword"
            Layout.fillWidth: true
            Layout.topMargin: 8
            echoMode: TextInput.Password
            placeholderText: qsTr("Password")
            Accessible.name: qsTr("Password")
            onAccepted: view.submit()
        }
        Words {
            Layout.fillWidth: true
            visible: view.problem.length > 0
            text: view.problem
            color: Theme.red
            wrapMode: Text.Wrap
        }
        RowLayout {
            Layout.alignment: Qt.AlignRight
            spacing: 10
            PlainButton {
                text: qsTr("Use fingerprint")
                onClicked: view.fingerprintRequested()
            }
            PlainButton {
                text: qsTr("Unlock")
                primary: true
                onClicked: view.submit()
            }
        }
    }
}
