import QtQuick
import KeychainBackend

// All text Keychain draws. Account, site and note text comes from other
// people's data, so it is never interpreted as rich text (which could load
// remote images); see docs/GUI-DESIGN-FOLIO.md.
Text {
    color: Theme.foreground
    textFormat: Text.PlainText
    font.family: Theme.family
    font.pixelSize: Theme.body
    elide: Text.ElideRight
    verticalAlignment: Text.AlignVCenter
    // Set, so that it's mirrored: left as it is, Latin text in a right-to-left
    // window would follow its own script and stay on the left.
    horizontalAlignment: Text.AlignLeft
}
