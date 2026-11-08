# Native passkey creation

The Chromium extension forwards one frozen creation request to its native host
and returns the resulting registration or error. Creation opens no extension
popup, and neither the extension nor another owner client can submit a storage
destination. The separate browser account picker remains for multi-account sign-in.

The broker parses the request, checks the active local session and supplies a
validated presentation to the unprivileged GPUI agent. It offers only destinations
permitted by the broker's deployment policy and enrolled account. iCloud is the
default when offered; otherwise the device-only destination is explicit. The
window follows the referenced Apple layout: header and Cancel, a neutral key icon,
site and account, storage explanation, and Other Options.

## One window, two phases

1. **Selection:** the window displays the site, account and default destination.
   Other Options exposes the broker's allowed alternatives. No SEP request,
   credential preparation, CloudKit preflight or upload starts in this phase.
2. **Binding:** Continue submits the selection once. The broker accepts only the
   same presentation ID and an offered destination, then sends back the immutable
   summary. The agent checks it against its submitted scope. The selection
   controls disappear, and the bound summary must be drawn, visible and focused
   before a second display acknowledgment is sent.
3. **Authorization:** the same window shows preparation and actual reader
   guidance. The broker performs the destination-specific preflight and SEP
   operation. Further UI selections cancel permission rather than altering scope.
4. **Completion:** a verified biometric result and the existing registration
   checks determine success. iCloud creation additionally requires its atomic
   upload and complete independent fetch/decrypt verification. The UI cannot
   supply a success grant or a cloud backup receipt.

The initial selection is bounded to 60 seconds and may remain open across focus
changes, including focus-follows-mouse transitions while reaching the popup.
Selection grants no authorization. After the bound summary is drawn and focused,
focus loss cancels permission to continue. Authorization has its own 60-second
deadline. Request disconnection, malformed/replayed messages, Cancel/Escape,
window closure or a locked/invalid session fail closed in both phases.
An uncertain SEP operation or upload is retained and never automatically replayed.
Changing destination requires a fresh selection and authorization lifetime.

## Private protocol and deployment

Broker/agent protocol **4** retains a `choose-creation` presentation with typed allowed
storage choices and a `selected` reply. Ordinary presentations still accept only
a display acknowledgment or cancellation. Selection is not biometric approval.
Both selection and the bound summary have independent display acknowledgments.
Versions 1–3 are rejected; install the matching broker and desktop agent.

Native messaging keeps its existing protocol version, but `create` no longer
accepts a `storage` field. Reload the extension with the updated native host.
There is no fallback to an older browser-controlled selection path. The existing
read-only creation inspection remains available to administrator diagnostics.
Administrator recovery tools use their separately reviewed fixed destination.

The desktop agent remains unprivileged and never opens SEP. Only the root broker
owns SEP operations and policy. The application window is an ordinary desktop
surface, not a protected OS input surface. The browser remains the source of the
reported website context; a native chooser does not independently attest origin
or protect against a compromised desktop session.

## Validation

Socket-pair tests cover offered-scope validation, old protocol rejection, wrong
request IDs, unavailable destinations, a replayed selection instead of the bound
summary acknowledgment, cancellation before binding, and disconnect after binding.
Native-host tests reject browser-supplied storage before broker IPC. Extension
tests cover direct forwarding, request abort, duplicate suppression and refusal
to retry or substitute another destination after an error. Live UI and browser
acceptance results are recorded in LIVE-ICLOUD-TEST.md.
