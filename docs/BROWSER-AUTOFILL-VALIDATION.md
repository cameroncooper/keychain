# Shared browser UI and protected autofill validation

2026-11-08. Implements the read/presentation portion of
[the Apple extension adaptation](../browser/APPLE-UX-REFERENCE.md).

- Shared JavaScript suite: 60 tests passed. Covers both adapter API shapes,
  picker selection/cancellation/deadlines, toolbar caller restrictions, fixed app
  handoff, metadata inspection, pinned selection, disconnection and navigation.
- Rust workspace/all targets: passed (library 238 passed, 27 ignored, plus binary,
  integration and driver tests). The additional desktop-action argument/version
  test passed separately. Clippy for library/binaries passed with warnings denied.
  Desktop-agent binary compatibility check and release host/broker builds passed.
- Root-only synthetic destination test passed: a foreign origin and forbidden
  Notes request are rejected before biometric/device access. It used a temporary
  registry and a nonexistent device, with no real item or sensor operation.
- Real packaged Chromium 156.0.8078.79 and LibreWolf 156.0 passed against a local
  HTTPS fixture and synthetic native provider. Both exercised WebAuthn
  registration/assertion/signature validation, account selection, cancellation,
  timeout, password/code filling, username-only forms, and destination/field
  replacement rejection. Light evidence: `/tmp/keychain-browser-harness-Y3MG67`.
- Final dark packages additionally passed hidden-input and changed-form-membership
  rejection. Evidence: `/tmp/keychain-browser-harness-olJLZ3`. This targeted rerun
  explicitly skipped the slow deadline case already exercised in the light run.
  Screenshots of inline/picker/toolbar surfaces were retained and inspected.

Installed root broker SHA-256:
`471a4aa4118878e7761fbca8a6895ffe82ed0b5cd560f3aa89911cb153d9ce4a`.
The previous binary is retained at
`/var/lib/keychain-service-backups/browser-autofill.he4wmz0t/keychain-broker`.
The service was inactive during atomic replacement. The existing item-decrypt
policy and socket activation were retained. Read-only native-host manager status,
authenticator capabilities and empty inventory matching for a synthetic foreign
origin passed after installation. No biometric capture or Apple write ran.

Real password/code browser filling with native authorization remains a deliberate
user acceptance check after reloading the built extension. Automated success does
not establish real sensor, Apple upload or every site's form compatibility.
Save/update, generation, QR enrollment and browser-autofill settings integration
remain pending; no controls claim those capabilities.
