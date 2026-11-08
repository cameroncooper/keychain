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

Initial autofill rollout broker SHA-256:
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

## Registrable-domain matching update

The root broker now matches password/code items by registrable domain using the
embedded `psl` 2.1.248 list, including its private suffixes. Domain matching and
private authorization tests cover Apple root/sibling/subdomains, `co.uk`,
`github.io`/`blogspot.com` tenant separation, PSL wildcard/exception rules, IDNA,
lookalikes, malformed names, HTTPS/port restrictions, IPs and local/unknown names.
Library tests passed: 240, with 27 ignored. Clippy with warnings denied and the
release host/broker builds passed. No browser JavaScript or WebAuthn RP policy
changed, so the existing browser harness was not rerun for this native-only change.

The broker was replaced atomically while inactive. The installed binary matches
release SHA-256 `5039b115e4c70f1887414bf98a824e0875f03c6c5d3b93dd07f56b2adca17d05`;
backup: `/var/lib/keychain-service-backups/domain-matching.5vi5xezy/keychain-broker`.
Read-only native inspection succeeded for `apple.com`, `account.apple.com` and
`developer.apple.com`, returning identical sets of offered item IDs. No private
fields were requested and no biometric operation or Apple write ran.
