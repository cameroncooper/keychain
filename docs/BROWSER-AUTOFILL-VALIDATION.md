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

## Passkey username suggestions

Username menus now offer verified, enabled broker passkey account metadata as
well as password logins. Entries have distinct typed IDs; passkey entries can
fill only a username. Password/code fields exclude them, and attempts to request
private login fields from a passkey suggestion are refused before native work.
Suggestions follow RP host/subdomain scope, exclude public suffix RPs and do not
inherit password matching across sibling subdomains.

The shared JavaScript suite passed 64 tests and Rust library tests passed 241
(with 27 ignored); Clippy with warnings denied passed. Both real packaged browser
harnesses passed in Chromium 156.0.8078.79 and LibreWolf 156.0. Evidence:
`/tmp/keychain-browser-harness-HyJBfO`. New cases select a passkey account in both
username-only and username/password forms and verify username-only filling,
no submission, no private field request and no assertion signing. This targeted
run skipped the previously tested deadline case. All browser credentials and
private operations in the harness were synthetic.

The installed native host returned the expected WebAuthn test account as a
passkey suggestion in a read-only `webauthn.io` inspection. The installed broker
matches release SHA-256
`f3bd99d15da3dbe9895c9f85abb0dcd517443c866fbfc8f6a9d581db8539470f`.
Its prior version is retained at
`/var/lib/keychain-service-backups/passkey-usernames.lfy1kg6e/keychain-broker`.
Replacement occurred while inactive. No real private operation or Apple write
ran. Reload the extension and refresh existing tabs to load the new form scripts.

## Public TOTP challenge form

The public `https://authenticationtest.com/totpChallenge/` form uses email and
password inputs plus a text input named/id `totpmfa`, without a one-time-code
autocomplete token. Its form disables autocomplete. The classifier now recognizes
that MFA name and common MFA/code variants on text/tel/number/password inputs.

The shared JavaScript suite passed 64 tests. Both actual packaged Chromium and
LibreWolf harnesses passed a local synthetic fixture with this form structure,
starting from both email and password, then filling the MFA field without
submitting. Evidence: `/tmp/keychain-browser-harness-Obuvp4`. The targeted run
skipped the previously validated deadline case; no new Rust/native change ran.

Separately, the existing TOTP Test login had neither an active nor a staged
broker record. After the user's fresh operation-specific readiness, its existing
`keychain protect` flow completed revision 1 with biometrics and retained the
encrypted software recovery copy. A subsequent read-only browser inventory
confirmed password and TOTP eligibility for the website. No Apple record or
website sign-in was changed; actual private browser filling remains user-initiated.
