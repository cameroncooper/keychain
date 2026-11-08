# Browser adapter validation — 2026-11-08

Actual packages from `node browser/build.mjs` passed the same isolated WebDriver
harness in Chromium 156.0.8078.79 and LibreWolf 156.0, using ChromeDriver 156 and
GeckoDriver 0.37.1. The full run did not skip deadlines.

Verified in each browser:

- Availability through the packaged adapter and native-messaging manifest.
- Public-key registration, credential/response prototypes, binary accessors,
  extension results and JSON conversion.
- Assertion signature independently checked against the synthetic registered
  public key, exact HTTPS origin and fresh challenge.
- Selecting the second account in the actual shared extension picker using
  WebDriver UI clicks; the selected credential ID was returned.
- AbortSignal rejection, foreign-RP rejection, timeout rejection and a successful
  new request after cancellation/timeout.

Current full-run evidence is `/tmp/keychain-browser-harness-iV0PYb/`, with one
`result.json`, private synthetic state, native-fixture log and driver log per
browser. Chromium expanded the one-second site timeout to 180000 ms in proxy
JSON; the shared adapter capped it at 120000 ms. Firefox applied the shorter
request timeout. These results exercise the production adapters/core/codec,
but the native provider is an explicitly synthetic test process.

The 38 Node tests also passed, including common lifecycle/selection cases under
both API shapes and Firefox sender/origin/navigation/disconnect negatives.
Workspace/all-target Rust checks passed: 236 library tests, executed binary and
example tests, and 12 driver tests; explicitly ignored live/privileged cases were
not counted as passing. The Rust caller tests reject foreign RP/origin and mixed
caller envelopes before broker IPC. Formatting and packaging/installer checks
passed. Workspace output: `/tmp/keychain-firefox-workspace-tests.log`.

The updated release native host is in `target/release/keychain-browser-host`.
The release broker was installed while the old service was inactive; installed
and built SHA-256 matched
`947d4fc554d156f9eaa554a87755fc40206990a3dea9c02090c520676a723085`.
The previous binary is retained under
`/var/lib/keychain-service-backups/firefox-adapter.AIJ688sZ`.
Socket activation reported the paired active session and available SEP key API;
no private operation was started by that status check. Device access remains
restricted to `/dev/sep-keys`.

Host manifests were installed for Firefox and LibreWolf, with only
`keychain@cameroncooper` in `allowed_extensions`. Staged copies also passed exact
allowlist/path and mode-0600 checks. No personal browser profile was used by the
automated harness. Loading the temporary add-on in the user's normal browser,
a real SEP-backed Firefox authentication, and any real iCloud creation remain
manual follow-up checks; this record does not claim those ran.
