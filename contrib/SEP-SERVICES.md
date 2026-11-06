# SEP broker and desktop-agent deployment

The user-session GTK agent and privileged operation broker are separate binaries.
Build and stage the exact install before applying it:

```sh
cargo build --release --features desktop-agent --bins
bash contrib/install-sep-services.sh --destdir /tmp/keychain-service-stage
sudo bash contrib/install-sep-services.sh
```

The installer copies root-owned executables to `/usr/libexec/keychain/`, root
system units to `/etc/systemd/system/` and the global user unit to
`/etc/systemd/user/`. It does not build as root, pair a user, enable services or
migrate a vault. It refuses unsafe existing targets and backs up changed system
artifacts under private `/var/lib/keychain-service-backups/update.*` directories.
Copies are replaced atomically; encrypted state is not part of artifact backups.

An administrator must explicitly pair ONE Linux UID with the configured SEP
identity before enabling `keychain-broker@UID.socket`. Installing the templates
does not authorize every user. The socket belongs to that UID and is mode 0600,
inside a root-controlled directory. The service separately checks SO_PEERCRED,
record ownership and the active unlocked local graphical session. Multiple
graphical sessions for one UID are currently refused.

For this machine, UID 1001 is explicitly paired using:

```sh
sudo bash contrib/pair-sep-owner.sh 1001 --item-decrypt
systemctl --user daemon-reload
systemctl --user start keychain-auth-agent.service
```

The pairing helper writes private root-owned `/etc/keychain/sep-owner`, prepares
the separate item recipient only with the explicit decrypt opt-in, and enables
the selected socket. It refuses reassignment to a different UID. Activated
brokers validate that pairing file before serving; merely enabling another
template instance cannot grant another UID access to the configured identity.
The direct root diagnostic `--socket` mode remains an explicit administrator test
path. No fingerprint enrollments or system keybags are changed by pairing.

`ProtectHome=tmpfs` hides user homes and other runtime directories, with a
read-only bind of the explicitly paired UID's `/run/user/UID`. Binding the directory
instead of a socket inode allows the agent to recreate its socket after restart.
This exposes that UID's runtime directory to the trusted helper, not only the
agent socket; peer ownership and protocol checks still apply. `ProtectHome=yes`
would prevent this bind exception; see the upstream
[systemd execution documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#ProtectHome=).

The agent now supports D-Bus activation through the user service
`cameroncooper.keychain.AuthenticationAgent`, backed by the `Type=dbus` systemd
user unit. After installation, run `systemctl --user daemon-reload`. No enable
step is required for on-demand use; the optional graphical-session target link
continues to permit eager startup. Existing enabled links are not removed by the
installer. The agent exits successfully after two idle minutes with no active
prompt, and later requests activate a fresh process. An active prompt/cleanup
lifetime prevents idle exit.

The unprivileged CLI/native host activates the fixed name in its own checked
`/run/user/UID/bus` before a prompt-dependent operation or availability query.
It ignores environment-supplied bus addresses, checks the private runtime and
socket owner, and bounds the full asynchronous probe/start path to five seconds
with cancellation checks. Activation alone never presents a dialog or starts
capture. The bus name is claimed after GTK initialization and listener setup;
there are no D-Bus authentication/success methods. The broker still checks the
agent's kernel peer and requires the actual window-visible acknowledgement before
capture. The user bus on the development machine rejects root connections, so the
privileged broker never impersonates an owner or spawns a user helper to activate
it. Direct root diagnostics require an already started agent; the desktop user
can run `systemctl --user start keychain-auth-agent.service` first.

The agent requires the graphical session environment. Its private runtime socket
is `$XDG_RUNTIME_DIR/keychain-auth.sock`, guarded by a process lock; stale sockets
are removed only after obtaining that lock and checking type/ownership. Activation
failure, unsafe files, headless startup or unavailable UI returns an error; there
is no invisible capture or forced service restart. Cancellation/timeout can leave
an otherwise idle agent running until idle exit, but sends no broker credential
operation. It holds no credentials and never opens the SEP device.

The broker receives its socket through systemd activation and stores encrypted
registry records and its metadata-encryption root in its private StateDirectory.
It exits after 120 seconds with no queued or active requests; `--idle-timeout`
can adjust that interval. Completion/disconnection starts a fresh idle interval.
The activation socket remains under systemd control for the next request. The
listener/worker idle behavior is integration-tested with a temporary root registry.
Installed socket activation, clean idle exit and new-process reactivation have
also passed on the development machine.
This metadata root is software-protected by root permissions; it is NOT the
user vault root and is not claimed to be biometric-protected. Native private keys
remain protected by SEP wrapping. Selected synced-scalar item envelopes and
biometric decrypt/software-signing are implemented; real-vault migration remains
pending. See [protected items](../docs/SEP-PROTECTED-ITEMS.md).

The matching local decrypt driver needs explicit root setup with `prepare-item-key`
and a deployment override adding `--allow-item-decrypt` to Serve. The template
keeps this disabled until the local extension and acceptance gates are validated.
It must not infer decrypt support from the signing capability bit.

The shipped service omits `--allow-diagnostics`. That flag is intended only for
temporary disposable-key tests; it cannot sign with non-diagnostic records.
The privileged `provision-diagnostic` command is likewise a test operation, not
credential registration or Apple synchronization.

Device access is exclusive. An EBUSY on open produces a waiting state; only this
pre-operation open is retried within the original deadline. No signing command
or ambiguous completion is retried. Cancellation/session policy remain active
while waiting. No fallback backend or forced restart of fprintd is used. A real
fprintd Claim held the SEP device busy while an installed-broker request remained
pending. After this client's Release, the biometric operation completed and a
fresh device probe succeeded. No verification/enrollment was started by fprintd
and no other client's claim was released. The diagnostic uses the standard
[Claim/Release API](https://fprint.freedesktop.org/fprintd-dev/Device.html).

Installed hardened services have now completed a synthetic migration and a
fresh release native-host assertion with independent ES256/identity/flag checks.
The older debug diagnostic services and registries are separate historical
fixtures. See [exact validation evidence](../docs/SEP-APPLICATION-VALIDATION.md).
Real-profile use and retirement require the migration/recovery gates, not just
successful socket activation. The current driver module is still a separate
deployment prerequisite after reboot.

To disable the integration, stop/disable `keychain-broker@1001.socket`, stop
`keychain-broker@1001.service`, and disable the user agent. Keep the pairing marker,
registry and recovery copies until a deliberate data-retirement decision; disabling
services does not erase keys or automatically revert protected references to software.


D-Bus activation validation on 2026-11-06 used the installed release binaries:
with no authentication window present, the old idle agent was stopped. An owner
native-host `--availability-only` check started PID 371722 through D-Bus and
returned availability without a window or capture. The service owned
`cameroncooper.keychain.AuthenticationAgent` as `Type=dbus`. It stopped after
120 idle seconds, leaving MainPID=0, Result=success and NRestarts=0; systemd recorded
SIGTERM during D-Bus-name shutdown, so a process-status-zero check alone is not the
right service-success criterion. A subsequent native-host availability check
activated PID 373455 and succeeded, again with no prompt. The optional existing
login-start link was preserved. Previous artifacts are retained at
`/var/lib/keychain-service-backups/update.pROl23d1`.

Three synthetic activation tests cover in-flight/preexisting cancellation,
timeout and future destruction, unsafe socket ownership/permissions/symlinks,
stale sockets and a full disposable socket backlog. `socket2` is a test-only
reference to the version already in Cargo.lock, used to bound that test backlog;
it adds no new runtime dependency/version. The tests accept immediate nonblocking
connect refusal or a bounded timeout; neither permits an ordinary blocking probe.
No real credential operation, biometric capture or Apple write was used in these
activation checks.

Final checks for this activation change: all 230 workspace tests passed (25
intentionally ignored), plus 21 privileged library tests run separately.
Formatting, strict Clippy, staged unit verification and release builds passed.
The production credential/write gates remain unchanged. Real prompt/capture,
biometric cancellation/session-lock and Apple-account acceptance remain open.
