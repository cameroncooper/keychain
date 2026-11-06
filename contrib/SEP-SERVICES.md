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
systemctl --user enable --now keychain-auth-agent.service
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

Enable the user agent with `systemctl --user enable --now keychain-auth-agent`.
It requires the graphical session environment. Its private runtime socket is
`$XDG_RUNTIME_DIR/keychain-auth.sock`, guarded by a process lock; stale sockets
are removed only after obtaining that lock and checking type/ownership.
The initial implementation uses graphical-session activation, not D-Bus
activation. It holds no credentials and never opens the SEP device. A future
on-demand activation mechanism must retain these ownership checks.

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
