#!/usr/bin/env bash
# Explicit administrator pairing with the one currently configured SEP identity.
# No account/vault migration; user agent activation is a separate user operation.
set -euo pipefail
umask 077
owner=${1:-}
decrypt=${2:-}
if [[ $EUID != 0 || ! $owner =~ ^[1-9][0-9]{0,9}$ || $# -gt 2 ||
      ( -n $decrypt && $decrypt != --item-decrypt ) ]]; then
  echo "usage (root): $0 UID [--item-decrypt]" >&2; exit 2
fi
(( 10#$owner <= 4294967294 )) || { echo 'invalid UID' >&2; exit 2; }
account=$(getent passwd "$owner") || { echo 'UID has no local account' >&2; exit 1; }
[[ $(cut -d: -f3 <<< "$account") == "$owner" ]] || { echo 'UID is not canonical' >&2; exit 1; }
[[ -x /usr/libexec/keychain/keychain-broker ]] || { echo 'install the service artifacts first' >&2; exit 1; }
if [[ -e /etc/keychain || -L /etc/keychain ]]; then
  [[ -d /etc/keychain && ! -L /etc/keychain && $(stat -c %u /etc/keychain) == 0 && $(stat -c %a /etc/keychain) == 700 ]] || {
    echo 'unsafe existing pairing directory' >&2; exit 1;
  }
else
  install -d -m 0700 /etc/keychain
fi
exec 9>/etc/keychain/.pair.lock
flock -n 9 || { echo 'another pairing update is active' >&2; exit 1; }
pair=/etc/keychain/sep-owner
if [[ -e $pair || -L $pair ]]; then
  [[ -f $pair && ! -L $pair && $(stat -c %u "$pair") == 0 && $(stat -c %a "$pair") == 600 ]] || {
    echo 'unsafe existing pairing file' >&2; exit 1;
  }
  [[ $(cat "$pair") == "$owner" ]] || { echo 'a different UID is already paired; refusing reassignment' >&2; exit 1; }
else
  temporary=$(mktemp /etc/keychain/.sep-owner.XXXXXXXX)
  chmod 0600 "$temporary"
  printf '%s\n' "$owner" > "$temporary"
  mv -T "$temporary" "$pair"
fi
registry=/var/lib/keychain-broker/$owner
if [[ -e /var/lib/keychain-broker || -L /var/lib/keychain-broker ]]; then
  [[ -d /var/lib/keychain-broker && ! -L /var/lib/keychain-broker && $(stat -c %u /var/lib/keychain-broker) == 0 ]] || {
    echo 'unsafe existing registry parent' >&2; exit 1;
  }
  mode=$(stat -c %a /var/lib/keychain-broker)
  (( (8#$mode & 0022) == 0 )) || { echo 'registry parent is writable by other users' >&2; exit 1; }
fi
if [[ -e $registry || -L $registry ]]; then
  [[ -d $registry && ! -L $registry && $(stat -c %u "$registry") == 0 && $(stat -c %a "$registry") == 700 ]] || {
    echo 'unsafe existing registry; refusing to change permissions' >&2; exit 1;
  }
else
  install -d -m 0700 "$registry"
fi
if [[ $decrypt == --item-decrypt ]]; then
  # Explicit opt-in for the known local decrypt API, never inferred from GET_INFO.
  /usr/libexec/keychain/keychain-broker --registry "$registry" --owner "$owner" prepare-item-key
  directory=/etc/systemd/system/keychain-broker@${owner}.service.d
  install -d -m 0755 "$directory"
  temporary=$(mktemp "$directory/.item-decrypt.XXXXXXXX")
  cat > "$temporary" <<'UNIT'
[Service]
ExecStart=
ExecStart=/usr/libexec/keychain/keychain-broker --registry /var/lib/keychain-broker/%i --owner %i serve --allow-item-decrypt
UNIT
  chmod 0644 "$temporary"
  mv -T "$temporary" "$directory/item-decrypt.conf"
fi
systemctl daemon-reload
systemctl enable --now "keychain-broker@$owner.socket"
echo "paired UID $owner; broker socket enabled; no user vault migrated"
echo 'start the desktop agent as the user: systemctl --user enable --now keychain-auth-agent.service'
