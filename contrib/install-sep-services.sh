#!/usr/bin/env bash
# Install reviewed, prebuilt service artifacts. Does not pair a user, provision
# keys, enable units or modify any user profile. --destdir stages without root.
set -euo pipefail
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
build_dir="$source_root/target/release"
destdir=/
network_helper=
network_coreadi=
while (($#)); do
  case "$1" in
    --build-dir|--destdir)
      (($# >= 2)) || { echo "missing value for $1" >&2; exit 2; }
      if [[ $1 == --build-dir ]]; then build_dir=$2; else destdir=$2; fi
      shift 2 ;;
    --network-helper|--network-coreadi)
      (($# >= 2)) || { echo "missing value for $1" >&2; exit 2; }
      if [[ $1 == --network-helper ]]; then network_helper=$2; else network_coreadi=$2; fi
      shift 2 ;;
    *) echo "usage: $0 [--build-dir DIR] [--destdir DIR] [--network-helper FILE --network-coreadi FILE]" >&2; exit 2 ;;
  esac
done
build_dir=$(realpath -e -- "$build_dir")
destdir=$(realpath -m -- "$destdir")
if [[ $destdir == / && $EUID != 0 ]]; then
  echo "system installation requires root; use --destdir to stage" >&2; exit 1
fi
if [[ -n $network_helper || -n $network_coreadi ]]; then
  [[ -n $network_helper && -n $network_coreadi ]] || { echo 'supply both network assets' >&2; exit 2; }
  network_helper=$(realpath -e -- "$network_helper")
  network_coreadi=$(realpath -e -- "$network_coreadi")
  [[ -f $network_helper && -x $network_helper && -f $network_coreadi ]] || { echo 'invalid network assets' >&2; exit 1; }
  [[ $(sha256sum -- "$network_coreadi" | cut -d ' ' -f 1) == 2eafc3c79c7f41a8afbfbeaaf23ee5dab5ad5bda55ec8e54dbc0ddf1d20ce630 ]] || { echo 'CoreADI differs from the pinned image' >&2; exit 1; }
fi
for binary in keychain-broker keychain-auth-agent keychain-network-worker; do
  [[ -f $build_dir/$binary && -x $build_dir/$binary ]] || {
    echo "missing $binary; build with cargo build --release --features desktop-agent --bins" >&2; exit 1;
  }
done
backup_dir=
check_root_parent() {
  local directory=$1
  while :; do
    [[ $(stat -Lc %u -- "$directory") == 0 ]] || { echo "non-root parent: $directory" >&2; exit 1; }
    local mode
    mode=$(stat -Lc %a -- "$directory")
    (( (8#$mode & 0022) == 0 )) || { echo "writable parent: $directory" >&2; exit 1; }
    [[ $directory == / ]] && return
    directory=$(dirname -- "$directory")
  done
}
install_artifact() {
  local source=$1 relative=$2 mode=$3
  local destination="$destdir/$relative" directory temporary
  directory=$(dirname -- "$destination")
  if [[ $destdir == / ]]; then
    local ancestor=$directory
    [[ ! -L $directory ]] || { echo "symlink target directory: $directory" >&2; exit 1; }
    while [[ ! -e $ancestor ]]; do ancestor=$(dirname -- "$ancestor"); done
    check_root_parent "$(realpath -e -- "$ancestor")"
  fi
  [[ -d $directory ]] || install -d -m 0755 -- "$directory"
  [[ $destdir != / ]] || check_root_parent "$(realpath -e -- "$directory")"
  if [[ -e $destination || -L $destination ]]; then
    [[ -f $destination && ! -L $destination ]] || { echo "unsafe target: $destination" >&2; exit 1; }
    if [[ $destdir == / ]]; then
      [[ $(stat -c %u -- "$destination") == 0 ]] || { echo "non-root target: $destination" >&2; exit 1; }
      local existing_mode
      existing_mode=$(stat -c %a -- "$destination")
      (( (8#$existing_mode & 0022) == 0 )) || { echo "writable target: $destination" >&2; exit 1; }
    fi
    cmp -s -- "$source" "$destination" && return
    if [[ $destdir == / ]]; then
      if [[ -z $backup_dir ]]; then
        if [[ -e /var/lib/keychain-service-backups || -L /var/lib/keychain-service-backups ]]; then
          [[ -d /var/lib/keychain-service-backups && ! -L /var/lib/keychain-service-backups ]] || {
            echo 'unsafe service backup directory' >&2; exit 1;
          }
        else
          check_root_parent /var/lib
          install -d -m 0700 /var/lib/keychain-service-backups
        fi
        check_root_parent /var/lib/keychain-service-backups
        backup_dir=$(mktemp -d /var/lib/keychain-service-backups/update.XXXXXXXX)
      fi
      install -D -m "$mode" -- "$destination" "$backup_dir/$relative"
    fi
  fi
  temporary=$(mktemp "$directory/.keychain-install.XXXXXXXX")
  if ! install -m "$mode" -- "$source" "$temporary" || ! mv -fT -- "$temporary" "$destination"; then
    rm -f -- "$temporary"
    return 1
  fi
  echo "installed $relative"
}
install_artifact "$build_dir/keychain-broker" usr/libexec/keychain/keychain-broker 0755
install_artifact "$build_dir/keychain-auth-agent" usr/libexec/keychain/keychain-auth-agent 0755
install_artifact "$build_dir/keychain-network-worker" usr/libexec/keychain/keychain-network-worker 0755
install_artifact "$source_root/contrib/systemd/keychain-network-worker.service" etc/systemd/system/keychain-network-worker.service 0644
install_artifact "$source_root/contrib/sysusers/keychain-network.conf" usr/lib/sysusers.d/keychain-network.conf 0644
if [[ -n $network_helper ]]; then
  install_artifact "$network_helper" usr/libexec/keychain/keychain-anisette-mac 0755
  install_artifact "$network_coreadi" usr/lib/keychain/CoreADI 0644
fi
install_artifact "$source_root/contrib/systemd/keychain-broker@.service" etc/systemd/system/keychain-broker@.service 0644
install_artifact "$source_root/contrib/systemd/keychain-broker@.socket" etc/systemd/system/keychain-broker@.socket 0644
install_artifact "$source_root/contrib/systemd/keychain-auth-agent.service" etc/systemd/user/keychain-auth-agent.service 0644
if [[ $destdir == / ]]; then
  systemctl daemon-reload
  systemd-analyze verify --man=no /etc/systemd/system/keychain-broker@.service /etc/systemd/system/keychain-broker@.socket /etc/systemd/system/keychain-network-worker.service
  [[ -z $backup_dir ]] || echo "previous artifacts saved under $backup_dir"
  echo 'installed; pairing and service activation are managed separately'
else
  echo "staged under $destdir; no system state changed"
fi
