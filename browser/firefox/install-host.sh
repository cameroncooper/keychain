#!/usr/bin/env bash
# Register only the fixed Gecko add-on ID; never accept wildcard extensions.
# --destdir supports staging/tests without touching a real browser installation.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
binary="$script_dir/../../target/release/keychain-browser-host"
destination_root="${HOME}"
while (($#)); do
  case "$1" in
    --binary) binary=$2; shift 2 ;;
    --destdir) destination_root=$2; shift 2 ;;
    *) echo "usage: $0 [--binary FILE] [--destdir HOME]" >&2; exit 2 ;;
  esac
done
[[ -x $binary ]] || { echo 'Build keychain-browser-host first' >&2; exit 1; }
binary=$(realpath -- "$binary")
node "$script_dir/../build.mjs"
# Python's JSON encoder handles all path characters without shell substitution.
for product in .mozilla .librewolf; do
  directory="$destination_root/$product/native-messaging-hosts"
  mkdir -p -- "$directory"
  chmod 700 -- "$directory"
  temporary=$(mktemp "$directory/.keychain.XXXXXXXX")
  trap 'rm -f -- "$temporary"' EXIT
  python3 - "$binary" > "$temporary" <<'PY'
import json, sys
print(json.dumps({"name": "cameroncooper.keychain", "description": "Keychain passkey native messaging host",
                  "path": sys.argv[1], "type": "stdio", "allowed_extensions": ["keychain@cameroncooper"]}, indent=2))
PY
  chmod 600 -- "$temporary"
  mv -f -- "$temporary" "$directory/cameroncooper.keychain.json"
  trap - EXIT
  echo "Installed $directory/cameroncooper.keychain.json"
done
echo "Load temporary add-on: $script_dir/../dist/firefox/manifest.json"
