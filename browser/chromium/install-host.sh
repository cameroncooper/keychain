#!/usr/bin/env bash
set -euo pipefail

extension_id="lcadeibeloholafalbgoehpbhnplmojh"
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
node "$script_dir/../build.mjs"
binary="${1:-${script_dir}/../../target/release/keychain-browser-host}"

if [[ ! -x "${binary}" ]]; then
  echo "keychain-browser-host is not executable at ${binary}" >&2
  echo "Build it first with: cargo build --release" >&2
  exit 1
fi

binary="$(realpath -- "${binary}")"
if [[ "${binary}" == *'"'* || "${binary}" == *'\\'* ]]; then
  echo "The native host path contains a character that cannot be represented safely" >&2
  exit 1
fi

config_root="${XDG_CONFIG_HOME:-${HOME}/.config}"
host_dir="${config_root}/chromium/NativeMessagingHosts"
host_manifest="${host_dir}/cameroncooper.keychain.json"
mkdir -p -- "${host_dir}"
chmod 700 -- "${host_dir}"
temporary="$(mktemp --tmpdir="${host_dir}" .cameroncooper.keychain.XXXXXX)"
trap 'rm -f -- "${temporary}"' EXIT
printf '%s\n' \
  '{' \
  '  "name": "cameroncooper.keychain",' \
  '  "description": "Keychain passkey native messaging host",' \
  "  \"path\": \"${binary}\"," \
  '  "type": "stdio",' \
  '  "allowed_origins": [' \
  "    \"chrome-extension://${extension_id}/\"" \
  '  ]' \
  '}' > "${temporary}"
chmod 600 -- "${temporary}"
mv -- "${temporary}" "${host_manifest}"
trap - EXIT

echo "Installed native host manifest: ${host_manifest}"
echo "Chromium extension ID: ${extension_id}"
echo "Load unpacked extension: ${script_dir}/../dist/chromium"
