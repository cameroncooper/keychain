#!/usr/bin/env python3
"""Disposable systemd startup/credential/socket check; no Apple or SEP operations.

Run as root with --binary BUILD/keychain-network-worker --coreadi PUBLIC_IMAGE.
Uses only synthetic credentials and a fake loopback anisette helper. Non-loopback
IP traffic is denied by the transient unit. Never reads a user's account state.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import uuid


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10)


def read_exact(stream, length):
    result = b""
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise EOFError("worker closed the channel")
        result += part
    return result


def hello(path, binding, accepted):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(3)
        stream.connect(str(path))
        _, uid, _ = struct.unpack("3i", stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        assert uid == 65534, "worker did not bind as its own service UID"
        header = dict(version=1, binding=binding, step=0, kind="hello", length=0)
        raw = json.dumps(header).encode()
        stream.sendall(struct.pack(">I", len(raw)) + raw)
        if not accepted:
            assert stream.recv(1) == b"", "wrong account scope was accepted"
            return
        length, = struct.unpack(">I", read_exact(stream, 4))
        assert 0 < length <= 16384
        assert json.loads(read_exact(stream, length)) == header


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--coreadi", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, "requires root for the disposable systemd unit"
    unit = "keychain-network-check-" + uuid.uuid4().hex + ".service"
    with tempfile.TemporaryDirectory(prefix="keychain-network-check-", dir="/run") as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        binary, image, helper = (root / name for name in ("worker", "CoreADI", "fake-anisette"))
        shutil.copyfile(args.binary, binary)
        binary.chmod(0o755)
        shutil.copyfile(args.coreadi, image)
        image.chmod(0o644)
        helper.write_text('''#!/usr/bin/python3
import argparse, http.server, json, os
p=argparse.ArgumentParser()
p.add_argument('--host'); p.add_argument('--port',type=int)
p.add_argument('--adi-path'); p.add_argument('--coreadi')
a=p.parse_args()
assert 'CREDENTIALS_DIRECTORY' not in os.environ
assert 'ENCRYPTED_CREDENTIALS_DIRECTORY' not in os.environ
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  if self.headers.get('Authorization')!='Bearer '+os.environ['KEYCHAIN_ANISETTE_NONCE']:
   self.send_error(403); return
  data=json.dumps({'X-Apple-I-MD':'synthetic','X-Apple-I-MD-M':'synthetic'}).encode()
  self.send_response(200); self.send_header('Content-Length',str(len(data)))
  self.end_headers(); self.wfile.write(data)
 def log_message(self,*args): pass
http.server.HTTPServer((a.host,a.port),Handler).serve_forever()
''')
        helper.chmod(0o755)
        state, runtime = root / "state", root / "runtime"
        for directory in (state, runtime):
            directory.mkdir(mode=0o700)
            os.chown(directory, 65534, 65534)
        scope_hash = "SHA256:" + base64.b64encode(hashlib.sha256(b"synthetic-adsid").digest()).decode()
        peer = "SHA256:" + base64.b64encode(bytes([2]) * 32).decode()
        machine = dict(version=1, host_uuid="01" * 16,
                       # ADI provisioning uses a macOS UDID; CloudKit app scope below remains a UUID.
                       identity=dict(device_id="00006000-0A1B2C3D4E5F6071", local_user_uuid=uuid.uuid4().hex),
                       store_export_b64="synthetic-only")
        seed = json.dumps(dict(version=1, phase="ready", machine_json=json.dumps(machine)))
        credential = dict(version=1, owner=1001, adsid="synthetic-adsid", peer_id=peer,
                          device=dict(schema_version=1, device_id=str(uuid.uuid4()),
                                      local_user_uuid=str(uuid.uuid4()), serial="synthetic"),
                          cloudkit_user_id="synthetic-owner", cloudkit_token="synthetic-token",
                          anisette_seed=base64.b64encode(seed.encode()).decode())
        source = root / "synthetic-credential"
        source.write_text(json.dumps(credential))
        source.chmod(0o600)
        try:
            command("systemd-run", "--quiet", "--no-block", "--collect", "--unit=" + unit,
                    "--property=User=65534", "--property=Group=65534",
                    "--property=LoadCredential=network-account:" + str(source),
                    "--property=NoNewPrivileges=yes", "--property=PrivateDevices=yes",
                    "--property=ProtectHome=yes", "--property=IPAddressDeny=any",
                    "--property=IPAddressAllow=localhost", str(binary), "serve",
                    "--state-directory", str(state), "--runtime-directory", str(runtime),
                    "--helper", str(helper), "--coreadi", str(image), "--idle-timeout", "1")
            endpoint = runtime / "worker.sock"
            deadline = time.monotonic() + 5
            while not endpoint.exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("worker did not become ready; inspect the transient unit")
                time.sleep(0.04)
            binding = dict(owner=1001, account_fingerprint=scope_hash, peer_id=peer,
                           transaction=str(uuid.uuid4()), request_sha256="ab" * 32,
                           zone=dict(name="Passwords", owner="synthetic-owner"))
            for field, value in (("owner", 1002), ("peer_id", "SHA256:" + base64.b64encode(bytes([3]) * 32).decode())):
                wrong = dict(binding)
                wrong[field] = value
                hello(endpoint, wrong, False)
            hello(endpoint, binding, True)
            deadline = time.monotonic() + 5
            while endpoint.exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("worker did not remove its socket after idle exit")
                time.sleep(0.04)
            print("verified systemd credential delivery, separate UID, scope refusal, handshake and idle exit; no Apple/SEP IO")
        finally:
            subprocess.run(["systemctl", "stop", unit], capture_output=True, timeout=10)


if __name__ == "__main__":
    main()
