// Disposable native-host integration check, not Chromium/RP acceptance evidence.
// Default inspection does not create a key or request a fingerprint. Biometric
// modes require explicit coordination with the person using the reader.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawn, execFileSync } = require("node:child_process");

const [profileArg, mode = "--inspect-only"] = process.argv.slice(2);
if (!profileArg || !path.basename(profileArg).startsWith(".sep-check-") ||
    !["--inspect-only", "--create-and-assert", "--assert"].includes(mode)) {
  throw new Error("usage: node contrib/check-native-registration.cjs .sep-check-PROFILE [--inspect-only|--create-and-assert|--assert]");
}
const profile = path.resolve(profileArg);
const root = path.resolve(__dirname, "..");
const environment = { ...process.env, XDG_CONFIG_HOME: path.join(profile, "config"),
  XDG_STATE_HOME: path.join(profile, "state"), XDG_RUNTIME_DIR: path.join(profile, "runtime") };
const fixturePath = path.join(profile, "native-registration.json");
const rpId = "diagnostic.invalid";
const origin = `https://${rpId}`;

async function native(message) {
  return new Promise((resolve, reject) => {
    const child = spawn(path.join(root, "target/release/keychain-browser-host"), [], {
      env: environment, stdio: ["pipe", "pipe", "pipe"],
    });
    let data = Buffer.alloc(0), result;
    const timeout = setTimeout(() => { child.kill(); reject(new Error("native request expired")); }, 75000);
    child.on("error", (error) => { clearTimeout(timeout); reject(error); });
    child.stdin.on("error", (error) => { clearTimeout(timeout); reject(error); });
    child.stderr.resume(); // Never dump unexpected native diagnostics or bodies.
    child.stdout.on("data", (chunk) => {
      try {
        data = Buffer.concat([data, chunk]);
        if (data.length > 1024 * 1024 + 4) throw new Error("oversized native reply");
        if (data.length < 4) return;
        const size = data.readUInt32LE(0);
        if (size === 0 || size > 1024 * 1024) throw new Error("invalid native reply size");
        if (data.length < size + 4) return;
        assert.equal(data.length, size + 4);
        result = JSON.parse(data.subarray(4));
        child.stdin.end(); // EOF before a reply would cancel the broker request.
      } catch (error) { clearTimeout(timeout); child.kill(); reject(error); }
    });
    child.on("exit", (code) => {
      clearTimeout(timeout);
      if (code !== 0 || !result) return reject(new Error(`native host failed (${code})`));
      if (!result.ok) return reject(new Error(`${result.error?.name}: ${result.error?.message}`));
      resolve(result.result);
    });
    const payload = Buffer.from(JSON.stringify({ version: 1, ...message }));
    const header = Buffer.alloc(4); header.writeUInt32LE(payload.length);
    child.stdin.write(Buffer.concat([header, payload]));
  });
}

function save(state) {
  const temporary = `${fixturePath}.${crypto.randomUUID()}.tmp`;
  const fd = fs.openSync(temporary, "wx", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(state)); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  fs.renameSync(temporary, fixturePath);
  const directory = fs.openSync(profile, "r");
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}

// Small independent decoder for the bounded CBOR maps used by none attestation
// and ES256 COSE. Reject trailing input and duplicate keys rather than guessing.
function cbor(bytes) {
  let offset = 0;
  function read() {
    assert.ok(offset < bytes.length);
    const head = bytes[offset++], major = head >> 5, extra = head & 31;
    let size = extra;
    if (extra === 24) { assert.ok(offset + 1 <= bytes.length); size = bytes[offset++]; }
    else if (extra === 25) { assert.ok(offset + 2 <= bytes.length); size = bytes.readUInt16BE(offset); offset += 2; }
    else if (extra >= 24) throw new Error("unexpected CBOR length");
    if (major === 0) return size;
    if (major === 1) return -1 - size;
    if (major === 2 || major === 3) {
      assert.ok(offset + size <= bytes.length);
      const value = bytes.subarray(offset, offset + size); offset += size;
      return major === 2 ? value : value.toString("utf8");
    }
    assert.equal(major, 5); assert.ok(size <= 16);
    const map = new Map();
    for (let i = 0; i < size; i++) {
      const key = read(); assert.ok(typeof key === "string" || typeof key === "number");
      assert.equal(map.has(key), false); map.set(key, read());
    }
    return map;
  }
  const value = read(); assert.equal(offset, bytes.length); return value;
}

function checkClient(encoded, type, challenge) {
  const bytes = Buffer.from(encoded, "base64url"), value = JSON.parse(bytes);
  assert.equal(value.type, type); assert.equal(value.challenge, challenge);
  assert.equal(value.origin, origin); assert.equal(value.crossOrigin, false);
  return bytes;
}

async function main() {
  const caller = { remoteDesktopClientOverride: { origin, sameOriginWithAncestors: true } };
  const details = JSON.stringify({ rp: { id: rpId, name: "Synthetic native registration check" },
    user: { id: "AQ", name: "Synthetic native registration check", displayName: "Synthetic native registration check" },
    challenge: crypto.randomBytes(32).toString("base64url"),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    extensions: { ...caller, credProps: true },
  });
  const inspection = await native({ action: "inspectCreation", requestDetailsJson: details });
  assert.equal(inspection.kind, "creationInspection");
  assert.deepEqual(inspection.storageChoices, ["device-bound"]);
  assert.equal(inspection.origin, origin);
  console.log("creation inspection passed without CREATE or fingerprint capture");
  if (mode === "--inspect-only") return;
  let state;
  if (fs.existsSync(fixturePath)) {
    const meta = fs.lstatSync(fixturePath);
    assert.ok(meta.isFile() && !meta.isSymbolicLink() && meta.uid === process.getuid());
    assert.equal(meta.mode & 0o077, 0); assert.ok(meta.size <= 64 * 1024);
    state = JSON.parse(fs.readFileSync(fixturePath));
    assert.equal(state.version, 1);
    assert.equal(JSON.parse(state.details).rp.id, rpId);
  } else {
    assert.equal(mode, "--create-and-assert", "no saved fixture; use --create-and-assert");
    state = { version: 1, transaction: crypto.randomUUID(), details };
    save(state); // Keep exact request/transaction across interrupted delivery.
  }
  if (mode === "--create-and-assert") {
    assert.equal(state.registration, undefined, "fixture already created; use --assert");
    console.log("CREATE: touch the reader when the desktop prompt asks");
    const result = await native({ action: "create", transaction: state.transaction,
      storage: "device-bound", requestDetailsJson: state.details });
    assert.equal(result.kind, "registration");
    state.registration = JSON.parse(result.responseJson); save(state);
  }
  const registration = state.registration;
  assert.ok(registration, "no completed registration fixture");
  assert.equal(registration.id, registration.rawId);
  assert.deepEqual(registration.clientExtensionResults, { credProps: { rk: true } });
  checkClient(registration.response.clientDataJSON, "webauthn.create", JSON.parse(state.details).challenge);
  const auth = Buffer.from(registration.response.authenticatorData, "base64url");
  assert.deepEqual(auth.subarray(0, 32), crypto.createHash("sha256").update(rpId).digest());
  assert.equal(auth[32], 0x45); assert.deepEqual(auth.subarray(33, 53), Buffer.alloc(20));
  const idLength = auth.readUInt16BE(53);
  assert.equal(auth.subarray(55, 55 + idLength).toString("base64url"), registration.id);
  const cose = cbor(auth.subarray(55 + idLength));
  assert.equal(cose.get(1), 2); assert.equal(cose.get(3), -7); assert.equal(cose.get(-1), 1);
  const attestation = cbor(Buffer.from(registration.response.attestationObject, "base64url"));
  assert.equal(attestation.get("fmt"), "none"); assert.equal(attestation.get("attStmt").size, 0);
  assert.deepEqual(attestation.get("authData"), auth);
  const publicKey = crypto.createPublicKey({ key: Buffer.from(registration.response.publicKey, "base64url"), format: "der", type: "spki" });
  const jwk = publicKey.export({ format: "jwk" });
  assert.deepEqual(cose.get(-2), Buffer.from(jwk.x, "base64url"));
  assert.deepEqual(cose.get(-3), Buffer.from(jwk.y, "base64url"));
  const listed = JSON.parse(execFileSync(path.join(root, "target/release/keychain"), ["list", "--json"], { env: environment, encoding: "utf8" }));
  assert.ok(listed.some((item) => item.id === state.transaction && item.storage === "device-bound"));
  console.log("registration CBOR/SPKI, RP/challenge, UV/BE/BS and general CLI inventory verified");
  const challenge = crypto.randomBytes(32).toString("base64url");
  const requestDetailsJson = JSON.stringify({ challenge, rpId, userVerification: "required",
    allowCredentials: [{ type: "public-key", id: registration.id }], extensions: caller });
  console.log("ASSERT: lift your finger, then touch when the next desktop prompt asks");
  const result = await native({ action: "assert", passkeyId: state.transaction, requestDetailsJson });
  const assertion = JSON.parse(result.responseJson);
  assert.equal(assertion.id, registration.id); assert.equal(assertion.response.userHandle, "AQ");
  const clientData = checkClient(assertion.response.clientDataJSON, "webauthn.get", challenge);
  const authenticatorData = Buffer.from(assertion.response.authenticatorData, "base64url");
  assert.equal(authenticatorData.length, 37); assert.equal(authenticatorData[32], 0x05);
  assert.deepEqual(authenticatorData.subarray(0, 32), crypto.createHash("sha256").update(rpId).digest());
  assert.ok(crypto.verify("sha256", Buffer.concat([authenticatorData, crypto.createHash("sha256").update(clientData).digest()]),
    publicKey, Buffer.from(assertion.response.signature, "base64url")));
  console.log("fresh-process assertion verified against the registered key; no Apple or relying-party request sent");
}
main().catch((error) => { console.error(error.message); process.exitCode = 1; });
