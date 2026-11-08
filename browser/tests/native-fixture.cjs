// TEST ONLY: synthetic native host for isolated browser profiles. Never deploy
// this as a real credential provider. It has no broker, SEP or account access.
const fs = require("node:fs");
const crypto = require("node:crypto");
const state = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
let input = Buffer.alloc(0), handled = false;
const encode = value => Buffer.from(value).toString("base64url");
function cbor(value) {
  function header(major, length) {
    if (length < 24) return Buffer.from([(major << 5) | length]);
    if (length < 256) return Buffer.from([(major << 5) | 24, length]);
    const out = Buffer.alloc(3); out[0] = (major << 5) | 25; out.writeUInt16BE(length, 1); return out;
  }
  if (Number.isInteger(value)) return value >= 0 ? header(0, value) : header(1, -1-value);
  if (Buffer.isBuffer(value)) return Buffer.concat([header(2, value.length), value]);
  if (typeof value === "string") { const data = Buffer.from(value); return Buffer.concat([header(3, data.length), data]); }
  const entries = value instanceof Map ? [...value] : Object.entries(value);
  return Buffer.concat([header(5, entries.length), ...entries.flatMap(([key, item]) => [cbor(key), cbor(item)])]);
}
function reply(value) {
  const payload = Buffer.from(JSON.stringify(value)); const header = Buffer.alloc(4); header.writeUInt32LE(payload.length);
  process.stdout.write(Buffer.concat([header, payload]), () => process.exit(0));
}
process.stdin.on("end", () => { fs.appendFileSync(state.log, "disconnect\n"); process.exit(0); });
process.stdin.on("data", chunk => {
  input = Buffer.concat([input, chunk]);
  if (handled || input.length < 4 || input.length < input.readUInt32LE(0) + 4) return;
  handled = true;
  try {
    const request = JSON.parse(input.subarray(4, input.readUInt32LE(0) + 4));
    fs.appendFileSync(state.log, request.action + "\n");
    if (request.action === "capabilities") { reply({ ok: true, result: { kind: "capabilities", userVerificationAvailable: true } }); return; }
    const options = JSON.parse(request.requestDetailsJson);
    fs.appendFileSync(state.log, `timeout=${String(options.timeout)} at=${Date.now()}\n`);
    const caller = options.extensions.remoteDesktopClientOverride ?? options.extensions.keychainFirefoxCaller;
    const rp = options.rp?.id ?? options.rpId ?? new URL(caller.origin).hostname;
    if (caller.origin !== state.origin || rp !== "localhost") {
      reply({ ok: false, error: { name: "SecurityError", message: "Synthetic fixture refused foreign RP/origin" } }); return;
    }
    if (request.action === "inspect") {
      const candidates = [{ id: "fixture", username: "test-user", displayName: "Synthetic user" }];
      if (options.challenge === encode(Buffer.alloc(32, 0xdd))) candidates.push({ id: "fixture-2", username: "test-user-2", displayName: "Second synthetic user" });
      reply({ ok: true, result: { kind: "inspection", biometric: true, candidates, origin: state.origin, rpId: rp } }); return;
    }
    if (options.challenge === encode(Buffer.alloc(32, 0xee))) return; // exercise actual browser abort
    const client = Buffer.from(JSON.stringify({ type: request.action === "create" ? "webauthn.create" : "webauthn.get", origin: caller.origin, challenge: options.challenge, crossOrigin: false }));
    const rpHash = crypto.createHash("sha256").update(rp).digest();
    let authData = Buffer.concat([rpHash, Buffer.from([request.action === "create" ? 0x45 : 0x05]), Buffer.alloc(4)]);
    const response = { clientDataJSON: encode(client) };
    if (request.action === "create") {
      const jwk = crypto.createPublicKey(state.public).export({ format: "jwk" });
      const cose = cbor(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,"base64url")],[-3,Buffer.from(jwk.y,"base64url")]]));
      const id = Buffer.from(state.id, "base64url"); const length = Buffer.alloc(2); length.writeUInt16BE(id.length);
      authData = Buffer.concat([authData, Buffer.alloc(16), length, id, cose]);
      Object.assign(response, { attestationObject: encode(cbor({ fmt: "none", attStmt: {}, authData })),
        authenticatorData: encode(authData), publicKey: encode(crypto.createPublicKey(state.public).export({ type: "spki", format: "der" })), publicKeyAlgorithm: -7, transports: ["internal"] });
    } else {
      const signed = Buffer.concat([authData, crypto.createHash("sha256").update(client).digest()]);
      Object.assign(response, { authenticatorData: encode(authData), signature: encode(crypto.sign("sha256", signed, state.private)), userHandle: encode("test-user") });
    }
    const selectedId = request.passkeyId === "fixture-2" ? state.id2 : state.id;
    const credential = { id: selectedId, rawId: selectedId, type: "public-key", authenticatorAttachment: "platform", response, clientExtensionResults: request.action === "create" ? { credProps: { rk: true } } : {} };
    reply({ ok: true, result: { kind: request.action === "create" ? "registration" : "assertion", responseJson: JSON.stringify(credential) } });
  } catch (error) { reply({ ok: false, error: { name: "UnknownError", message: error.message } }); }
});
