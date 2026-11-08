const { test } = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const context = vm.createContext({ ArrayBuffer, Uint8Array, btoa, atob });
vm.runInContext(fs.readFileSync(`${__dirname}/../shared/webauthn.js`, "utf8"), context);
const codec = context.KeychainWebAuthn;
test("WebAuthn binary encoding respects typed-array offsets and never accepts strings", () => {
  assert.equal(codec.encode(new Uint8Array([9,1,2,8]).subarray(1,3)), "AQI");
  assert.throws(() => codec.encode("AQI"));
  assert.throws(() => codec.encode(new Uint8Array(4097)));
  assert.throws(() => codec.decode("not+url/base64"));
});
test("WebAuthn options snapshot binary challenge, IDs and allowlists", () => {
  const raw = { challenge: new Uint8Array(32), user: { id: new Uint8Array([1,2]), name: "alice" },
    excludeCredentials: [{ type: "public-key", id: new Uint8Array([3,4]) }] };
  const wire = codec.serialize("create", raw); raw.user.id[0] = 7;
  assert.equal(wire.user.id, "AQI"); assert.equal(wire.excludeCredentials[0].id,"AwQ");
  assert.equal(wire.challenge,"A".repeat(43));
});
test("WebAuthn public response methods return fresh copies with correct binary data", () => {
  const input = { id:"AQI",rawId:"AQI",type:"public-key",response:{clientDataJSON:"e30",attestationObject:"AQI",
    authenticatorData:"AwQ",publicKey:"BQY",publicKeyAlgorithm:-7,transports:["internal"]},clientExtensionResults:{credProps:{rk:true}} };
  const value = codec.credential(JSON.stringify(input));
  assert.deepEqual([...new Uint8Array(value.rawId)],[1,2]);
  assert.equal(value.response.getPublicKeyAlgorithm(),-7);
  assert.deepEqual([...new Uint8Array(value.response.getPublicKey())],[5,6]);
  value.getClientExtensionResults().credProps.rk=false;
  assert.equal(value.getClientExtensionResults().credProps.rk,true);
  assert.equal(value.toJSON().id,"AQI");
  assert.throws(()=>codec.credential(JSON.stringify({...input,rawId:"AwQ"})));
});
