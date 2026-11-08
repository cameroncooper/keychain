const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const event = () => ({ listeners: [], addListener(fn) { this.listeners.push(fn); }, fire(...args) { for (const fn of this.listeners) fn(...args); } });
const tick = () => new Promise(resolve => setImmediate(resolve));
function fixture() {
  const runtime = { id: "keychain@cameroncooper", onConnect: event() };
  const browser = { runtime, tabs: { get: async id => ({ id, url: "https://example.com/login" }), onRemoved: event() },
    webNavigation: { onBeforeNavigate: event() } };
  const context = vm.createContext({ browser, URL, console });
  vm.runInContext(fs.readFileSync(`${__dirname}/../firefox/background.js`, "utf8"), context);
  const transport = context.keychainTransport;
  const received = [];
  const canceled = [];
  for (const kind of ["Get", "Create", "IsUvpaa"]) transport[`on${kind}Request`].addListener(request => received.push(request));
  transport.onRequestCanceled.addListener(id => canceled.push(id));
  transport.attach();
  function port(sender = {}) {
    const replies = [];
    const p = { name: "keychain-webauthn", sender: { id: runtime.id, tab: { id: 7 }, frameId: 0,
      url: "https://example.com/login", origin: "https://example.com", ...sender },
      onMessage: event(), onDisconnect: event(), disconnected: false,
      postMessage(value) { replies.push(value); }, disconnect() { if (this.disconnected) return; this.disconnected = true; this.onDisconnect.fire(); } };
    runtime.onConnect.fire(p);
    return { p, replies, send: message => p.onMessage.fire(message) };
  }
  return { browser, transport, port, received, canceled };
}
const options = () => ({ challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", rpId: "example.com", extensions: {} });
test("Firefox derives caller only from browser sender, defaults RP, and freezes options", async () => {
  const f = fixture(); const p = f.port(); const key = options(); delete key.rpId;
  p.send({ kind: "get", publicKey: key }); await tick();
  assert.equal(f.received.length, 1);
  key.challenge = "modified";
  const wire = JSON.parse(f.received[0].requestDetailsJson);
  assert.equal(wire.rpId, "example.com");
  assert.deepEqual(wire.extensions, { keychainFirefoxCaller: { origin: "https://example.com", topLevel: true } });
  assert.notEqual(wire.challenge, "modified");
});
test("Firefox rejects subframes, opaque/mismatched origins, HTTP and other extensions before native dispatch", async () => {
  for (const sender of [{ frameId: 1 }, { origin: "null" }, { origin: "https://evil.test" },
    { url: "http://example.com", origin: "http://example.com" }, { id: "other-extension" }, { url: "about:blank" }]) {
    const f = fixture(); const p = f.port(sender); await tick();
    assert.equal(p.p.disconnected, true); assert.equal(f.received.length, 0);
  }
});
test("Firefox refuses page-supplied origin envelopes and unexpected authority fields", async () => {
  for (const name of ["remoteDesktopClientOverride", "keychainFirefoxCaller"]) {
    const f = fixture(); const p = f.port();
    p.send({ kind: "get", publicKey: { ...options(), extensions: { [name]: { origin: "https://victim.test", topLevel: true } } } });
    await tick(); assert.equal(f.received.length, 0); assert.equal(p.replies[0].error.name, "SecurityError");
  }
  const f = fixture(); const p = f.port(); p.send({ kind: "get", origin: "https://victim.test", publicKey: options() });
  await tick(); assert.equal(f.received.length, 0);
});
test("Firefox disconnect and top-level navigation revoke a pending request and drop late results", async () => {
  for (const disconnect of [true, false]) {
    const f = fixture(); const p = f.port(); p.send({ kind: "get", publicKey: options() }); await tick();
    const id = f.received[0].requestId;
    if (disconnect) p.p.disconnect(); else f.browser.webNavigation.onBeforeNavigate.fire({ tabId: 7, frameId: 0 });
    assert.deepEqual(f.canceled, [id]);
    const count = p.replies.length;
    await f.transport.completeGetRequest({ requestId: id, responseJson: "late signature" });
    assert.equal(p.replies.length, count);
  }
});
test("Firefox disconnect during sender validation cannot start native work", async () => {
  const f = fixture(); let release;
  f.browser.tabs.get = () => new Promise(resolve => { release = resolve; });
  const p = f.port(); p.send({ kind: "create", publicKey: options() }); p.p.disconnect();
  release({ id: 7, url: "https://example.com" }); await tick();
  assert.equal(f.received.length, 0);
});
test("Firefox allows built-in fallback only when disabled before dispatch", async () => {
  const f = fixture(); await f.transport.detach(); const p = f.port(); p.send({ kind: "get", publicKey: options() }); await tick();
  assert.equal(p.replies[0].fallback, true); assert.equal(f.received.length, 0);
});
test("Firefox rejects a navigated caller before dispatch and consumes request ports once", async () => {
  const f = fixture(); f.browser.tabs.get = async id => ({ id, url: "https://evil.test" });
  const p = f.port(); p.send({ kind: "get", publicKey: options() }); await tick(); assert.equal(f.received.length, 0);
  const g = fixture(); const q = g.port(); q.send({ kind: "get", publicKey: options() }); await tick();
  q.send({ kind: "get", publicKey: options() }); await tick(); assert.equal(g.received.length, 1); assert.equal(g.canceled.length, 1);
});
