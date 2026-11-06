const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const event = () => ({ listeners: [], addListener(fn) { this.listeners.push(fn); } });
function fixture({ biometric = true, count = 1, holdAssertion = false, available = true } = {}) {
  const stored = {};
  const ports = [];
  const windows = [];
  const completed = [];
  const availability = [];
  const operations = [];
  const candidates = Array.from({ length: count }, (_, id) => ({ id: String(id), username: `account-${id}` }));
  const chrome = {
    runtime: {
      id: "test-extension", getURL: (path) => `chrome-extension://test/${path}`,
      onMessage: event(), onInstalled: event(), onStartup: event(),
      sendMessage: async () => {},
      connectNative() {
        const port = { onMessage: event(), onDisconnect: event(), disconnected: false,
          disconnect() {
            if (this.disconnected) return;
            this.disconnected = true;
            this.onDisconnect.listeners.forEach((fn) => fn());
          },
          postMessage(message) {
            operations.push(message);
            if (message.action === "assert" && holdAssertion) return;
            const result = message.action === "capabilities"
              ? { kind: "capabilities", userVerificationAvailable: available }
              : message.action === "inspect"
              ? { kind: "inspection", biometric, candidates, rpId: "example.com", origin: "https://example.com" }
              : { kind: "assertion", responseJson: "{}" };
            queueMicrotask(() => { if (!this.disconnected) this.onMessage.listeners.forEach((fn) => fn({ ok: true, result })); });
          },
        };
        ports.push(port);
        return port;
      },
    },
    action: { onClicked: event(), setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setTitle: async () => {} },
    storage: {
      local: { get: async () => ({ proxyEnabled: false }), set: async () => {} },
      session: { get: async (key) => ({ [key]: stored[key] }), set: async (value) => Object.assign(stored, value),
        remove: async (key) => { delete stored[key]; }, clear: async () => {} },
    },
    windows: { create: async (value) => { windows.push(value); } },
    webAuthenticationProxy: {
      attach: async () => {}, detach: async () => {},
      onGetRequest: event(), onCreateRequest: event(), onIsUvpaaRequest: event(), onRequestCanceled: event(),
      completeGetRequest: async (value) => { completed.push(value); },
      completeIsUvpaaRequest: async (value) => { availability.push(value); },
    },
  };
  const context = vm.createContext({ chrome, console });
  vm.runInContext(fs.readFileSync(`${__dirname}/service-worker.js`, "utf8"), context);
  return { context, chrome, ports, windows, completed, operations, stored, availability };
}
const tick = () => new Promise((resolve) => setImmediate(resolve));

test("one biometric account starts signing without an approval window", async () => {
  const f = fixture();
  await vm.runInContext('handleGet({requestId:1,requestDetailsJson:"frozen"})', f.context);
  assert.equal(f.windows.length, 0);
  assert.deepEqual(f.operations.map((op) => op.action), ["inspect", "assert"]);
  assert.equal(f.operations[1].requestDetailsJson, "frozen");
  assert.equal(f.completed.length, 1);
  assert.equal(f.completed[0].responseJson, "{}");
});

test("multiple biometric accounts require selection, and selection is consumed", async () => {
  const f = fixture({ count: 2 });
  await vm.runInContext('handleGet({requestId:2,requestDetailsJson:"frozen"})', f.context);
  assert.equal(f.windows.length, 1);
  assert.deepEqual(f.operations.map((op) => op.action), ["inspect"]);
  await vm.runInContext('approveRequest(2,"1")', f.context);
  assert.equal(f.operations[1].passkeyId, "1");
  await vm.runInContext('approveRequest(2,"1")', f.context);
  assert.equal(f.operations.filter((op) => op.action === "assert").length, 1);
});

test("software credentials retain explicit presence approval", async () => {
  const f = fixture({ biometric: false });
  await vm.runInContext('handleGet({requestId:3,requestDetailsJson:"frozen"})', f.context);
  assert.equal(f.windows.length, 1);
  assert.deepEqual(f.operations.map((op) => op.action), ["inspect"]);
});

test("website abort disconnects a pending native assertion and delivers no response", async () => {
  const f = fixture({ holdAssertion: true });
  const task = vm.runInContext('handleGet({requestId:4,requestDetailsJson:"frozen"})', f.context);
  for (let i = 0; i < 20 && f.operations.length < 2; i++) await tick();
  assert.equal(f.operations.length, 2);
  f.chrome.webAuthenticationProxy.onRequestCanceled.listeners[0](4);
  await task;
  assert.equal(f.ports[1].disconnected, true);
  assert.equal(f.completed.length, 0);
  assert.equal(f.stored["pending:4"], undefined);
});

test("authenticator availability uses the native backend result without opening a dialog", async () => {
  for (const available of [true, false]) {
    const f = fixture({ available });
    await vm.runInContext("handleIsUvpaa({requestId:5})", f.context);
    assert.equal(f.availability[0].isUvpaa, available);
    assert.equal(f.windows.length, 0);
    assert.deepEqual(f.operations.map((op) => op.action), ["capabilities"]);
  }
});
