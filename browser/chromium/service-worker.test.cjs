const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const event = () => ({ listeners: [], addListener(fn) { this.listeners.push(fn); } });
function fixture({ biometric = true, count = 1, holdAssertion = false, holdCreation = false, available = true } = {}) {
  const stored = {};
  const ports = [];
  const windows = [];
  const completed = [];
  const created = [];
  const closed = [];
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
            if (message.action === "create" && holdCreation) return;
            const result = message.action === "capabilities"
              ? { kind: "capabilities", userVerificationAvailable: available }
              : message.action === "inspect"
              ? { kind: "inspection", biometric, candidates, rpId: "example.com", origin: "https://example.com" }
              : message.action === "inspectCreation"
              ? { kind: "creationInspection", storageChoices: ["device-bound"], rpId: "example.com", origin: "https://example.com" }
              : message.action === "create"
              ? { kind: "registration", responseJson: "{\"type\":\"public-key\"}" }
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
      session: { get: async (key) => key === null ? { ...stored } : ({ [key]: stored[key] }), set: async (value) => Object.assign(stored, value),
        remove: async (key) => { delete stored[key]; }, clear: async () => {} },
    },
    windows: { onRemoved: event(), create: async (value) => { windows.push(value); return { id: windows.length }; },
      remove: async (id) => { closed.push(id); chrome.windows.onRemoved.listeners.forEach((fn) => fn(id)); } },
    webAuthenticationProxy: {
      attach: async () => {}, detach: async () => {},
      onGetRequest: event(), onCreateRequest: event(), onIsUvpaaRequest: event(), onRequestCanceled: event(),
      completeGetRequest: async (value) => { completed.push(value); },
      completeCreateRequest: async (value) => { created.push(value); },
      completeIsUvpaaRequest: async (value) => { availability.push(value); },
    },
  };
  const context = vm.createContext({ chrome, console, crypto: require("node:crypto").webcrypto });
  vm.runInContext(fs.readFileSync(`${__dirname}/service-worker.js`, "utf8"), context);
  return { context, chrome, ports, windows, closed, completed, created, operations, stored, availability };
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
  assert.equal(f.completed.length, 1);
});

test("registration requires explicit storage selection and consumes it before biometrics", async () => {
  const f = fixture();
  await vm.runInContext('handleCreate({requestId:6,requestDetailsJson:"frozen-create"})', f.context);
  assert.equal(f.windows.length, 1);
  assert.deepEqual(f.operations.map((op) => op.action), ["inspectCreation"]);
  const transaction = f.stored["pending:6"].transaction;
  assert.match(transaction, /^[a-f0-9-]{36}$/);
  await vm.runInContext('createRequest(6,"synced")', f.context);
  assert.equal(f.operations.length, 1); // no cloud-to-local fallback
  await vm.runInContext('createRequest(6,"device-bound")', f.context);
  assert.deepEqual(f.operations.map((op) => op.action), ["inspectCreation", "create"]);
  assert.equal(f.operations[1].transaction, transaction);
  assert.equal(f.operations[1].requestDetailsJson, "frozen-create");
  assert.equal(f.stored["pending:6"], undefined);
  assert.deepEqual(f.closed, [1]); // application window closes before OS prompt
  assert.equal(f.created.length, 1);
  assert.equal(f.created[0].responseJson, '{"type":"public-key"}');
  assert.equal(f.completed.length, 0);
  await vm.runInContext('createRequest(6,"device-bound")', f.context);
  assert.equal(f.operations.length, 2);
  assert.equal(f.created.length, 1);
});

test("website abort disconnects native registration and returns no creation response", async () => {
  const f = fixture({ holdCreation: true });
  await vm.runInContext('handleCreate({requestId:7,requestDetailsJson:"frozen"})', f.context);
  const task = vm.runInContext('createRequest(7,"device-bound")', f.context);
  for (let i = 0; i < 20 && f.operations.length < 2; i++) await tick();
  assert.equal(f.operations[1].action, "create");
  f.chrome.webAuthenticationProxy.onRequestCanceled.listeners[0](7);
  await task;
  assert.equal(f.ports[1].disconnected, true);
  assert.equal(f.created.length, 0);
  assert.equal(f.completed.length, 0);
});

test("closing the storage selection cancels creation without generating a key", async () => {
  const f = fixture();
  await vm.runInContext('handleCreate({requestId:8,requestDetailsJson:"frozen"})', f.context);
  f.chrome.windows.onRemoved.listeners[0](1);
  await tick();
  assert.equal(f.operations.length, 1);
  assert.equal(f.created.length, 1);
  assert.equal(f.created[0].error.name, "NotAllowedError");
  assert.equal(f.completed.length, 0);
  assert.equal(f.stored["pending:8"], undefined);
});

test("closing a restored chooser still completes creation after worker memory is lost", async () => {
  const f = fixture();
  await vm.runInContext('handleCreate({requestId:9,requestDetailsJson:"frozen"})', f.context);
  assert.equal(f.stored["pending:9"].windowId, 1);
  vm.runInContext('selectionWindows.clear(); requestKinds.clear()', f.context);
  await vm.runInContext('cancelClosedSelection(1)', f.context);
  assert.equal(f.created.length, 1);
  assert.equal(f.created[0].error.name, "NotAllowedError");
  assert.equal(f.completed.length, 0);
  assert.equal(f.operations.length, 1);
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
