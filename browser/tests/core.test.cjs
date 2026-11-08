const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const event = () => ({ listeners: [], addListener(fn) { this.listeners.push(fn); } });
function makeFixture({ target, biometric = true, count = 1, holdAssertion = false, holdCreation = false, available = true, createError = null } = {}) {
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
            if (message.action === "create" && createError) {
              queueMicrotask(() => { if (!this.disconnected) this.onMessage.listeners.forEach((fn) => fn({ ok: false, error: createError })); });
              return;
            }
            const result = message.action === "capabilities"
              ? { kind: "capabilities", userVerificationAvailable: available }
              : message.action === "inspect"
              ? { kind: "inspection", biometric, candidates, rpId: "example.com", origin: "https://example.com" }
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
      local: { get: async () => ({ proxyEnabled: true }), set: async () => {} },
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
  const context = vm.createContext({ chrome, console, URL, setTimeout: (...args) => setTimeout(...args).unref(), clearTimeout, crypto: require("node:crypto").webcrypto });
  if (target === "firefox") {
    context.browser = { runtime: chrome.runtime, storage: chrome.storage, windows: chrome.windows, browserAction: chrome.action };
    vm.runInContext("globalThis.keychainApi = { ...browser, action: browser.browserAction }; globalThis.keychainTransport = chrome.webAuthenticationProxy", context);
  } else {
    context.importScripts = () => {};
    vm.runInContext(fs.readFileSync(`${__dirname}/../chromium/service-worker.js`, "utf8"), context);
  }
  vm.runInContext(fs.readFileSync(`${__dirname}/../shared/core.js`, "utf8"), context);
  return { context, chrome, ports, windows, closed, completed, created, operations, stored, availability };
}
const tick = () => new Promise((resolve) => setImmediate(resolve));

for (const target of ["chromium", "firefox"]) {
const fixture = options => makeFixture({ ...options, target });
const test = (name, fn) => require("node:test").test(`${target}: ${name}`, fn);
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

test("creation goes directly to native UI without browser storage selection", async () => {
  const f = fixture();
  await vm.runInContext('handleCreate({requestId:6,requestDetailsJson:"frozen-create",storage:"device-bound"})', f.context);
  assert.equal(f.windows.length, 0);
  assert.deepEqual(f.operations.map((op) => op.action), ["create"]);
  assert.match(f.operations[0].transaction, /^[a-f0-9-]{36}$/);
  assert.equal(f.operations[0].requestDetailsJson, "frozen-create");
  assert.equal(Object.hasOwn(f.operations[0], "storage"), false);
  assert.equal(f.created.length, 1);
  assert.equal(f.completed.length, 0);
  await vm.runInContext('handleCreate({requestId:6,requestDetailsJson:"frozen-create"})', f.context);
  assert.equal(f.operations.length, 1);
});

test("website abort disconnects native selection/capture and delivers no registration", async () => {
  const f = fixture({ holdCreation: true });
  const task = vm.runInContext('handleCreate({requestId:7,requestDetailsJson:"frozen"})', f.context);
  for (let i = 0; i < 20 && f.operations.length < 1; i++) await tick();
  assert.equal(f.operations[0].action, "create");
  f.chrome.webAuthenticationProxy.onRequestCanceled.listeners[0](7);
  await task;
  assert.equal(f.ports[0].disconnected, true);
  assert.equal(f.created.length, 0);
  assert.equal(f.windows.length, 0);
});

test("native chooser cancellation is returned once without another attempt", async () => {
  const f = fixture({ createError: { name: "NotAllowedError", message: "Canceled" } });
  await vm.runInContext('handleCreate({requestId:8,requestDetailsJson:"frozen"})', f.context);
  assert.equal(f.operations.length, 1);
  assert.equal(f.created[0].error.name, "NotAllowedError");
  assert.equal(f.created[0].responseJson, undefined);
  assert.equal(f.windows.length, 0);
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


test("native creation errors never fall back to another destination", async () => {
  const f = fixture({ createError: { name: "NotAllowedError", message: "Fresh Apple sign-in required" } });
  await vm.runInContext('handleCreate({requestId:80,requestDetailsJson:"frozen-icloud"})', f.context);
  assert.deepEqual(f.operations.map(op => op.action), ["create"]);
  assert.equal(f.operations[0].requestDetailsJson, "frozen-icloud");
  assert.equal(Object.hasOwn(f.operations[0], "storage"), false);
  assert.equal(f.created[0].error.name, "NotAllowedError");
  assert.equal(f.created[0].responseJson, undefined);
});

test("request deadlines disconnect a sleeping native caller and complete once", async () => {
  const f = fixture({ holdAssertion: true });
  const task = vm.runInContext('handleGet({requestId:91,requestDetailsJson:JSON.stringify({timeout:20})})', f.context);
  await Promise.all([task, new Promise(resolve => setTimeout(resolve, 35))]);
  assert.equal(f.ports.at(-1).disconnected, true);
  assert.equal(f.completed.length, 1);
  assert.equal(f.completed[0].error.name, "NotAllowedError");
  assert.equal(f.completed[0].responseJson, undefined);
});

test("an expired account picker cannot start signing", async () => {
  const f = fixture({ count: 2 });
  await vm.runInContext('handleGet({requestId:92,requestDetailsJson:JSON.stringify({timeout:15})})', f.context);
  await new Promise(resolve => setTimeout(resolve, 25));
  await vm.runInContext('approveRequest(92,"1")', f.context);
  assert.deepEqual(f.operations.map(op => op.action), ["inspect"]);
  assert.equal(f.completed.length, 1);
  assert.equal(f.completed[0].error.name, "NotAllowedError");
});
test("account picker messages require the exact extension page and matching request ID", () => {
  const f = fixture(); const listener = f.chrome.runtime.onMessage.listeners[0];
  for (const url of ["https://example.com/approval.html?requestId=1", "chrome-extension://test/approval.html.evil?requestId=1", "chrome-extension://test/approval.html?requestId=2"]) {
    assert.equal(listener({ type:"approve",requestId:1,passkeyId:"0" },{id:"test-extension",url},()=>{throw new Error("untrusted callback");}), false);
  }
  assert.equal(f.operations.length,0);
});

}
