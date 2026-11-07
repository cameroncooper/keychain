const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

// Minimal document fixture; real Chromium rendering is checked separately.
async function fixture(storageChoices, kind = "create") {
  const inputs = [];
  class Element {
    constructor(tag) {
      this.tag = tag; this.children = []; this.listeners = {};
      this.hidden = false; this.textContent = "";
      this.attributes = {}; this.classList = { add() {} };
      if (tag === "input") inputs.push(this);
    }
    append(...children) { this.children.push(...children); }
    addEventListener(type, callback) { this.listeners[type] = callback; }
    setAttribute(key, value) { this.attributes[key] = value; }
    removeAttribute(key) { delete this.attributes[key]; }
    click() { return this.listeners.click?.(); }
    set checked(value) {
      if (value) inputs.forEach((input) => { input.selected = false; });
      this.selected = value;
    }
    get checked() { return this.selected; }
  }
  const nodes = new Map();
  const document = {
    body: new Element("body"),
    querySelector(selector) {
      if (!nodes.has(selector)) nodes.set(selector, new Element(selector));
      return nodes.get(selector);
    },
    createElement: (tag) => new Element(tag),
    addEventListener(type, callback) { this[type] = callback; },
  };
  const messages = [];
  let closed = false;
  const context = vm.createContext({ document, URLSearchParams,
    location: { search: "?requestId=42" }, window: { close() { closed = true; } },
    FormData: class { get() { return inputs.find((input) => input.checked)?.value ?? null; } },
    chrome: { runtime: {
      onMessage: { addListener() {} },
      async sendMessage(message) {
        messages.push(message);
        if (message.type === "getPending") return { ok: true, pending: { kind, inspection: {
          storageChoices, rpId: "example.com", origin: "https://example.com",
          username: "alice", biometric: true, candidates: [{ id: "credential-1", username: "alice" }],
        } } };
        return { ok: true };
      },
    } },
  });
  vm.runInContext(fs.readFileSync(`${__dirname}/approval.js`, "utf8"), context);
  await new Promise((resolve) => setImmediate(resolve));
  return { document, nodes, inputs, messages, closed: () => closed,
    submit: () => nodes.get("#approval-form").listeners.submit({ preventDefault() {} }) };
}

test("iCloud is selected regardless of provider ordering, without starting creation", async () => {
  const f = await fixture(["device-bound", "synced"]);
  assert.equal(f.inputs.find((input) => input.checked).value, "synced");
  assert.equal(f.nodes.get("#choices").hidden, true);
  assert.equal(f.nodes.get("#other-options").hidden, false);
  assert.deepEqual(f.messages.map((message) => message.type), ["getPending"]);
  await f.submit();
  assert.equal(f.messages.at(-1).storage, "synced");
  assert.equal(f.messages.at(-1).requestId, 42);
});

test("Other Options changes the submitted destination and its explanation", async () => {
  const f = await fixture(["synced", "device-bound"]);
  f.nodes.get("#other-options").click();
  assert.equal(f.nodes.get("#choices").hidden, false);
  assert.equal(f.nodes.get("#other-options").attributes["aria-expanded"], "true");
  f.inputs.find((input) => input.value === "device-bound").checked = true;
  f.nodes.get("#approval-form").listeners.change();
  assert.match(f.nodes.get("#notice").textContent, /this device only/);
  await f.submit();
  assert.equal(f.messages.at(-1).storage, "device-bound");
});

test("a device-only provider never defaults to unavailable iCloud storage", async () => {
  const f = await fixture(["device-bound"]);
  assert.equal(f.nodes.get("#other-options").hidden, true);
  assert.match(f.nodes.get("#notice").textContent, /this device only/);
  await f.submit();
  assert.equal(f.messages.at(-1).storage, "device-bound");
});

test("Escape denies the request without sending a create action", async () => {
  const f = await fixture(["synced", "device-bound"]);
  f.document.keydown({ key: "Escape", preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.messages.at(-1).type, "deny");
  assert.equal(f.closed(), true);
  assert.equal(f.messages.some((message) => message.type === "create"), false);
});

test("the account chooser still submits an assertion selection", async () => {
  const f = await fixture([], "get");
  await f.submit();
  assert.equal(f.messages.at(-1).type, "approve");
  assert.equal(f.messages.at(-1).passkeyId, "credential-1");
});
