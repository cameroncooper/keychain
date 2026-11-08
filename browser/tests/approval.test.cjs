const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

// Minimal document fixture; real Chromium rendering is checked separately.
async function fixture(target) {
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
        if (message.type === "getPending") return { ok: true, pending: { kind: "get", inspection: {
          rpId: "example.com", origin: "https://example.com",
          username: "alice", biometric: true, candidates: [{ id: "credential-1", username: "alice" }],
        } } };
        return { ok: true };
      },
    } },
  });
  if (target === "firefox") { context.browser = context.chrome; delete context.chrome; }
  vm.runInContext(fs.readFileSync(`${__dirname}/../shared/approval.js`, "utf8"), context);
  await new Promise((resolve) => setImmediate(resolve));
  return { document, nodes, inputs, messages, closed: () => closed,
    submit: () => nodes.get("#approval-form").listeners.submit({ preventDefault() {} }) };
}

for (const target of ["chromium", "firefox"]) {
const test = (name, fn) => require("node:test").test(`${target}: ${name}`, fn);
test("Escape denies the request without sending a create action", async () => {
  const f = await fixture(target);
  f.document.keydown({ key: "Escape", preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.messages.at(-1).type, "deny");
  assert.equal(f.closed(), true);
  assert.equal(f.messages.some((message) => message.type === "create"), false);
});

test("the account chooser still submits an assertion selection", async () => {
  const f = await fixture(target);
  await f.submit();
  assert.equal(f.messages.at(-1).type, "approve");
  assert.equal(f.messages.at(-1).passkeyId, "credential-1");
});

}
