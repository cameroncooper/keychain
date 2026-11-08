// Firefox-only ingress. Page data is untrusted; only runtime.Port.sender binds
// a caller. No MAIN-world script, DOM message or page-supplied origin is trusted.
(() => {
  const event = () => ({ listeners: [], addListener(fn) { this.listeners.push(fn); },
    fire(...args) { for (const fn of this.listeners) fn(...args); } });
  const pending = new Map();
  let nextId = 1;
  let enabled = false;
  function fail(port, message, name = "SecurityError") {
    try { port.postMessage({ error: { name, message } }); } finally { port.disconnect(); }
  }
  function finish(id, response) {
    const request = pending.get(id);
    if (!request) return;
    pending.delete(id);
    try { request.port.postMessage(response); } finally { request.port.disconnect(); }
  }
  const transport = {
    onGetRequest: event(), onCreateRequest: event(), onIsUvpaaRequest: event(), onRequestCanceled: event(),
    async attach() { enabled = true; },
    async detach() {
      enabled = false;
      for (const id of [...pending.keys()]) {
        transport.onRequestCanceled.fire(id);
        finish(id, { error: { name: "NotAllowedError", message: "Keychain was disabled" } });
      }
    },
    async completeGetRequest({ requestId, ...result }) { finish(requestId, result); },
    async completeCreateRequest({ requestId, ...result }) { finish(requestId, result); },
    async completeIsUvpaaRequest({ requestId, isUvpaa }) { finish(requestId, { available: isUvpaa === true }); },
  };
  globalThis.keychainApi = { runtime: browser.runtime, storage: browser.storage,
    windows: browser.windows, tabs: browser.tabs, webNavigation: browser.webNavigation, action: browser.browserAction };
  globalThis.keychainTransport = transport;

  browser.runtime.onConnect.addListener((port) => {
    if (port.name !== "keychain-webauthn") return;
    let url;
    try { url = KeychainSender.caller(port.sender, browser.runtime.id); }
    catch (error) { fail(port, error.message); return; }
    if (pending.size >= 64 || [...pending.values()].filter(request => request.tab === port.sender.tab.id).length >= 4 || !Number.isSafeInteger(nextId)) {
      fail(port, "Too many passkey requests", "NotAllowedError"); return;
    }
    const id = nextId++;
    // Include connections still awaiting their first message/tab validation in
    // the bound; asynchronous sender checks must not create an unbounded queue.
    pending.set(id, { port, tab: port.sender.tab.id });
    let received = false;
    let disconnected = false;
    port.onDisconnect.addListener(() => {
      disconnected = true;
      if (pending.delete(id)) transport.onRequestCanceled.fire(id);
    });
    port.onMessage.addListener((message) => {
      if (received) { fail(port, "A request connection may be used only once"); return; }
      received = true;
      void (async () => {
        if (!enabled) { port.postMessage({ fallback: true }); port.disconnect(); return; }
        if (!message || !["get", "create", "available"].includes(message.kind) ||
            Object.keys(message).some(key => !["kind", "publicKey"].includes(key))) {
          throw new Error("Invalid passkey request");
        }
        const tab = await browser.tabs.get(port.sender.tab.id);
        if (disconnected) return;
        if (new URL(tab.url).origin !== url.origin) throw new Error("The requesting document navigated");
        if (message.kind === "available") {
          transport.onIsUvpaaRequest.fire({ requestId: id }); return;
        }
        // Freeze a JSON-only copy; never allow page caller metadata to cross
        // the background boundary. RP defaults to the browser-bound hostname.
        const options = JSON.parse(JSON.stringify(message.publicKey));
        if (!options || typeof options !== "object" || Array.isArray(options) ||
            JSON.stringify(options).length > 256 * 1024) throw new Error("Invalid WebAuthn options");
        const extensions = options.extensions ?? {};
        if (typeof extensions !== "object" || Array.isArray(extensions) ||
            Object.hasOwn(extensions, "remoteDesktopClientOverride") || Object.hasOwn(extensions, "keychainFirefoxCaller")) {
          throw new Error("Page-supplied caller metadata is forbidden");
        }
        options.extensions = { ...extensions, keychainFirefoxCaller: { origin: url.origin, topLevel: true } };
        if (message.kind === "get") options.rpId ??= url.hostname;
        const request = { requestId: id, requestDetailsJson: JSON.stringify(options) };
        transport[message.kind === "get" ? "onGetRequest" : "onCreateRequest"].fire(request);
      })().catch(error => { pending.delete(id); fail(port, error.message); });
    });
  });
  function revokeTab(tabId) {
    for (const [id, request] of pending) {
      if (request.tab === tabId) {
        transport.onRequestCanceled.fire(id);
        finish(id, { error: { name: "AbortError", message: "The requesting document navigated or closed" } });
      }
    }
  }
  browser.tabs.onRemoved.addListener(revokeTab);
  browser.webNavigation.onBeforeNavigate.addListener(details => { if (details.frameId === 0) revokeTab(details.tabId); });
})();
