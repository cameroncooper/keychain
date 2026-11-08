// Firefox's Xray/exportFunction boundary keeps extension APIs out of page code.
// Only this document's public options enter its background port. No DOM message
// bridge and no page-supplied caller metadata are used.
(() => {
  if (!window.isSecureContext || window !== window.top || window.origin === "null" ||
      window.origin !== new URL(document.URL).origin || !navigator.credentials || !window.PublicKeyCredential) return;
  const page = window.wrappedJSObject;
  const target = page.navigator.credentials;
  const original = { get: target.get.bind(target), create: target.create.bind(target),
    available: page.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable.bind(page.PublicKeyCredential) };
  const active = new Set();
  function pageError(error) { return new window.DOMException(String(error.message ?? error), String(error.name ?? "UnknownError")); }
  function pageCredential(json) {
    const plain = KeychainWebAuthn.credential(json);
    const result = cloneInto(plain, window, { cloneFunctions: true }).wrappedJSObject;
    // Exported methods also need page-realm return values; cloneFunctions alone
    // would expose content-compartment ArrayBuffers/objects on later calls.
    for (const [destination, source, names] of [
      [result, plain, ["toJSON", "getClientExtensionResults"]],
      [result.response, plain.response, ["getAuthenticatorData", "getPublicKey", "getPublicKeyAlgorithm", "getTransports"]],
    ]) {
      for (const name of names) if (typeof source[name] === "function") {
        exportFunction(() => {
          const value = source[name]();
          return value !== null && typeof value === "object" ? cloneInto(value, window) : value;
        }, destination, { defineAs: name });
      }
    }
    // Capture the response before changing prototypes: an Xray view of the
    // credential would otherwise invoke the native response getter without slots.
    const response = result.response;
    Object.setPrototypeOf(result, page.PublicKeyCredential.prototype);
    Object.setPrototypeOf(response, plain.response.attestationObject
      ? page.AuthenticatorAttestationResponse.prototype : page.AuthenticatorAssertionResponse.prototype);
    return result;
  }
  function request(kind, options = {}) {
    // Promises and credentials must belong to the page realm, not the privileged
    // content-script compartment. No callable extension/browser objects leak.
    return new window.Promise(exportFunction((resolve, reject) => {
      let port;
      let timer;
      let done = false;
      let signal;
      const finish = (fn, value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        try { signal?.removeEventListener("abort", abort); } catch {}
        if (port) { active.delete(port); port.disconnect(); }
        fn(value);
      };
      const abort = () => finish(reject, pageError({ name: "AbortError", message: "The passkey request was aborted" }));
      try {
        if (kind !== "available" && !options.publicKey) {
          finish(resolve, original[kind](options)); return;
        }
        if (options.mediation === "conditional") {
          throw { name: "NotSupportedError", message: "Keychain does not yet support Firefox conditional mediation" };
        }
        signal = options.signal;
        if (signal?.aborted) { abort(); return; }
        const publicKey = kind === "available" ? undefined : KeychainWebAuthn.serialize(kind, options.publicKey);
        signal?.addEventListener("abort", abort, { once: true });
        port = browser.runtime.connect({ name: "keychain-webauthn" });
        active.add(port);
        // Bound the complete UI/native lifetime. Timers are browser events, not
        // authorization factors. Disconnect propagates through the native host.
        const timeout = Number(options.publicKey?.timeout ?? 120000);
        timer = setTimeout(() => finish(reject, pageError({ name: "NotAllowedError", message: "The passkey request expired" })),
          Number.isFinite(timeout) ? Math.min(120000, Math.max(1, timeout)) : 120000);
        port.onMessage.addListener(reply => {
          if (signal?.aborted) { abort(); return; }
          if (reply?.fallback === true) { finish(resolve, original[kind](options)); return; }
          if (reply?.error) { finish(reject, pageError(reply.error)); return; }
          try {
            if (kind === "available") finish(resolve, reply.available === true);
            else if (typeof reply?.responseJson === "string") finish(resolve, pageCredential(reply.responseJson));
            else throw new Error("The native host returned an invalid response");
          } catch (error) { finish(reject, pageError(error)); }
        });
        port.onDisconnect.addListener(() => finish(reject, pageError({ name: "NotAllowedError", message: "Keychain disconnected" })));
        port.postMessage(kind === "available" ? { kind } : { kind, publicKey });
      } catch (error) { finish(reject, pageError(error)); }
    }, window));
  }
  for (const kind of ["get", "create"]) {
    exportFunction(options => request(kind, options), target, { defineAs: kind });
  }
  exportFunction(() => request("available"), page.PublicKeyCredential, { defineAs: "isUserVerifyingPlatformAuthenticatorAvailable" });
  // Back/forward-cache suspension must not preserve an authorization request.
  window.addEventListener("pagehide", () => { for (const port of active) port.disconnect(); active.clear(); });
})();
