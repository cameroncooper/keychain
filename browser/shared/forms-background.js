// Scoped password/code service shared by both browser adapters. Public account
// metadata stays in this connection; intentional secrets are never persisted.
(() => {
  const api = globalThis.keychainApi;
  const requests = new Set();
  const waiting = new Map();
  function nativeError(reply, fallback) {
    if(reply?.error?.name === "NotAllowedError" || reply?.error?.name === "AbortError") return "The request was canceled or not authorized. Choose the field again to continue.";
    if(reply?.error?.name === "SecurityError") return "This account could not be filled safely on this website.";
    return fallback;
  }
  function fail(request, message) {
    if (!request.live) return;
    try { request.port.postMessage({ kind: "error", message }); } finally { close(request); }
  }
  function close(request) {
    if (!request.live) return;
    request.live = false; requests.delete(request); clearTimeout(request.timer); request.resolveReady?.();
    for (const native of request.native) native.disconnect();
    request.native.clear(); request.port.disconnect();
  }
  function native(request, message) {
    return new Promise((resolve, reject) => {
      if (!request.live) { reject(new Error("The form request was canceled")); return; }
      const port = api.runtime.connectNative("cameroncooper.keychain");
      request.native.add(port);
      let done = false;
      const finish = (fn, value) => { if (done) return; done = true; clearTimeout(timer); request.native.delete(port); port.disconnect(); fn(value); };
      const timer = setTimeout(() => finish(reject, new Error("The form request expired")), 65000);
      port.onMessage.addListener(reply => finish(resolve, reply));
      port.onDisconnect.addListener(() => finish(reject, new Error(api.runtime.lastError?.message || "Keychain disconnected")));
      try { port.postMessage(message); } catch (error) { finish(reject, error); }
    });
  }
  async function current(request) {
    if (!request.live || Date.now() >= request.expires) throw new Error("The form request was canceled or expired");
    const tab = await api.tabs.get(request.tab);
    if (!request.live || new URL(tab.url).origin !== request.context.origin) throw new Error("The requesting website changed");
  }
  api.runtime.onConnect.addListener(port => {
    if (port.name !== "keychain-login") return;
    let url;
    try { url = KeychainSender.caller(port.sender, api.runtime.id); }
    catch { port.disconnect(); return; }
    if (requests.size >= 16 || [...requests].filter(request => request.tab === port.sender.tab.id).length >= 2) { port.disconnect(); return; }
    const request = { port, live: true, expires:Date.now()+120000, tab: port.sender.tab.id, native: new Set(), candidates: new Map(), inspected: false, used: false,
      context: { origin:url.origin,document:crypto.randomUUID(),target:crypto.randomUUID(),nonce:crypto.randomUUID() } };
    request.ready = new Promise(resolve => { request.resolveReady = resolve; });
    requests.add(request);
    const waiter = waiting.get(request.tab); if (waiter) { waiting.delete(request.tab); waiter(request); }
    request.timer = setTimeout(() => fail(request, "This form request expired. Choose the field again."),120000);
    port.onDisconnect.addListener(() => close(request));
    port.onMessage.addListener(message => {
      void (async () => {
        const { proxyEnabled = true } = await api.storage.local.get("proxyEnabled");
        if (!proxyEnabled) throw new Error("Keychain is turned off in this browser");
        await current(request);
        if (message?.kind === "inspect" && !request.inspected) {
          if (!["username","password","totp"].includes(message.field)) throw new Error("Invalid form field");
          request.field = message.field;
          request.inspected = true;
          const reply = await native(request, { version:1,action:"inspectLogins",context:request.context });
          await current(request);
          if (reply?.ok !== true || reply.result?.kind !== "logins" || !Array.isArray(reply.result.candidates) || reply.result.candidates.length > 64) {
            throw new Error(nativeError(reply,"Keychain could not read accounts. Open Keychain to check your setup."));
          }
          for (const candidate of reply.result.candidates) {
            if (typeof candidate.selection?.id !== "string" || typeof candidate.username !== "string") throw new Error("Invalid account metadata");
            request.candidates.set(candidate.selection.id, candidate);
          }
          request.managerAvailable = reply.result.managerAvailable === true;
          request.loaded = true; request.resolveReady();
          void api.runtime.sendMessage({type:"keychainAccountsChanged"}).catch(()=>{});
          port.postMessage({ kind:"candidates", managerAvailable:request.managerAvailable, candidates:[...request.candidates.values()].map(candidate => ({ id:candidate.selection.id,username:candidate.username,title:candidate.title,hasPassword:candidate.hasPassword,hasTotp:candidate.hasTotp })) });
          return;
        }
        if (message?.kind === "manager" && request.managerAvailable && !request.used) {
          request.used = true;
          const reply = await native(request,{version:1,action:"openManager"});
          if(reply?.ok !== true) throw new Error("The Keychain app could not be opened.");
          close(request); return;
        }
        if (message?.kind !== "fill" || !request.inspected || request.used || !["username","password","totp"].includes(message.field)) throw new Error("Invalid or already consumed form selection");
        const selected = request.candidates.get(message.id);
        if (!selected) throw new Error("This account was not offered for this website");
        request.used = true; // Revoke reuse before any asynchronous private call.
        if (message.field === "username") {
          port.postMessage({kind:"fill",field:"username",username:selected.username});close(request);return;
        }
        const reply = await native(request, { version:1,action:"fillLogin",context:request.context,selection:selected.selection,field:message.field });
        try {
          await current(request);
          if (reply?.ok !== true || reply.result?.kind !== "login" || reply.result.id !== selected.selection.id || reply.result.revision !== selected.selection.revision) {
            throw new Error(nativeError(reply,"Keychain could not complete this request. Open Keychain to check your setup."));
          }
          port.postMessage({kind:"fill",field:message.field,username:selected.username,result:reply.result});
          close(request);
        } finally {
          if (reply?.result) { delete reply.result.password; delete reply.result.totp; }
        }
      })().catch(error => fail(request, error.message));
    });
  });
  function revokeTab(id) { for (const request of [...requests]) if (request.tab === id) close(request); }
  api.tabs.onRemoved.addListener(revokeTab);
  api.webNavigation.onBeforeNavigate.addListener(details => { if (details.frameId === 0) revokeTab(details.tabId); });
  globalThis.keychainForms = {
    cancelAll() { for (const request of [...requests]) close(request); },
    async prepare(tab) {
      let request = [...requests].find(item => item.tab === tab && item.live);
      if (!request) {
        let timer;
        const connection = new Promise(resolve => {
          waiting.set(tab, resolve);
          timer = setTimeout(() => { waiting.delete(tab); resolve(null); }, 2000);
        });
        try {
          const response = await api.tabs.sendMessage(tab, {type:"keychainInspectForm"});
          if (response?.ok !== true) { waiting.get(tab)?.(null); waiting.delete(tab); }
          request = await connection;
        } catch { waiting.get(tab)?.(null); waiting.delete(tab); }
        finally { clearTimeout(timer); }
      }
      if (!request) return null;
      let timer;
      try { await Promise.race([request.ready, new Promise(resolve => { timer = setTimeout(resolve, 5000); })]); }
      finally { clearTimeout(timer); }
      if (!request.live || !request.field) return null;
      return { handle:request.context.nonce, field:request.field, loading:!request.loaded,
        candidates:[...request.candidates.values()].filter(candidate => request.field === "totp" ? candidate.hasTotp : request.field === "password" ? candidate.hasPassword : true)
          .map(candidate => ({id:candidate.selection.id,username:candidate.username,title:candidate.title})) };
    },
    async choose(tab, handle, id) {
      const request = [...requests].find(item => item.tab === tab && item.context.nonce === handle && item.live);
      if (!request || request.used || request.intent || !request.candidates.has(id)) throw new Error("This account selection is no longer active");
      await current(request);
      request.intent = id;
      request.port.postMessage({kind:"select",id});
    },
  };
})();
