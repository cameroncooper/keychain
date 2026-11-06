const NATIVE_HOST = "cameroncooper.keychain";
const APPROVAL_PAGE = chrome.runtime.getURL("approval.html");
const pendingKey = (requestId) => `pending:${requestId}`;
const canceledRequests = new Set();
const processingRequests = new Set();
const activeNative = new Map();

function domError(name, message) {
  return { name, message };
}

async function attach() {
  try {
    await chrome.webAuthenticationProxy.attach();
    await chrome.action.setBadgeText({ text: "ON" });
    await chrome.action.setBadgeBackgroundColor({ color: "#1769e0" });
    await chrome.action.setTitle({ title: "Keychain Passkeys: enabled (click to disable)" });
    return true;
  } catch (error) {
    console.error("Could not attach WebAuthentication proxy", error);
    await chrome.action.setBadgeText({ text: "ERR" });
    await chrome.action.setBadgeBackgroundColor({ color: "#b42318" });
    await chrome.action.setTitle({ title: "Keychain Passkeys: could not attach" });
    return false;
  }
}

async function detach() {
  for (const [requestId, port] of activeNative) {
    canceledRequests.add(requestId);
    port.disconnect();
  }
  activeNative.clear();
  await chrome.webAuthenticationProxy.detach();
  await chrome.storage.session.clear();
  await chrome.action.setBadgeText({ text: "OFF" });
  await chrome.action.setBadgeBackgroundColor({ color: "#666666" });
  await chrome.action.setTitle({ title: "Keychain Passkeys: disabled (click to enable)" });
}

async function ensureProxyState() {
  const { proxyEnabled = true } = await chrome.storage.local.get("proxyEnabled");
  if (proxyEnabled) {
    await attach();
  } else {
    await detach();
  }
}

async function completeGetWithError(requestId, error) {
  if (canceledRequests.has(requestId)) {
    return;
  }
  try {
    await chrome.webAuthenticationProxy.completeGetRequest({ requestId, error });
  } catch (completionError) {
    console.error("Could not complete WebAuthn request", completionError);
  }
}

async function callNative(message, requestId) {
  if (canceledRequests.has(requestId)) {
    throw new Error("The website canceled this request");
  }
  const reply = await new Promise((resolve, reject) => {
    const port = chrome.runtime.connectNative(NATIVE_HOST);
    activeNative.set(requestId, port);
    let finished = false;
    function finish(callback, value) {
      if (finished) return;
      finished = true;
      if (activeNative.get(requestId) === port) activeNative.delete(requestId);
      port.disconnect();
      callback(value);
    }
    port.onMessage.addListener((reply) => finish(resolve, reply));
    port.onDisconnect.addListener(() => {
      const message = chrome.runtime.lastError?.message || "The native host disconnected";
      finish(reject, new Error(message));
    });
    try { port.postMessage(message); }
    catch (error) { finish(reject, error); }
  });
  if (!reply || typeof reply !== "object") {
    throw new Error("The native host returned no reply");
  }
  return reply;
}

async function handleGet(request) {
  const requestId = request.requestId;
  canceledRequests.delete(requestId);
  try {
    const reply = await callNative({
      version: 1,
      action: "inspect",
      requestDetailsJson: request.requestDetailsJson,
    }, requestId);
    if (!reply.ok) {
      await completeGetWithError(
        requestId,
        reply.error || domError("UnknownError", "The native host rejected the request"),
      );
      return;
    }
    if (reply.result?.kind !== "inspection" || !Array.isArray(reply.result.candidates)) {
      await completeGetWithError(
        requestId,
        domError("UnknownError", "The native host returned an invalid inspection"),
      );
      return;
    }
    if (canceledRequests.has(requestId)) return;
    await chrome.storage.session.set({
      [pendingKey(requestId)]: {
        requestId,
        requestDetailsJson: request.requestDetailsJson,
        inspection: reply.result,
      },
    });
    // One biometric-backed account goes directly to the desktop prompt. The
    // browser picker is needed only to choose among accounts. Software presence
    // approval stays explicit until that credential has been migrated.
    if (reply.result.biometric === true && reply.result.candidates.length === 1) {
      await approveRequest(requestId, reply.result.candidates[0].id);
      return;
    }
    try {
      await chrome.windows.create({
        url: `${APPROVAL_PAGE}?requestId=${encodeURIComponent(requestId)}`,
        type: "popup",
        width: 440,
        height: 560,
        focused: true,
      });
    } catch (error) {
      await chrome.storage.session.remove(pendingKey(requestId));
      throw error;
    }
  } catch (error) {
    await completeGetWithError(
      requestId,
      domError("UnknownError", error instanceof Error ? error.message : String(error)),
    );
  }
}

async function pendingRequest(requestId) {
  const key = pendingKey(requestId);
  const values = await chrome.storage.session.get(key);
  return values[key] || null;
}

async function approveRequest(requestId, passkeyId) {
  if (processingRequests.has(requestId)) {
    throw new Error("This request is already being processed");
  }
  processingRequests.add(requestId);
  try {
    const pending = await pendingRequest(requestId);
    if (!pending) {
      throw new Error("This passkey request is no longer active");
    }
    const eligible = pending.inspection.candidates.some(
      (candidate) => candidate.id === passkeyId,
    );
    if (!eligible) {
      throw new Error("The selected passkey is not eligible for this request");
    }

    // Consume the selection before signing so it cannot be replayed.
    await chrome.storage.session.remove(pendingKey(requestId));
    const reply = await callNative({
      version: 1,
      action: "assert",
      requestDetailsJson: pending.requestDetailsJson,
      passkeyId,
    }, requestId);
    if (!reply.ok) {
      await completeGetWithError(
        requestId,
        reply.error || domError("UnknownError", "The native host rejected the assertion"),
      );
      return { ok: false, message: reply.error?.message || "Assertion rejected" };
    }
    if (reply.result?.kind !== "assertion" || typeof reply.result.responseJson !== "string") {
      await completeGetWithError(
        requestId,
        domError("UnknownError", "The native host returned an invalid assertion"),
      );
      return { ok: false, message: "The native host returned an invalid assertion" };
    }
    if (canceledRequests.has(requestId)) {
      return { ok: false, message: "The website canceled this request" };
    }
    await chrome.webAuthenticationProxy.completeGetRequest({
      requestId,
      responseJson: reply.result.responseJson,
    });
    return { ok: true };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await completeGetWithError(requestId, domError("UnknownError", message));
    return { ok: false, message };
  } finally {
    processingRequests.delete(requestId);
  }
}

async function denyRequest(requestId) {
  await chrome.storage.session.remove(pendingKey(requestId));
  await completeGetWithError(
    requestId,
    domError("NotAllowedError", "The passkey request was not approved"),
  );
  return { ok: true };
}

chrome.webAuthenticationProxy.onGetRequest.addListener((request) => {
  void handleGet(request);
});

chrome.webAuthenticationProxy.onCreateRequest.addListener((request) => {
  void chrome.webAuthenticationProxy.completeCreateRequest({
    requestId: request.requestId,
    error: domError("NotSupportedError", "Creating passkeys is not supported yet"),
  });
});

async function handleIsUvpaa(request) {
  const requestId = request.requestId;
  canceledRequests.delete(requestId);
  let available = false;
  try {
    const reply = await callNative({ version: 1, action: "capabilities" }, requestId);
    available = reply?.ok === true && reply.result?.kind === "capabilities" &&
      reply.result.userVerificationAvailable === true;
  } catch {
    // Unavailable service/UI/hardware cannot advertise verified authentication.
  }
  if (canceledRequests.has(requestId)) return;
  try {
    await chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId, isUvpaa: available });
  } catch (error) {
    console.error("Could not complete authenticator availability request", error);
  }
}

chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener((request) => {
  void handleIsUvpaa(request);
});

chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId) => {
  canceledRequests.add(requestId);
  activeNative.get(requestId)?.disconnect();
  activeNative.delete(requestId);
  void chrome.storage.session.remove(pendingKey(requestId));
  void chrome.runtime.sendMessage({ type: "requestCanceled", requestId }).catch(() => {});
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(APPROVAL_PAGE)) {
    return false;
  }
  const requestId = Number(message?.requestId);
  if (!Number.isSafeInteger(requestId)) {
    sendResponse({ ok: false, message: "Invalid request identifier" });
    return false;
  }
  if (message.type === "getPending") {
    void pendingRequest(requestId)
      .then((pending) => sendResponse({ ok: true, pending }))
      .catch((error) => sendResponse({ ok: false, message: String(error) }));
    return true;
  }
  if (message.type === "approve") {
    void approveRequest(requestId, message.passkeyId).then(sendResponse);
    return true;
  }
  if (message.type === "deny") {
    void denyRequest(requestId).then(sendResponse);
    return true;
  }
  return false;
});

chrome.runtime.onInstalled.addListener(() => {
  void ensureProxyState();
});
chrome.runtime.onStartup.addListener(() => {
  void ensureProxyState();
});
chrome.action.onClicked.addListener(() => {
  void (async () => {
    const { proxyEnabled = true } = await chrome.storage.local.get("proxyEnabled");
    if (proxyEnabled) {
      await detach();
      await chrome.storage.local.set({ proxyEnabled: false });
    } else if (await attach()) {
      await chrome.storage.local.set({ proxyEnabled: true });
    }
  })();
});
void ensureProxyState();
