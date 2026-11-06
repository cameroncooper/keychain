const NATIVE_HOST = "cameroncooper.keychain";
const APPROVAL_PAGE = chrome.runtime.getURL("approval.html");
const pendingKey = (requestId) => `pending:${requestId}`;
const canceledRequests = new Set();
const processingRequests = new Set();
const activeNative = new Map();
const requestKinds = new Map();
const completedRequests = new Set();
const selectionWindows = new Map();

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
  return completeRequest(requestId, "get", { error });
}

async function completeRequest(requestId, kind, result) {
  if (canceledRequests.has(requestId) || completedRequests.has(requestId)) return;
  completedRequests.add(requestId);
  try {
    if (kind === "create") {
      await chrome.webAuthenticationProxy.completeCreateRequest({ requestId, ...result });
    } else {
      await chrome.webAuthenticationProxy.completeGetRequest({ requestId, ...result });
    }
  } catch (completionError) {
    console.error("Could not complete WebAuthn request", completionError);
  }
}

async function openSelection(requestId) {
  const window = await chrome.windows.create({
    url: `${APPROVAL_PAGE}?requestId=${encodeURIComponent(requestId)}`,
    type: "popup", width: 440, height: 560, focused: true,
  });
  if (canceledRequests.has(requestId) || completedRequests.has(requestId)) {
    await chrome.storage.session.remove(pendingKey(requestId));
    if (window?.id !== undefined) await chrome.windows.remove(window.id);
  } else if (window?.id !== undefined) {
    selectionWindows.set(requestId, window.id);
    const pending = await pendingRequest(requestId);
    if (pending) {
      await chrome.storage.session.set({ [pendingKey(requestId)]: { ...pending, windowId: window.id } });
      if (canceledRequests.has(requestId) || completedRequests.has(requestId)) {
        await chrome.storage.session.remove(pendingKey(requestId));
      }
    } else {
      await closeSelection(requestId);
    }
  }
}

async function closeSelection(requestId) {
  const windowId = selectionWindows.get(requestId);
  selectionWindows.delete(requestId);
  if (windowId !== undefined) {
    try { await chrome.windows.remove(windowId); } catch { /* Already closed. */ }
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
  completedRequests.delete(requestId);
  requestKinds.set(requestId, "get");
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
        kind: "get",
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
      await openSelection(requestId);
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
      return { ok: false, message: "This passkey request is no longer active" };
    }
    if (pending.kind !== "get") {
      return { ok: false, message: "This is not a sign-in request" };
    }
    const eligible = pending.inspection.candidates.some(
      (candidate) => candidate.id === passkeyId,
    );
    if (!eligible) {
      throw new Error("The selected passkey is not eligible for this request");
    }

    // Consume the selection before signing so it cannot be replayed.
    await chrome.storage.session.remove(pendingKey(requestId));
    await closeSelection(requestId);
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
    await completeRequest(requestId, "get", { responseJson: reply.result.responseJson });
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
  const pending = await pendingRequest(requestId);
  const kind = pending?.kind || requestKinds.get(requestId);
  if (!kind) return { ok: false, message: "This request is no longer active" };
  const completion = completeRequest(requestId, kind, {
    error: domError("NotAllowedError", "The passkey request was canceled"),
  });
  activeNative.get(requestId)?.disconnect();
  await chrome.storage.session.remove(pendingKey(requestId));
  await closeSelection(requestId);
  await completion;
  return { ok: true };
}

async function handleCreate(request) {
  const requestId = request.requestId;
  canceledRequests.delete(requestId);
  completedRequests.delete(requestId);
  requestKinds.set(requestId, "create");
  try {
    const reply = await callNative({ version: 1, action: "inspectCreation",
      requestDetailsJson: request.requestDetailsJson }, requestId);
    if (!reply.ok) {
      await completeRequest(requestId, "create", { error: reply.error || domError("UnknownError", "Registration is unavailable") });
      return;
    }
    const inspection = reply.result;
    if (inspection?.kind !== "creationInspection" || !Array.isArray(inspection.storageChoices) ||
        inspection.storageChoices.length === 0 || inspection.storageChoices.some((choice) => choice !== "device-bound")) {
      throw new Error("The native host returned invalid registration storage choices");
    }
    if (canceledRequests.has(requestId)) return;
    await chrome.storage.session.set({ [pendingKey(requestId)]: {
      kind: "create", requestId, requestDetailsJson: request.requestDetailsJson,
      transaction: crypto.randomUUID(), inspection,
    } });
    await openSelection(requestId);
  } catch (error) {
    await chrome.storage.session.remove(pendingKey(requestId));
    await completeRequest(requestId, "create", { error: domError("UnknownError", String(error)) });
  }
}

async function createRequest(requestId, storage) {
  if (processingRequests.has(requestId)) return { ok: false, message: "This request is already being processed" };
  processingRequests.add(requestId);
  try {
    const pending = await pendingRequest(requestId);
    if (!pending || pending.kind !== "create") return { ok: false, message: "This creation request is no longer active" };
    if (!pending.inspection.storageChoices.includes(storage)) {
      return { ok: false, message: "Choose an available storage location" };
    }
    // Freeze and consume the application selection before presenting the OS
    // prompt. A replay cannot create another key or reuse biometric approval.
    await chrome.storage.session.remove(pendingKey(requestId));
    await closeSelection(requestId);
    const reply = await callNative({ version: 1, action: "create", transaction: pending.transaction,
      storage, requestDetailsJson: pending.requestDetailsJson }, requestId);
    if (!reply.ok) {
      await completeRequest(requestId, "create", { error: reply.error || domError("UnknownError", "Registration failed") });
      return { ok: false, message: reply.error?.message || "Registration failed" };
    }
    if (reply.result?.kind !== "registration" || typeof reply.result.responseJson !== "string") {
      throw new Error("The native host returned an invalid registration");
    }
    if (canceledRequests.has(requestId)) return { ok: false, message: "The website canceled this request" };
    await completeRequest(requestId, "create", { responseJson: reply.result.responseJson });
    return { ok: true };
  } catch (error) {
    await completeRequest(requestId, "create", { error: domError("UnknownError", String(error)) });
    return { ok: false, message: String(error) };
  } finally {
    processingRequests.delete(requestId);
  }
}

chrome.webAuthenticationProxy.onGetRequest.addListener((request) => {
  void handleGet(request);
});

chrome.webAuthenticationProxy.onCreateRequest.addListener((request) => {
  void handleCreate(request);
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
  void closeSelection(requestId);
  void chrome.runtime.sendMessage({ type: "requestCanceled", requestId }).catch(() => {});
});

chrome.windows.onRemoved.addListener((windowId) => {
  void cancelClosedSelection(windowId);
});

async function cancelClosedSelection(windowId) {
  for (const [requestId, selectedWindow] of selectionWindows) {
    if (selectedWindow === windowId) {
      selectionWindows.delete(requestId);
      await denyRequest(requestId);
      return;
    }
  }
  // MV3 may suspend the worker while the application chooser is open. Its
  // persisted kind/window ID must still select completeCreateRequest on close.
  const pending = await chrome.storage.session.get(null);
  for (const value of Object.values(pending)) {
    if (value?.windowId === windowId && Number.isSafeInteger(value.requestId)) {
      await denyRequest(value.requestId);
      return;
    }
  }
}

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
  if (message.type === "create") {
    void createRequest(requestId, message.storage).then(sendResponse);
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
