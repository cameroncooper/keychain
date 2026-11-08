const api = globalThis.keychainApi;
const transport = globalThis.keychainTransport;
const NATIVE_HOST = "cameroncooper.keychain";
const APPROVAL_PAGE = api.runtime.getURL("approval.html");
const pendingKey = (requestId) => `pending:${requestId}`;
const canceledRequests = new Set();
const processingRequests = new Set();
const activeNative = new Map();
const requestKinds = new Map();
const completedRequests = new Set();
const selectionWindows = new Map();

const requestTimers = new Map();
function clearRequestTimer(id) {
  const deadline = requestTimers.get(id);
  if (deadline) clearTimeout(deadline.timer);
  requestTimers.delete(id);
}
function scheduleDeadline(id, kind, expiresAt) {
  clearRequestTimer(id);
  requestTimers.set(id, { expiresAt, timer: setTimeout(() => {
    // Reserve completion before revoking/disconnecting. Late native replies
    // cannot complete a second time or deliver success after this deadline.
    const completion = completeRequest(id, kind, kind === "available"
      ? { isUvpaa: false } : { error: domError("NotAllowedError", "The passkey request expired") });
    canceledRequests.add(id);
    activeNative.get(id)?.disconnect();
    void api.storage.session.remove(pendingKey(id));
    void closeSelection(id);
    void completion;
  }, Math.max(1, expiresAt - Date.now())) });
}
function startDeadline(request, kind) {
  let timeout = kind === "available" ? 5000 : 120000;
  try {
    const value = JSON.parse(request.requestDetailsJson).timeout;
    if (typeof value === "number" && Number.isFinite(value)) timeout = Math.min(120000, Math.max(1, value));
  } catch { /* Native parsing still rejects malformed request details. */ }
  scheduleDeadline(request.requestId, kind, Date.now() + timeout);
}

function domError(name, message) {
  return { name, message };
}

async function attach() {
  try {
    await transport.attach();
    await api.action.setBadgeText({ text: "ON" });
    await api.action.setBadgeBackgroundColor({ color: "#1769e0" });
    await api.action.setTitle({ title: "Keychain Passkeys: enabled (click to disable)" });
    return true;
  } catch (error) {
    console.error("Could not attach WebAuthentication proxy", error);
    await api.action.setBadgeText({ text: "ERR" });
    await api.action.setBadgeBackgroundColor({ color: "#b42318" });
    await api.action.setTitle({ title: "Keychain Passkeys: could not attach" });
    return false;
  }
}

async function detach() {
  for (const id of requestTimers.keys()) clearRequestTimer(id);
  for (const [requestId, port] of activeNative) {
    canceledRequests.add(requestId);
    port.disconnect();
  }
  activeNative.clear();
  await transport.detach();
  await api.storage.session.clear();
  await api.action.setBadgeText({ text: "OFF" });
  await api.action.setBadgeBackgroundColor({ color: "#666666" });
  await api.action.setTitle({ title: "Keychain Passkeys: disabled (click to enable)" });
}

async function ensureProxyState() {
  const { proxyEnabled = true } = await api.storage.local.get("proxyEnabled");
  if (proxyEnabled) {
    await attach();
    // Restore picker deadlines if Chromium suspended the service worker.
    const values = await api.storage.session.get(null);
    for (const pending of Object.values(values)) {
      if (Number.isSafeInteger(pending?.requestId) && pending.kind === "get" && Number.isFinite(pending.expiresAt)) {
        requestKinds.set(pending.requestId, "get");
        scheduleDeadline(pending.requestId, "get", pending.expiresAt);
      }
    }
  } else {
    await detach();
  }
}

async function completeGetWithError(requestId, error) {
  return completeRequest(requestId, "get", { error });
}

async function completeRequest(requestId, kind, result) {
  clearRequestTimer(requestId);
  if (canceledRequests.has(requestId) || completedRequests.has(requestId)) return;
  completedRequests.add(requestId);
  try {
    if (kind === "available") {
      await transport.completeIsUvpaaRequest({ requestId, ...result });
    } else if (kind === "create") {
      await transport.completeCreateRequest({ requestId, ...result });
    } else {
      await transport.completeGetRequest({ requestId, ...result });
    }
  } catch (completionError) {
    console.error("Could not complete WebAuthn request", completionError);
  }
}

async function openSelection(requestId) {
  const window = await api.windows.create({
    url: `${APPROVAL_PAGE}?requestId=${encodeURIComponent(requestId)}`,
    type: "popup", width: 440, height: 560, focused: true,
  });
  if (canceledRequests.has(requestId) || completedRequests.has(requestId)) {
    await api.storage.session.remove(pendingKey(requestId));
    if (window?.id !== undefined) await api.windows.remove(window.id);
  } else if (window?.id !== undefined) {
    selectionWindows.set(requestId, window.id);
    const pending = await pendingRequest(requestId);
    if (pending) {
      await api.storage.session.set({ [pendingKey(requestId)]: { ...pending, windowId: window.id } });
      if (canceledRequests.has(requestId) || completedRequests.has(requestId)) {
        await api.storage.session.remove(pendingKey(requestId));
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
    try { await api.windows.remove(windowId); } catch { /* Already closed. */ }
  }
}

async function callNative(message, requestId) {
  if (canceledRequests.has(requestId)) {
    throw new Error("The website canceled this request");
  }
  const reply = await new Promise((resolve, reject) => {
    const port = api.runtime.connectNative(NATIVE_HOST);
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
      const message = api.runtime.lastError?.message || "The native host disconnected";
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
  startDeadline(request, "get");
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
    await api.storage.session.set({
      [pendingKey(requestId)]: {
        kind: "get",
        requestId,
        requestDetailsJson: request.requestDetailsJson,
        expiresAt: requestTimers.get(requestId)?.expiresAt,
        inspection: reply.result,
      },
    });
    if (canceledRequests.has(requestId) || completedRequests.has(requestId)) {
      await api.storage.session.remove(pendingKey(requestId));
      return;
    }
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
      await api.storage.session.remove(pendingKey(requestId));
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
  const values = await api.storage.session.get(key);
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
    if (!Number.isFinite(pending.expiresAt) || pending.expiresAt <= Date.now()) {
      await denyRequest(requestId);
      return { ok: false, message: "The passkey request expired" };
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
    await api.storage.session.remove(pendingKey(requestId));
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
  await api.storage.session.remove(pendingKey(requestId));
  await closeSelection(requestId);
  await completion;
  return { ok: true };
}

async function handleCreate(request) {
  const requestId = request.requestId;
  if (processingRequests.has(requestId) || completedRequests.has(requestId)) return;
  processingRequests.add(requestId);
  canceledRequests.delete(requestId);
  requestKinds.set(requestId, "create");
  startDeadline(request, "create");
  try {
    const reply = await callNative({ version: 1, action: "create",
      transaction: crypto.randomUUID(), requestDetailsJson: request.requestDetailsJson }, requestId);
    if (!reply.ok) {
      await completeRequest(requestId, "create", { error: reply.error || domError("UnknownError", "Registration failed") });
      return;
    }
    if (reply.result?.kind !== "registration" || typeof reply.result.responseJson !== "string") {
      throw new Error("The native host returned an invalid registration");
    }
    await completeRequest(requestId, "create", { responseJson: reply.result.responseJson });
  } catch (error) {
    await completeRequest(requestId, "create", { error: domError("UnknownError", String(error)) });
  } finally {
    processingRequests.delete(requestId);
  }
}

transport.onGetRequest.addListener((request) => {
  void handleGet(request);
});

transport.onCreateRequest.addListener((request) => {
  void handleCreate(request);
});

async function handleIsUvpaa(request) {
  const requestId = request.requestId;
  canceledRequests.delete(requestId);
  startDeadline(request, "available");
  let available = false;
  try {
    const reply = await callNative({ version: 1, action: "capabilities" }, requestId);
    available = reply?.ok === true && reply.result?.kind === "capabilities" &&
      reply.result.userVerificationAvailable === true;
  } catch {
    // Unavailable service/UI/hardware cannot advertise verified authentication.
  }
  if (canceledRequests.has(requestId)) return;
  await completeRequest(requestId, "available", { isUvpaa: available });
}

transport.onIsUvpaaRequest.addListener((request) => {
  void handleIsUvpaa(request);
});

transport.onRequestCanceled.addListener((requestId) => {
  clearRequestTimer(requestId);
  canceledRequests.add(requestId);
  activeNative.get(requestId)?.disconnect();
  activeNative.delete(requestId);
  void api.storage.session.remove(pendingKey(requestId));
  void closeSelection(requestId);
  void api.runtime.sendMessage({ type: "requestCanceled", requestId }).catch(() => {});
});

api.windows.onRemoved.addListener((windowId) => {
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
  const pending = await api.storage.session.get(null);
  for (const value of Object.values(pending)) {
    if (value?.windowId === windowId && Number.isSafeInteger(value.requestId)) {
      await denyRequest(value.requestId);
      return;
    }
  }
}

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== api.runtime.id) return false;
  let source;
  try {
    source = new URL(sender.url);
    const expected = new URL(APPROVAL_PAGE);
    if (source.protocol !== expected.protocol || source.host !== expected.host || source.pathname !== expected.pathname) return false;
  } catch { return false; }
  const requestId = Number(message?.requestId);
  if (!source.searchParams.has("requestId") || Number(source.searchParams.get("requestId")) !== requestId) return false;
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

api.runtime.onInstalled.addListener(() => {
  void ensureProxyState();
});
api.runtime.onStartup.addListener(() => {
  void ensureProxyState();
});
api.action.onClicked.addListener(() => {
  void (async () => {
    const { proxyEnabled = true } = await api.storage.local.get("proxyEnabled");
    if (proxyEnabled) {
      await detach();
      await api.storage.local.set({ proxyEnabled: false });
    } else if (await attach()) {
      await api.storage.local.set({ proxyEnabled: true });
    }
  })();
});
void ensureProxyState();
