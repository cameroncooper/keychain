const NATIVE_HOST = "cameroncooper.keychain";
const APPROVAL_PAGE = chrome.runtime.getURL("approval.html");
const pendingKey = (requestId) => `pending:${requestId}`;
const canceledRequests = new Set();
const processingRequests = new Set();

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

async function callNative(message) {
  const reply = await chrome.runtime.sendNativeMessage(NATIVE_HOST, message);
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
    });
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
    await chrome.storage.session.set({
      [pendingKey(requestId)]: {
        requestId,
        requestDetailsJson: request.requestDetailsJson,
        inspection: reply.result,
      },
    });
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

    // Consume the approval before signing so a repeated message cannot reuse it.
    await chrome.storage.session.remove(pendingKey(requestId));
    const reply = await callNative({
      version: 1,
      action: "assert",
      requestDetailsJson: pending.requestDetailsJson,
      passkeyId,
    });
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

chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener((request) => {
  // The software backend has explicit presence approval but no local user verification.
  void chrome.webAuthenticationProxy.completeIsUvpaaRequest({
    requestId: request.requestId,
    isUvpaa: false,
  });
});

chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId) => {
  canceledRequests.add(requestId);
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
