const params = new URLSearchParams(location.search);
const requestId = Number(params.get("requestId"));
const form = document.querySelector("#approval-form");
const site = document.querySelector("#site");
const origin = document.querySelector("#origin");
const accounts = document.querySelector("#accounts");
const errorText = document.querySelector("#error");
const approveButton = document.querySelector("#approve");
const cancelButton = document.querySelector("#cancel");

function showError(message) {
  errorText.textContent = message;
}

function setBusy(busy) {
  approveButton.disabled = busy;
  cancelButton.disabled = busy;
}

function accountChoice(candidate, checked) {
  const label = document.createElement("label");
  label.className = "account";
  const radio = document.createElement("input");
  radio.type = "radio";
  radio.name = "passkey";
  radio.value = candidate.id;
  radio.checked = checked;
  const text = document.createElement("span");
  const name = document.createElement("span");
  name.className = "account-name";
  name.textContent = candidate.displayName || candidate.username || "Passkey";
  const detail = document.createElement("span");
  detail.className = "account-detail";
  detail.textContent = candidate.username || "Synced passkey";
  text.append(name, detail);
  label.append(radio, text);
  return label;
}

async function load() {
  if (!Number.isSafeInteger(requestId)) {
    site.textContent = "Invalid passkey request";
    return;
  }
  const reply = await chrome.runtime.sendMessage({ type: "getPending", requestId });
  if (!reply?.ok || !reply.pending) {
    site.textContent = "This passkey request is no longer active";
    return;
  }
  const inspection = reply.pending.inspection;
  if (inspection.biometric === true) {
    document.querySelector("h1").textContent = "Choose an account";
    document.querySelector("#notice").textContent = "Your desktop will ask for a fingerprint after you choose an account.";
    approveButton.textContent = "Use passkey";
  }
  site.textContent = inspection.rpId;
  origin.textContent = inspection.origin;
  inspection.candidates.forEach((candidate, index) => {
    accounts.append(accountChoice(candidate, index === 0));
  });
  form.hidden = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  showError("");
  const selected = new FormData(form).get("passkey");
  if (typeof selected !== "string") {
    showError("Choose an account first.");
    return;
  }
  setBusy(true);
  const reply = await chrome.runtime.sendMessage({
    type: "approve",
    requestId,
    passkeyId: selected,
  });
  if (reply?.ok) {
    window.close();
    return;
  }
  showError(reply?.message || "The passkey request failed.");
  setBusy(false);
});

cancelButton.addEventListener("click", async () => {
  setBusy(true);
  await chrome.runtime.sendMessage({ type: "deny", requestId });
  window.close();
});

chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "requestCanceled" && message.requestId === requestId) {
    site.textContent = "The website canceled this request";
    form.hidden = true;
  }
});

void load().catch((error) => {
  site.textContent = "Could not load the passkey request";
  showError(error instanceof Error ? error.message : String(error));
});
