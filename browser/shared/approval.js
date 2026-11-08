const extensionApi = globalThis.browser ?? globalThis.chrome;
const requestId = Number(new URLSearchParams(location.search).get("requestId"));
const accounts = document.querySelector("#accounts");
const errorText = document.querySelector("#error");
const cancelButton = document.querySelector("#cancel");
const buttons = [];
let busy = false;
let active = true;
function showError(message) { errorText.textContent = message; }
function setBusy(value) {
  busy = value;
  for (const button of buttons) button.disabled = value;
}
async function choose(id) {
  if (busy || !active) return;
  setBusy(true); showError("");
  try {
    const reply = await extensionApi.runtime.sendMessage({ type: "approve", requestId, passkeyId: id });
    if (reply?.ok) { active = false; window.close(); return; }
    showError(reply?.message || "The request could not be completed.");
  } catch { showError("Keychain is unavailable."); }
  if (active) setBusy(false);
}
function accountChoice(candidate, website) {
  const row = document.createElement("button");
  row.type = "button"; row.className = "account"; row.dataset.credential = candidate.id;
  const icon = document.createElement("span"); icon.className = "account-icon"; icon.setAttribute("aria-hidden", "true");
  const text = document.createElement("span"); text.className = "account-text";
  const name = document.createElement("span"); name.className = "account-name"; name.textContent = candidate.username || candidate.displayName || "Account";
  const detail = document.createElement("span"); detail.className = "account-detail"; detail.textContent = website;
  const type = document.createElement("span"); type.className = "account-type"; type.textContent = "Passkey";
  text.append(name, detail); row.append(icon, text, type);
  row.addEventListener("click", () => { void choose(candidate.id); });
  row.addEventListener("keydown", event => {
    const index = buttons.indexOf(row);
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault(); buttons[(index + (event.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length].focus();
    }
  });
  buttons.push(row); return row;
}
async function load() {
  if (!Number.isSafeInteger(requestId)) throw new Error("Invalid account request");
  const reply = await extensionApi.runtime.sendMessage({ type: "getPending", requestId });
  if (!reply?.ok || !reply.pending || reply.pending.kind !== "get") throw new Error("This account request is no longer active");
  const inspection = reply.pending.inspection;
  document.querySelector("#site").textContent = inspection.rpId;
  document.querySelector("#origin").textContent = inspection.origin;
  document.querySelector("#notice").textContent = inspection.biometric
    ? "Choose an account, then use your fingerprint to sign in."
    : "Choose an account to approve this sign-in. Device user verification is unavailable.";
  for (const candidate of inspection.candidates) accounts.append(accountChoice(candidate, inspection.rpId));
  buttons[0]?.focus();
}
cancelButton.addEventListener("click", async () => {
  if (!active) return;
  active = false; setBusy(true);
  try { await extensionApi.runtime.sendMessage({ type: "deny", requestId }); } finally { window.close(); }
});
document.addEventListener("keydown", event => {
  if (event.key === "Escape") { event.preventDefault(); cancelButton.click(); }
});
extensionApi.runtime.onMessage.addListener(message => {
  if (message?.type === "requestCanceled" && message.requestId === requestId) {
    active = false; setBusy(true); document.querySelector("#notice").textContent = "This request was canceled.";
  }
});
void load().catch(error => { active = false; document.querySelector("#site").textContent = "No active request"; showError(error.message); });
