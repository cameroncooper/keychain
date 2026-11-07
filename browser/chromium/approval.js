const params = new URLSearchParams(location.search);
const requestId = Number(params.get("requestId"));
const form = document.querySelector("#approval-form");
const site = document.querySelector("#site");
const origin = document.querySelector("#origin");
const accounts = document.querySelector("#accounts");
const errorText = document.querySelector("#error");
const approveButton = document.querySelector("#approve");
const cancelButton = document.querySelector("#cancel");
const otherOptions = document.querySelector("#other-options");
const choices = document.querySelector("#choices");
let creation = false;

function showError(message) {
  errorText.textContent = message;
}

function setBusy(busy) {
  approveButton.disabled = busy;
  cancelButton.disabled = busy;
  otherOptions.disabled = busy;
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
  creation = reply.pending.kind === "create";
  if (creation) {
    document.body.classList.add("creation");
    document.title = "Create a passkey";
    document.querySelector("h1").textContent = "Save a passkey";
    document.querySelector("#passkey-mark").removeAttribute("hidden");
    document.querySelector("#next-step").hidden = false;
    const username = document.querySelector("#username");
    username.textContent = inspection.username || inspection.displayName || "";
    username.hidden = !username.textContent;
    document.querySelector("legend").textContent = "Where to save it";
    choices.hidden = true;
    otherOptions.hidden = inspection.storageChoices.length < 2;
    const notice = document.querySelector("#notice");
    const updateStorageNotice = () => {
      const selected = new FormData(form).get("passkey");
      notice.textContent = selected === "synced"
        ? "Save this passkey in your iCloud Keychain, available for sign-in on your other devices."
        : selected === "device-bound"
        ? "Save this passkey on this device only. It will not sync to iCloud or be available on your other devices."
        : "Choose where to save this passkey.";
    };
    approveButton.textContent = "Continue";
    const defaultStorage = inspection.storageChoices.includes("synced") ? "synced" : inspection.storageChoices[0];
    inspection.storageChoices.forEach((choice) => {
      accounts.append(accountChoice({ id: choice,
        displayName: choice === "synced" ? "iCloud Keychain" : "This device",
        username: choice === "synced" ? "Sync across your devices" : "Device-bound passkey" }, choice === defaultStorage));
    });
    form.addEventListener("change", updateStorageNotice);
    updateStorageNotice();
  } else if (inspection.biometric === true) {
    document.querySelector("h1").textContent = "Choose an account";
    document.querySelector("#notice").textContent = "Your desktop will ask for a fingerprint after you choose an account.";
    approveButton.textContent = "Use passkey";
  }
  site.textContent = creation ? `Save a passkey for ${inspection.rpId}?` : inspection.rpId;
  origin.textContent = inspection.origin;
  if (!creation) inspection.candidates.forEach((candidate, index) => {
    accounts.append(accountChoice(candidate, index === 0));
  });
  form.hidden = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  showError("");
  const selected = new FormData(form).get("passkey");
  if (typeof selected !== "string") {
    showError(creation ? "Choose where to save the passkey." : "Choose an account first.");
    return;
  }
  setBusy(true);
  const reply = await chrome.runtime.sendMessage({
    type: creation ? "create" : "approve",
    requestId,
    passkeyId: selected,
    storage: selected,
  });
  if (reply?.ok) {
    window.close();
    return;
  }
  showError(reply?.message || "The passkey request failed.");
  setBusy(false);
});

otherOptions.addEventListener("click", () => {
  choices.hidden = !choices.hidden;
  otherOptions.setAttribute("aria-expanded", String(!choices.hidden));
  otherOptions.textContent = choices.hidden ? "Other Options" : "Hide Options";
});

cancelButton.addEventListener("click", async () => {
  setBusy(true);
  await chrome.runtime.sendMessage({ type: "deny", requestId });
  window.close();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !cancelButton.disabled) {
    event.preventDefault();
    cancelButton.click();
  }
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
