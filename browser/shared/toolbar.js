const api = globalThis.browser ?? globalThis.chrome;
const toggle = document.querySelector("#enabled");
const manager = document.querySelector("#open-manager");
const status = document.querySelector("#status");
const error = document.querySelector("#error");
async function refresh() {
  const reply = await api.runtime.sendMessage({ type: "getToolbarState" });
  if (!reply?.ok) throw new Error(reply?.message || "Keychain is unavailable.");
  toggle.checked = reply.enabled;
  manager.disabled = !reply.managerAvailable;
  document.querySelector("#site").textContent = reply.site || "Keychain";
  const accounts = document.querySelector("#accounts");
  accounts.replaceChildren();
  if (reply.loginForm) {
    for (const candidate of reply.loginForm.candidates) {
      const row = document.createElement("button");row.type="button";row.className="account";
      const text = document.createElement("span");text.className="account-text";
      const name = document.createElement("span");name.className="account-name";name.textContent=candidate.username||candidate.title||"Account";
      const site = document.createElement("span");site.className="account-detail";site.textContent=reply.site;
      const kind = document.createElement("span");kind.className="account-type";kind.textContent=reply.loginForm.field === "totp" ? "Code" : reply.loginForm.field === "username" ? "Username" : "Password";
      text.append(name,site);row.append(text,kind);accounts.append(row);
      row.addEventListener("click",async()=>{
        row.disabled=true;
        try { const result=await api.runtime.sendMessage({type:"fillSelectedLogin",handle:reply.loginForm.handle,id:candidate.id});if(!result?.ok)throw new Error(result?.message||"The form changed.");window.close(); }
        catch(e){error.textContent=e.message;row.disabled=false;}
      });
    }
  }
  status.textContent = !reply.enabled ? "Keychain is turned off in this browser."
    : reply.loginForm?.loading ? "Looking for saved accounts…"
    : reply.loginForm?.candidates.length ? "Choose an account to fill this website."
    : reply.loginForm ? "No protected accounts match this website."
    : reply.ready ? "Ready. Choose a passkey on the website, or focus a login field."
    : reply.connected ? "Keychain is connected, but biometric authentication is unavailable."
    : "Cannot connect to Keychain. Open the app to check your setup.";
}
toggle.addEventListener("change", async () => {
  toggle.disabled = true; error.textContent = "";
  try { const reply = await api.runtime.sendMessage({ type: "setEnabled", enabled: toggle.checked }); if (!reply?.ok) throw new Error(reply?.message || "Could not change the setting."); await refresh(); }
  catch (e) { error.textContent = e.message; }
  finally { toggle.disabled = false; }
});
manager.addEventListener("click", async () => {
  manager.disabled = true;
  try { const reply = await api.runtime.sendMessage({ type: "openManager" }); if (!reply?.ok) throw new Error(reply?.message || "Could not open Keychain."); window.close(); }
  catch (e) { error.textContent = e.message; manager.disabled = false; }
});
void refresh().catch(e => { status.textContent = "Keychain is unavailable."; error.textContent = e.message; });

api.runtime.onMessage.addListener(message => { if(message?.type === "keychainAccountsChanged") void refresh().catch(()=>{}); });
