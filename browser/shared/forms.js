// Isolated-world login UI. Closed shadow DOM is presentation isolation, not
// authorization; the native broker checks the destination and requires a scan.
(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (!isSecureContext || window !== window.top || window.origin === "null" || window.origin !== new URL(document.URL).origin) return;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  let active;
  let enabled = false;
  void api.storage.local.get("proxyEnabled").then(settings => { enabled = settings.proxyEnabled !== false; });
  api.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.proxyEnabled) {
      enabled = changes.proxyEnabled.newValue !== false;
      if (!enabled) stop();
    }
  });
  let restoringFocus = false;
  function restore(field) {
    if (!field?.isConnected || !document.hasFocus()) return;
    restoringFocus = true;
    try { field.focus({preventScroll:true}); } finally { restoringFocus = false; }
  }
  function visible(field) {
    if (!(field instanceof HTMLInputElement) || !field.isConnected || field.disabled || field.readOnly || field.type === "hidden" || field.closest('[inert],[aria-hidden="true"]')) return false;
    const rect = field.getBoundingClientRect(), style = getComputedStyle(field);
    if (rect.width < 8 || rect.height < 8 || rect.bottom <= 0 || rect.top >= innerHeight || rect.right <= 0 || rect.left >= innerWidth || style.visibility !== "visible" || Number(style.opacity) < .5) return false;
    const hit = document.elementFromPoint(Math.min(innerWidth-1,Math.max(0,rect.left+rect.width/2)),Math.min(innerHeight-1,Math.max(0,rect.top+rect.height/2)));
    return hit === field || hit === active?.host;
  }
  function role(field) {
    if (!visible(field)) return null;
    const autocomplete = (field.autocomplete || "").toLowerCase().split(/\s+/);
    if (autocomplete.includes("new-password")) return null;
    if (autocomplete.includes("one-time-code") || /(?:^|[\s_-])(otp|totp|verification|2fa)(?:$|[\s_-])/.test((field.name+" "+field.id).toLowerCase())) {
      return field.maxLength > 0 && field.maxLength < 6 ? null : "totp";
    }
    if (field.type === "password" || autocomplete.includes("current-password")) return "password";
    if (["text","email","tel"].includes(field.type) && (autocomplete.includes("username") || field.type === "email" || /user|email|login/i.test(field.name+" "+field.id))) return "username";
    return null;
  }
  function stop(session = active) {
    if (!session || session.closed) return;
    session.closed = true; session.port.disconnect(); session.host.remove();
    if (active === session) active = null;
  }
  function valid(session) {
    if (session.closed || session.disconnected || location.href !== session.url || document.hidden) return false;
    if (session.form && (!session.form.isConnected || session.form.action !== session.action || session.form.target !== session.target || session.form.method !== session.method)) return false;
    return session.fields.every(({ field, name, type, autocomplete }) => visible(field) && field.name === name && field.type === type && field.autocomplete === autocomplete && field.form === session.form);
  }
  function select(session, candidate) {
    if (session.used || !valid(session)) { stop(session); return; }
    session.used = true;
    for (const button of session.rows ?? []) button.disabled = true;
    if(session.manager)session.manager.disabled=true;
    session.notice.textContent = session.mode === "totp" || session.password ? "Continue in the desktop fingerprint prompt…" : "Filling username…";
    session.port.postMessage({kind:"fill",id:candidate.id,field:session.mode === "totp" ? "totp" : session.password ? "password" : "username"});
  }
  function show(session, candidates, managerAvailable) {
    const root = session.root;
    session.candidates = new Map(candidates.map(candidate => [candidate.id,candidate]));
    const main = document.createElement("main");
    const heading = document.createElement("header"); heading.className = "menu-heading"; heading.textContent = "Keychain"; main.append(heading);
    const list = document.createElement("div"); list.className = "account-list"; main.append(list);
    const choices = candidates.filter(candidate => session.mode === "totp" ? candidate.hasTotp : session.password ? candidate.hasPassword : true);
    const rows = [];
    for (const candidate of choices) {
      const row = document.createElement("button"); row.type = "button"; row.className = "account";
      const icon = document.createElement("span");icon.className="account-icon";icon.setAttribute("aria-hidden","true");
      const text = document.createElement("span"); text.className = "account-text";
      const name = document.createElement("span"); name.className = "account-name"; name.textContent = candidate.username || candidate.title || "Account";
      const site = document.createElement("span"); site.className = "account-detail"; site.textContent = location.hostname;
      const type = document.createElement("span"); type.className = "account-type"; type.textContent = session.mode === "totp" ? "Code" : session.password ? "Password" : "Username";
      text.append(name,site); row.append(icon,text,type);
      row.addEventListener("click", event => {
        if (!event.isTrusted || session.used) return;
        if (!valid(session)) { stop(session); return; }
        select(session,candidate);
      });
      row.addEventListener("keydown", event => {
        if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); rows[(rows.indexOf(row)+(event.key === "ArrowDown"?1:-1)+rows.length)%rows.length].focus(); }
        if (["Enter"," ","ArrowDown","ArrowUp","Escape"].includes(event.key)) event.stopPropagation();
        if (event.key === "Escape") { event.preventDefault(); stop(session); }
      });
      rows.push(row); list.append(row);
    }
    if (managerAvailable) {
      const manager = document.createElement("button");manager.type="button";manager.className="menu-action";manager.textContent="Open Keychain…";
      manager.addEventListener("click",event=>{if(!event.isTrusted||session.used||!valid(session))return;session.used=true;manager.disabled=true;session.port.postMessage({kind:"manager"});});
      main.append(manager);
      session.manager = manager;
    }
    session.rows = rows;
    session.host.dataset.keychainState = "ready";
    const notice = document.createElement("p"); notice.className = "notice"; notice.textContent = choices.length ? "Choose an account" : "No protected accounts match this website."; session.notice = notice; main.append(notice);
    session.menu?.remove(); session.menu = main; root.append(main);
  }
  function fill(session, reply) {
    let filled;
    try {
      if (!session.used || !valid(session)) return;
      const apply = (field, value) => { filled = field; setter.call(field, value); field.dispatchEvent(new Event("input",{bubbles:true,composed:true})); field.dispatchEvent(new Event("change",{bubbles:true})); };
      if (reply.field === "username" && session.username) apply(session.username, reply.username);
      else if (reply.field === "password" && session.password && typeof reply.result?.password === "string") {
        // Recheck the password field after username event handlers, too. Page
        // code may replace controls or change form action in response to input.
        if (session.username) apply(session.username, reply.username);
        if (valid(session)) apply(session.password, reply.result.password);
      } else if (reply.field === "totp" && session.mode === "totp" && typeof reply.result?.totp?.code === "string" && reply.result.totp.expires > Date.now()/1000+1) {
        apply(session.focused,reply.result.totp.code);
      }
    } finally {
      if (reply.result) { delete reply.result.password; delete reply.result.totp; }
      stop(session);
      if (filled) restore(filled);
    }
  }
  function start(field) {
    if (!enabled) return;
    const mode = role(field); if (!mode) return;
    if (active && !active.disconnected && active.fields.some(item => item.field === field)) return;
    stop();
    const form = field.form;
    const action = form?.action;
    if (form && new URL(action).origin !== location.origin) return;
    const inputs = form ? [...form.elements].filter(item => item instanceof HTMLInputElement && visible(item)) : [field];
    const passwords = inputs.filter(item => role(item) === "password");
    const usernames = inputs.filter(item => role(item) === "username");
    const password = mode === "password" ? field : passwords.length === 1 ? passwords[0] : null;
    const username = mode === "username" ? field : usernames.length === 1 ? usernames[0] : null;
    const selected = mode === "totp" ? [field] : [...new Set([username,password].filter(Boolean))];
    if (!selected.length) return;
    const host = document.createElement("div");
    host.dataset.keychainMenu = "";
    host.setAttribute("role", "region");host.setAttribute("aria-label", "Keychain suggestions");
    host.style.cssText = "all:initial;position:fixed;z-index:2147483647;display:block;width:360px;max-width:calc(100vw - 16px);";
    const root = host.attachShadow({mode:"closed"});
    const style = document.createElement("style"); style.textContent = KeychainMenuStyle + "\n:host{direction:ltr} main{border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--foreground);font:13px system-ui;box-shadow:0 5px 20px #0003;max-height:320px;overflow:auto}";root.append(style);
    const rect = field.getBoundingClientRect();host.style.left = Math.max(8,Math.min(rect.left,innerWidth-368))+"px";
    host.style.top = Math.max(8,Math.min(rect.bottom+4,innerHeight-220))+"px";
    const port = api.runtime.connect({name:"keychain-login"});
    const session = {host,root,port,form,action,target:form?.target,method:form?.method,url:location.href,focused:field,mode,username,password,used:false,closed:false,
      fields:selected.map(field => ({field,name:field.name,type:field.type,autocomplete:field.autocomplete}))};
    active = session;document.documentElement.append(host);
    const loading = document.createElement("main");
    session.notice = document.createElement("p"); session.notice.className = "notice"; session.notice.textContent = "Looking for saved accounts…"; loading.append(session.notice);root.append(loading);session.menu = loading;
    port.onMessage.addListener(reply => {
      if (reply.kind === "candidates") { if (valid(session)) show(session,reply.candidates,reply.managerAvailable);else stop(session); }
      else if (reply.kind === "select") { const candidate = session.candidates?.get(reply.id); if(candidate)select(session,candidate); }
      else if (reply.kind === "fill") fill(session,reply);
      else if (reply.kind === "error") { session.terminal = true; if(session.notice)session.notice.textContent = reply.message; }
    });
    port.onDisconnect.addListener(() => { session.disconnected = true; if (!session.terminal) stop(session); });
    port.postMessage({kind:"inspect",field:mode === "totp" ? "totp" : password ? "password" : "username"});
  }
  document.addEventListener("focusin", event => {
    if (restoringFocus) return;
    if (event.target === active?.host) return;
    if (event.target instanceof HTMLInputElement) start(event.target); else stop();
  },true);
  document.addEventListener("pointerdown",event => {
    if ((!active || active.disconnected) && event.isTrusted && event.target instanceof HTMLInputElement) { stop(); start(event.target); }
    else if (active && event.target !== active.host && !active.fields.some(item => item.field === event.target)) stop();
  },true);
  document.addEventListener("keydown",event => {
    if (event.key === "Escape") stop();
    else if (event.isTrusted && event.key === "ArrowDown" && active?.fields.some(item => item.field === event.target) && active.rows?.length) {
      event.preventDefault(); active.rows[0].focus();
    }
  },true);
  api.runtime.onMessage.addListener((message,sender) => {
    if (sender.id !== api.runtime.id || message?.type !== "keychainInspectForm") return;
    const focused = document.activeElement;
    const first = focused instanceof HTMLInputElement && role(focused) ? focused : [...document.querySelectorAll("input")].find(field => role(field));
    if (first) start(first);
    return Promise.resolve({ok:!!active});
  });
  window.addEventListener("pagehide",()=>stop());
  document.addEventListener("visibilitychange",()=>{if(document.hidden)stop();});
})();
