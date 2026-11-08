// Presentation only. IDs and public account labels in; intentional selections
// out. No classification, credential requests, field writes or secret values.
(() => {
  function create(field, callbacks) {
    const host = document.createElement("div");
    host.dataset.keychainMenu = "";
    host.setAttribute("role", "region");
    host.setAttribute("aria-label", "Keychain suggestions");
    host.style.cssText =
      "all:initial;position:fixed;z-index:2147483647;display:block;width:360px;max-width:calc(100vw - 16px);";
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent =
      KeychainMenuStyle +
      "\n:host{direction:ltr} main{border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--foreground);font:13px system-ui;box-shadow:0 5px 20px #0003;max-height:320px;overflow:auto}";
    root.append(style);
    const rect = field.getBoundingClientRect();
    host.style.left = Math.max(8, Math.min(rect.left, innerWidth - 368)) + "px";
    host.style.top =
      Math.max(8, Math.min(rect.bottom + 4, innerHeight - 220)) + "px";
    let main,
      notice,
      buttons = [];
    function message(value) {
      notice.textContent = value;
    }
    function render(accounts, managerAvailable) {
      main?.remove();
      main = document.createElement("main");
      const heading = document.createElement("header");
      heading.className = "menu-heading";
      heading.textContent = "Keychain";
      main.append(heading);
      const list = document.createElement("div");
      list.className = "account-list";
      main.append(list);
      const rows = [];
      for (const account of accounts) {
        const row = document.createElement("button");
        row.type = "button";
        row.className = "account";
        const icon = document.createElement("span");
        icon.className = "account-icon";
        icon.setAttribute("aria-hidden", "true");
        const text = document.createElement("span");
        text.className = "account-text";
        const name = document.createElement("span");
        name.className = "account-name";
        name.textContent = account.username || account.title || "Account";
        const site = document.createElement("span");
        site.className = "account-detail";
        site.textContent = location.hostname;
        const type = document.createElement("span");
        type.className = "account-type";
        type.textContent = account.label;
        text.append(name, site);
        row.append(icon, text, type);
        list.append(row);
        rows.push(row);
        row.addEventListener("click", (event) => {
          if (event.isTrusted) callbacks.choose(account.id);
        });
        row.addEventListener("keydown", (event) => {
          if (event.key === "ArrowDown" || event.key === "ArrowUp") {
            event.preventDefault();
            rows[
              (rows.indexOf(row) +
                (event.key === "ArrowDown" ? 1 : -1) +
                rows.length) %
                rows.length
            ].focus();
          }
          if (
            ["Enter", " ", "ArrowDown", "ArrowUp", "Escape"].includes(event.key)
          )
            event.stopPropagation();
          if (event.key === "Escape") {
            event.preventDefault();
            callbacks.cancel();
          }
        });
      }
      buttons = [...rows];
      if (managerAvailable) {
        const manager = document.createElement("button");
        manager.type = "button";
        manager.className = "menu-action";
        manager.textContent = "Open Keychain…";
        manager.addEventListener("click", (event) => {
          if (event.isTrusted) callbacks.manager();
        });
        main.append(manager);
        buttons.push(manager);
      }
      notice = document.createElement("p");
      notice.className = "notice";
      notice.setAttribute("role", "status");
      notice.textContent = accounts.length
        ? "Choose an account"
        : "No protected accounts match this website.";
      main.append(notice);
      root.append(main);
      host.dataset.keychainState = "ready";
      return rows;
    }
    main = document.createElement("main");
    notice = document.createElement("p");
    notice.className = "notice";
    notice.textContent = "Looking for saved accounts…";
    main.append(notice);
    root.append(main);
    document.documentElement.append(host);
    let rows = [];
    return {
      host,
      message,
      render(accounts, manager) {
        rows = render(accounts, manager);
      },
      busy(value) {
        for (const button of buttons) button.disabled = true;
        message(value);
      },
      focusFirst() {
        rows[0]?.focus();
      },
      close() {
        host.remove();
      },
    };
  }
  globalThis.KeychainFormMenu = Object.freeze({ create });
})();
