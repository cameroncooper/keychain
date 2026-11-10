// Presentation only. IDs and public account labels in; intentional selections
// out. No classification, credential requests, field writes or secret values.
(() => {
  const margin = 8, gap = 4, maxHeight = 320;
  // Pure viewport geometry, shared by loading and populated menus. Never clamp
  // the top across the anchor: reduce height or decline presentation instead.
  function placement(anchor, viewport, naturalHeight) {
    const values = [anchor.left, anchor.right, anchor.top, anchor.bottom,
      viewport.left, viewport.top, viewport.width, viewport.height, naturalHeight];
    if (!values.every(Number.isFinite) || viewport.width <= 2 * margin ||
        viewport.height <= 2 * margin || naturalHeight <= 0 ||
        anchor.right <= anchor.left || anchor.bottom <= anchor.top) return null;
    const left = viewport.left + margin, top = viewport.top + margin;
    const right = viewport.left + viewport.width - margin;
    const bottom = viewport.top + viewport.height - margin;
    if (anchor.right <= left || anchor.left >= right ||
        anchor.bottom <= top || anchor.top >= bottom) return null;
    const width = Math.min(360, right - left);
    const desired = Math.min(maxHeight, naturalHeight);
    const below = Math.max(0, bottom - anchor.bottom - gap);
    const above = Math.max(0, anchor.top - gap - top);
    const side = below >= desired ? "below" : above >= desired ? "above"
      : below >= above ? "below" : "above";
    const height = Math.min(desired, side === "below" ? below : above);
    if (height < Math.min(96, desired)) return null;
    return {
      left: Math.max(left, Math.min(anchor.left, right - width)),
      top: side === "below" ? anchor.bottom + gap : anchor.top - gap - height,
      width, height, side,
    };
  }
  function create(field, callbacks) {
    const host = document.createElement("div");
    host.dataset.keychainMenu = "";
    host.setAttribute("role", "region");
    host.setAttribute("aria-label", "Keychain suggestions");
    host.style.cssText =
      "all:initial;position:fixed;z-index:2147483647;display:block;visibility:hidden;width:360px;max-width:calc(100vw - 16px);";
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent =
      KeychainMenuStyle +
      "\n:host{direction:ltr} main{border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--foreground);font:13px system-ui;box-shadow:0 5px 20px #0003;max-height:320px;overflow:auto}";
    root.append(style);
    let main,
      notice,
      buttons = [];
    let closed = false, dirty = true, frame, lastGeometry;
    const observer = new ResizeObserver(() => { dirty = true; });
    observer.observe(field);
    function message(value) {
      notice.textContent = value;
      dirty = true;
    }
    function track() {
      if (closed) return;
      if (!field.isConnected || !host.isConnected) {
        callbacks.cancel();
        return;
      }
      const rect = field.getBoundingClientRect();
      const visual = window.visualViewport;
      const viewport = {
        left: visual?.offsetLeft ?? 0, top: visual?.offsetTop ?? 0,
        width: visual?.width ?? innerWidth, height: visual?.height ?? innerHeight,
      };
      const geometry = [rect.left, rect.right, rect.top, rect.bottom,
        viewport.left, viewport.top, viewport.width, viewport.height].join(",");
      if (dirty || geometry !== lastGeometry) {
        dirty = false;
        lastGeometry = geometry;
        host.style.width = Math.max(0, Math.min(360, viewport.width - 2 * margin)) + "px";
        main.style.maxHeight = maxHeight + "px";
        const result = placement(rect, viewport, main.getBoundingClientRect().height);
        if (!result) {
          callbacks.cancel();
          return;
        }
        host.style.left = result.left + "px";
        host.style.top = result.top + "px";
        main.style.maxHeight = result.height + "px";
        host.dataset.keychainPlacement = result.side;
        host.style.visibility = "visible";
      }
      frame = requestAnimationFrame(track);
    }
    function render(accounts, managerAvailable) {
      if (main) observer.unobserve(main);
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
      observer.observe(main);
      dirty = true;
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
    observer.observe(main);
    frame = requestAnimationFrame(track);
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
        closed = true;
        cancelAnimationFrame(frame);
        observer.disconnect();
        host.remove();
      },
    };
  }
  globalThis.KeychainFormMenu = Object.freeze({ create, placement });
})();
