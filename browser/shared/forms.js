// Isolated-world request controller. Classification, DOM delivery guards and
// presentation live in separate shared modules; authorization stays native.
(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (
    !isSecureContext ||
    window !== window.top ||
    window.origin === "null" ||
    window.origin !== new URL(document.URL).origin
  )
    return;
  const dom = KeychainFormDOM;
  let active,
    manualProbe,
    enabled = false,
    restoringFocus = false;
  void api.storage.local.get("proxyEnabled").then((settings) => {
    enabled = settings.proxyEnabled !== false;
    if (enabled && document.activeElement instanceof HTMLInputElement)
      start(document.activeElement);
  });
  api.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.proxyEnabled) {
      enabled = changes.proxyEnabled.newValue !== false;
      if (!enabled) stop();
    }
  });
  function stop(session = active) {
    manualProbe = null;
    if (!session || session.closed) return;
    session.closed = true;
    session.port.disconnect();
    session.view.close();
    if (active === session) active = null;
  }
  const valid = (session) =>
    !session.closed &&
    !session.disconnected &&
    dom.valid(session.plan, session.view.host);
  function select(session, id) {
    const candidate = session.candidates?.get(id);
    if (!candidate || session.used || !valid(session)) {
      stop(session);
      return;
    }
    session.used = true;
    const field =
      candidate.kind === "passkey"
        ? "username"
        : session.plan.mode === "totp"
          ? "totp"
          : session.plan.password
            ? "password"
            : "username";
    session.view.busy(
      field === "username"
        ? "Filling username…"
        : "Continue in the desktop fingerprint prompt…",
    );
    session.port.postMessage({ kind: "fill", id, field });
  }
  function fill(session, reply) {
    let filled;
    try {
      if (session.used && valid(session))
        filled = dom.apply(session.plan, reply, session.view.host);
    } finally {
      if (reply.result) {
        delete reply.result.password;
        delete reply.result.totp;
      }
      stop(session);
      if (filled?.isConnected && document.hasFocus()) {
        restoringFocus = true;
        try {
          filled.focus({ preventScroll: true });
        } finally {
          restoringFocus = false;
        }
      }
    }
  }
  function start(field, manualRole) {
    if (!enabled || document.hidden) return false;
    if (active?.plan.focused === field && !manualRole && valid(active))
      return true;
    const plan = dom.plan(field, active?.view.host, manualRole);
    stop();
    if (!plan) return false;
    const port = api.runtime.connect({ name: "keychain-login" });
    const session = { plan, port, used: false, closed: false };
    session.view = KeychainFormMenu.create(field, {
      choose: (id) => select(session, id),
      cancel: () => stop(session),
      manager: () => {
        if (session.used || !valid(session)) return;
        session.used = true;
        session.view.busy("Opening Keychain…");
        port.postMessage({ kind: "manager" });
      },
    });
    active = session;
    port.onMessage.addListener((reply) => {
      if (reply.kind === "candidates") {
        if (!valid(session)) {
          stop(session);
          return;
        }
        const choices = reply.candidates.filter((candidate) =>
          candidate.kind === "passkey"
            ? plan.mode === "username"
            : plan.mode === "totp"
              ? candidate.hasTotp
              : plan.password
                ? candidate.hasPassword
                : true,
        );
        session.candidates = new Map(
          choices.map((candidate) => [candidate.id, candidate]),
        );
        session.view.render(
          choices.map((candidate) => ({
            ...candidate,
            label:
              candidate.kind === "passkey"
                ? "Passkey"
                : plan.mode === "totp"
                  ? "Code"
                  : plan.password
                    ? "Password"
                    : "Username",
          })),
          reply.managerAvailable,
        );
      } else if (reply.kind === "select") select(session, reply.id);
      else if (reply.kind === "fill") fill(session, reply);
      else if (reply.kind === "error") {
        session.terminal = true;
        session.view.message(reply.message);
      }
    });
    port.onDisconnect.addListener(() => {
      session.disconnected = true;
      if (!session.terminal) stop(session);
    });
    port.postMessage({
      kind: "inspect",
      field: plan.mode,
      hasPasswordField: !!plan.password,
    });
    return true;
  }
  document.addEventListener(
    "focusin",
    (event) => {
      if (restoringFocus || event.target === active?.view.host) return;
      if (event.target instanceof HTMLInputElement) start(event.target);
      else stop();
    },
    true,
  );
  document.addEventListener(
    "pointerdown",
    (event) => {
      if (event.target === active?.view.host) return;
      if (event.isTrusted && event.target instanceof HTMLInputElement)
        start(event.target);
      else stop();
    },
    true,
  );
  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key === "Escape") stop();
      else if (
        event.isTrusted &&
        event.key === "ArrowDown" &&
        active?.plan.selected.includes(event.target)
      ) {
        event.preventDefault();
        active.view.focusFirst();
      }
    },
    true,
  );
  api.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== api.runtime.id || message?.type !== "keychainInspectForm")
      return;
    const focused = document.activeElement;
    if (focused instanceof HTMLInputElement) {
      if (message.manualRole) {
        const probe = manualProbe;
        manualProbe = null;
        if (
          !probe ||
          probe.token !== message.manualToken ||
          probe.expires < Date.now() ||
          probe.binding.focused !== focused ||
          !probe.roles.includes(message.manualRole) ||
          !dom.valid(probe.binding)
        )
          return Promise.resolve({ ok: false });
        return Promise.resolve({ ok: start(focused, message.manualRole) });
      }
      const ok = start(focused);
      if (ok) return Promise.resolve({ ok: true });
      const fallback = dom.fallback(focused);
      if (!fallback) {
        manualProbe = null;
        return Promise.resolve({ ok: false });
      }
      manualProbe = {
        ...fallback,
        token: crypto.randomUUID(),
        expires: Date.now() + 30000,
      };
      return Promise.resolve({
        ok: false,
        manualRoles: fallback.roles,
        manualToken: manualProbe.token,
      });
    }
    if (message.manualRole) return Promise.resolve({ ok: false });
    const first = [...document.querySelectorAll("input")]
      .slice(0, 64)
      .find((field) => dom.plan(field));
    return Promise.resolve({ ok: first ? start(first) : false });
  });
  window.addEventListener("pagehide", () => stop());
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stop();
  });
})();
