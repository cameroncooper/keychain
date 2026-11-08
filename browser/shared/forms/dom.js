// DOM adapter: bounded public descriptors, original-node plans and delivery
// checks. The classifier never sees editable values or credentials.
(() => {
  const classifier = KeychainFieldClassifier;
  const setter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  ).set;
  const limit = 64;
  const text = (value) => String(value ?? "").slice(0, 512);
  function visible(field, overlay) {
    if (
      !(field instanceof HTMLInputElement) ||
      !field.isConnected ||
      field.disabled ||
      field.readOnly ||
      field.matches(":disabled") ||
      field.closest('[inert],[aria-hidden="true"]')
    )
      return false;
    for (let node = field; node instanceof Element; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (
        style.visibility !== "visible" ||
        style.display === "none" ||
        Number(style.opacity) < 0.5
      )
        return false;
    }
    const rect = field.getBoundingClientRect();
    if (
      rect.width < 8 ||
      rect.height < 8 ||
      rect.bottom <= 0 ||
      rect.top >= innerHeight ||
      rect.right <= 0 ||
      rect.left >= innerWidth
    )
      return false;
    const hit = document.elementFromPoint(
      Math.min(innerWidth - 1, Math.max(0, rect.left + rect.width / 2)),
      Math.min(innerHeight - 1, Math.max(0, rect.top + rect.height / 2)),
    );
    return hit === field || (overlay && hit === overlay);
  }
  function descriptor(field, overlay) {
    return {
      type: field.type,
      name: text(field.name),
      id: text(field.id),
      autocomplete: text(field.getAttribute("autocomplete")),
      label: text(
        [...(field.labels ?? [])]
          .slice(0, 4)
          .map((label) => label.textContent)
          .join(" "),
      ),
      ariaLabel: text(field.getAttribute("aria-label")),
      labelledBy: text(
        (field.getAttribute("aria-labelledby") ?? "")
          .split(/\s+/)
          .slice(0, 4)
          .map((id) => document.getElementById(id)?.textContent ?? "")
          .join(" "),
      ),
      placeholder: text(field.placeholder),
      inputMode: text(field.inputMode),
      maxLength: field.maxLength,
      eligible: visible(field, overlay),
    };
  }
  function collect(field, overlay) {
    if (!(field instanceof HTMLInputElement) || !field.isConnected) return null;
    const form = field.form;
    const scope =
      form ??
      field.closest('[role="form"],[role="search"],fieldset,section,dialog') ??
      document.body;
    if (!scope) return null;
    const fields = [];
    for (const input of form
      ? form.elements
      : scope.querySelectorAll("input")) {
      if (
        !(input instanceof HTMLInputElement) ||
        input.form !== form ||
        !["text", "email", "tel", "number", "password", "search"].includes(
          input.type,
        )
      )
        continue;
      fields.push(input);
      if (fields.length > limit) return null;
    }
    if (!fields.includes(field)) return null;
    const descriptors = fields.map((input) => descriptor(input, overlay));
    // Restrict context to the form/scope. A generic document body is not a
    // coherent form, so unrelated page headings/buttons cannot classify it.
    const coherent = scope !== document.body;
    const context = {
      heading: coherent
        ? text(
            scope.querySelector("legend,h1,h2,h3,[role=heading]")?.textContent,
          )
        : "",
      buttons: coherent
        ? [...scope.querySelectorAll('button,input[type="submit"]')]
            .slice(0, 8)
            .filter((button) => button.form === form)
            .map((button) =>
              text(
                button.tagName === "INPUT"
                  ? button.getAttribute("value")
                  : button.textContent,
              ),
            )
            .join(" ")
        : "",
      search: scope.getAttribute("role") === "search",
    };
    return {
      form,
      scope,
      fields,
      descriptors,
      context,
      analysis: classifier.analyze(descriptors, context),
    };
  }
  function fingerprint(details) {
    return JSON.stringify({
      fields: details.descriptors,
      context: details.context,
      analysis: details.analysis,
    });
  }
  function binding(field, details, selected = [field]) {
    return Object.freeze({
      focused: field,
      form: details.form,
      scope: details.scope,
      action: details.form?.action,
      target: details.form?.target,
      method: details.form?.method,
      url: location.href,
      fingerprint: fingerprint(details),
      nodes: Object.freeze([...details.fields]),
      selected: Object.freeze([...selected]),
      // Classification text is bounded. Routing attributes on the actual target
      // nodes must still match in full, including changes beyond that text bound.
      attributes: selected.map((input) => ({
        input,
        name: input.name,
        id: input.id,
        type: input.type,
        autocomplete: input.getAttribute("autocomplete"),
      })),
    });
  }
  function plan(field, overlay, manualRole) {
    const details = collect(field, overlay);
    if (!details) return null;
    const index = details.fields.indexOf(field),
      classified = details.analysis.roles[index];
    let mode = classified.role;
    if (manualRole) {
      if (!manualRoles(details, index).includes(manualRole)) return null;
      mode = manualRole;
    }
    if (!["username", "password", "totp"].includes(mode)) return null;
    if (details.form && new URL(details.form.action).origin !== location.origin)
      return null;
    const passwordIndex = classifier.uniqueBest(
      details.analysis.roles,
      "password",
    );
    const usernameIndex = classifier.uniqueBest(
      details.analysis.roles,
      "username",
    );
    const password = manualRole
      ? mode === "password"
        ? field
        : null
      : mode === "password"
        ? field
        : passwordIndex === null
          ? null
          : details.fields[passwordIndex];
    const username = manualRole
      ? mode === "username"
        ? field
        : null
      : mode === "username"
        ? field
        : usernameIndex === null
          ? null
          : details.fields[usernameIndex];
    const selected =
      mode === "totp"
        ? [field]
        : [...new Set([username, password].filter(Boolean))];
    return Object.freeze({
      ...binding(field, details, selected),
      mode,
      password,
      username,
      manualRole,
    });
  }
  function manualRoles(details, index) {
    if (
      ["signup", "reset", "payment", "newsletter", "search"].includes(
        details.analysis.intent,
      )
    )
      return [];
    if (
      details.analysis.roles[index].role !== "unknown" ||
      !details.descriptors[index].eligible
    )
      return [];
    const field = details.descriptors[index];
    if (field.type === "password") return ["password"];
    if (!["text", "email", "tel", "number"].includes(field.type)) return [];
    return field.maxLength > 0 && field.maxLength < 6
      ? ["username"]
      : ["username", "totp"];
  }
  function fallback(field, overlay) {
    const details = collect(field, overlay);
    if (
      !details ||
      (details.form && new URL(details.form.action).origin !== location.origin)
    )
      return null;
    const roles = manualRoles(details, details.fields.indexOf(field));
    return roles.length ? { roles, binding: binding(field, details) } : null;
  }
  function valid(plan, overlay) {
    if (
      !plan.attributes.every(
        ({ input, name, id, type, autocomplete }) =>
          input.name === name &&
          input.id === id &&
          input.type === type &&
          input.getAttribute("autocomplete") === autocomplete,
      )
    )
      return false;
    if (
      location.href !== plan.url ||
      document.hidden ||
      !plan.scope.isConnected
    )
      return false;
    if (
      plan.form &&
      (!plan.form.isConnected ||
        plan.form.action !== plan.action ||
        plan.form.target !== plan.target ||
        plan.form.method !== plan.method)
    )
      return false;
    const current = collect(plan.focused, overlay);
    return (
      !!current &&
      current.form === plan.form &&
      current.scope === plan.scope &&
      current.fields.length === plan.nodes.length &&
      current.fields.every((field, index) => field === plan.nodes[index]) &&
      fingerprint(current) === plan.fingerprint &&
      plan.selected.every((field) => visible(field, overlay))
    );
  }
  function apply(plan, reply, overlay) {
    if (!valid(plan, overlay)) return null;
    let filled;
    const set = (field, value) => {
      filled = field;
      setter.call(field, value);
      field.dispatchEvent(
        new Event("input", { bubbles: true, composed: true }),
      );
      field.dispatchEvent(new Event("change", { bubbles: true }));
    };
    if (
      reply.field === "username" &&
      plan.username &&
      typeof reply.username === "string"
    )
      set(plan.username, reply.username);
    else if (
      reply.field === "password" &&
      plan.password &&
      typeof reply.result?.password === "string"
    ) {
      if (plan.username) set(plan.username, reply.username);
      if (valid(plan, overlay)) set(plan.password, reply.result.password);
    } else if (
      reply.field === "totp" &&
      plan.mode === "totp" &&
      typeof reply.result?.totp?.code === "string" &&
      reply.result.totp.expires > Date.now() / 1000 + 1
    )
      set(plan.focused, reply.result.totp.code);
    return filled;
  }
  globalThis.KeychainFormDOM = Object.freeze({ plan, valid, apply, fallback });
})();
