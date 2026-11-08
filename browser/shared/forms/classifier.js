// Pure classification over bounded public field metadata. No DOM, values,
// browser APIs or authorization decisions. Keep rules and reasons testable.
(() => {
  const normalize = (value) =>
    String(value ?? "")
      .slice(0, 512)
      .replace(/([a-z])([A-Z])/g, "$1 $2")
      .normalize("NFKC")
      .toLowerCase()
      .replace(/[^\p{L}\p{N}]+/gu, " ")
      .trim()
      .replace(/\s+/g, " ");
  const words = (values) => values.map(normalize).filter(Boolean).join(" ");
  const tokens = (field) =>
    String(field.autocomplete ?? "")
      .toLowerCase()
      .split(/\s+/);
  const result = (role, confidence, reason) => ({
    role,
    confidence,
    reasons: [reason],
  });
  const unsupported =
    /\b(?:search|newsletter|subscribe|coupon|discount|promo|postal|zip|cvv|cvc|card number|credit card)\b/;
  const username =
    /\b(?:username|user name|user id|userid|email|e mail|login(?: id)?|account (?:name|id)|identifier)\b/;
  const code =
    /\b(?:otp|totp(?:mfa|code)?|totp mfa|mfa(?:code| code)?|2fa(?:code| code)?|one time (?:password|code)|authenticator(?: app)?(?: code)?|verification(?:code| code)|security code)\b/;
  const newPassword =
    /\b(?:(?:new|confirm|repeat|retype) (?:your )?(?:password|passwd)|(?:password|passwd) (?:confirmation|confirm|again|repeat))\b/;
  const currentPassword = /\b(?:current|old|existing) (?:password|passwd)\b/;
  const nonTotp =
    /\b(?:sms|text message|backup code|recovery code|email code|e mail code|code (?:sent|emailed|texted)|sent (?:to|by) (?:your )?(?:email|phone))\b/;
  const confidenceRank = { none: 0, contextual: 1, strong: 2, explicit: 3 };
  function classify(field, context) {
    const hints = tokens(field);
    const semantic = words([field.label, field.ariaLabel, field.labelledBy]);
    const identifiers = words([field.name, field.id]);
    const text = words([semantic, identifiers, field.placeholder]);
    if (!field.eligible) return result("excluded", "none", "unavailable-field");
    if (!["text", "email", "tel", "number", "password"].includes(field.type))
      return result("excluded", "none", "unsupported-input-type");
    if (
      hints.some((hint) =>
        /^(?:cc-|address-|postal-code$|shipping$|billing$)/.test(hint),
      ) ||
      unsupported.test(text)
    )
      return result("excluded", "strong", "non-login-field");
    if (hints.includes("new-password") || newPassword.test(text))
      return result("new-password", "explicit", "new-or-confirm-password");
    if (
      context.intent === "search" ||
      context.intent === "newsletter" ||
      context.intent === "payment"
    )
      return result("excluded", "strong", "non-login-form");
    if (nonTotp.test(text))
      return result("excluded", "strong", "non-totp-code");
    if (
      hints.includes("one-time-code") ||
      code.test(text) ||
      (context.authenticator && /\bcode\b/.test(text))
    ) {
      if (!["text", "tel", "number", "password"].includes(field.type))
        return result("excluded", "none", "unsupported-code-type");
      if (field.maxLength > 0 && field.maxLength < 6)
        return result("excluded", "strong", "segmented-code");
      return result(
        "totp",
        hints.includes("one-time-code") ? "explicit" : "strong",
        "verification-code",
      );
    }
    if (context.intent === "signup" || context.intent === "reset")
      return result("excluded", "strong", "new-account-or-reset-form");
    if (hints.includes("current-password"))
      return field.type === "password"
        ? result("password", "explicit", "current-password-token")
        : result("excluded", "none", "unmasked-password-hint");
    if (field.type === "password") {
      if (currentPassword.test(text))
        return result("password", "strong", "current-password-label");
      if (context.hasNewPassword || context.passwordCount > 1)
        return result("unknown", "none", "ambiguous-passwords");
      return result("password", "strong", "password-type");
    }
    if (hints.includes("username"))
      return result("username", "explicit", "username-token");
    if (hints.includes("email") || field.type === "email")
      return result("username", "strong", "email-field");
    if (username.test(semantic))
      return result("username", "strong", "account-label");
    if (
      username.test(identifiers) ||
      username.test(normalize(field.placeholder))
    )
      return result("username", "contextual", "account-hint");
    return result("unknown", "none", "insufficient-evidence");
  }
  function analyze(fields, publicContext = {}) {
    const text = words([publicContext.heading, publicContext.buttons]);
    let intent = "unknown";
    if (publicContext.search || /\bsearch\b/.test(text)) intent = "search";
    else if (/\b(?:subscribe|newsletter|mailing list)\b/.test(text))
      intent = "newsletter";
    else if (/\b(?:pay now|place order|payment|checkout)\b/.test(text))
      intent = "payment";
    else if (
      /\b(?:sign up|signup|register|registration|create (?:an )?account|join now)\b/.test(
        text,
      )
    )
      intent = "signup";
    else if (/\b(?:reset|forgot|recover) (?:your )?password\b/.test(text))
      intent = "reset";
    else if (
      /\b(?:sign in|signin|log in|login|authenticate|continue|next)\b/.test(
        text,
      )
    )
      intent = "login";
    const context = {
      intent,
      authenticator:
        /\b(?:totp|authenticator|multi factor|two factor|2fa|mfa)\b/.test(text),
      hasNewPassword: fields.some(
        (field) =>
          field.eligible &&
          (tokens(field).includes("new-password") ||
            newPassword.test(
              words([
                field.name,
                field.id,
                field.label,
                field.ariaLabel,
                field.labelledBy,
                field.placeholder,
              ]),
            )),
      ),
      passwordCount: fields.filter(
        (field) => field.eligible && field.type === "password",
      ).length,
    };
    if (
      context.hasNewPassword &&
      !fields.some(
        (field) =>
          field.eligible &&
          (tokens(field).includes("current-password") ||
            currentPassword.test(
              words([
                field.name,
                field.id,
                field.label,
                field.ariaLabel,
                field.labelledBy,
              ]),
            )),
      ) &&
      ["unknown", "login"].includes(intent)
    )
      context.intent = "signup";
    const roles = fields.map((field) => classify(field, context));
    const passwords = roles.flatMap((role, index) =>
      role.role === "password" ? [index] : [],
    );
    // Context can identify an otherwise anonymous username. Never guess among
    // multiple preceding text controls, or transfer this inference to a code.
    if (
      passwords.length === 1 &&
      !roles.some((role) => role.role === "username")
    ) {
      const preceding = fields.flatMap((field, index) =>
        index < passwords[0] &&
        ["text", "tel"].includes(field.type) &&
        roles[index].role === "unknown"
          ? [index]
          : [],
      );
      if (preceding.length === 1)
        roles[preceding[0]] = result(
          "username",
          "contextual",
          "single-field-before-password",
        );
    }
    if (
      intent === "login" &&
      !passwords.length &&
      !context.hasNewPassword &&
      !roles.some((role) => role.role === "username" || role.role === "totp")
    ) {
      const possible = fields.flatMap((field, index) =>
        ["text", "tel"].includes(field.type) && roles[index].role === "unknown"
          ? [index]
          : [],
      );
      if (possible.length === 1)
        roles[possible[0]] = result(
          "username",
          "contextual",
          "username-first-form",
        );
    }
    return { intent: context.intent, roles };
  }
  function uniqueBest(roles, role) {
    const candidates = roles.flatMap((entry, index) =>
      entry.role === role
        ? [{ index, rank: confidenceRank[entry.confidence] }]
        : [],
    );
    candidates.sort((a, b) => b.rank - a.rank);
    return candidates.length &&
      (candidates.length === 1 || candidates[0].rank > candidates[1].rank)
      ? candidates[0].index
      : null;
  }
  globalThis.KeychainFieldClassifier = Object.freeze({ analyze, uniqueBest });
})();
