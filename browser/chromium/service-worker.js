// Chromium alone supplies browser-validated WebAuthn proxy events/origins.
globalThis.keychainApi = chrome;
globalThis.keychainTransport = chrome.webAuthenticationProxy;
importScripts("sender.js", "forms-background.js", "core.js");
