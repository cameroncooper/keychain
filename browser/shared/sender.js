// Browser-supplied metadata only. Page options cannot select an origin/frame.
globalThis.KeychainSender = {
  caller(sender, extensionId) {
    if (sender?.id !== extensionId || !Number.isInteger(sender.tab?.id) || sender.frameId !== 0) {
      throw new Error("Only top-level extension content scripts may request credentials");
    }
    const url = new URL(sender.url);
    if (url.protocol !== "https:" || url.origin === "null" || (sender.origin !== undefined && sender.origin !== url.origin)) {
      throw new Error("Credentials require a non-opaque HTTPS document origin");
    }
    return url;
  },
};
