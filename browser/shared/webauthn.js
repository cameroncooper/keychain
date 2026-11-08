// Public WebAuthn wire encoding. No secret/private-key material enters this code.
(() => {
  function encode(value) {
    let bytes;
    if (ArrayBuffer.isView(value)) bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    else if (Object.prototype.toString.call(value) === "[object ArrayBuffer]") bytes = new Uint8Array(value);
    else throw new TypeError("WebAuthn binary fields must be BufferSource values");
    if (bytes.length > 4096) throw new TypeError("WebAuthn binary field exceeds its limit");
    return btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(""))
      .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  }
  function decode(value) {
    if (typeof value !== "string" || value.length > 1024 * 1024 || !/^[A-Za-z0-9_-]*$/.test(value)) {
      throw new TypeError("Invalid WebAuthn base64url response");
    }
    const raw = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
    return Uint8Array.from(raw, char => char.charCodeAt(0)).buffer;
  }
  function serialize(kind, publicKey) {
    // Snapshot the WebIDL inputs before asynchronous dispatch. JSON serialization
    // is only for public fields; binary BufferSources are encoded explicitly.
    const result = JSON.parse(JSON.stringify(publicKey));
    result.challenge = encode(publicKey.challenge);
    const list = kind === "create" ? "excludeCredentials" : "allowCredentials";
    if (publicKey[list] !== undefined) {
      if (publicKey[list].length > 256) throw new TypeError("Too many credential descriptors");
      result[list] = Array.from(publicKey[list], item => ({ ...JSON.parse(JSON.stringify(item)), id: encode(item.id) }));
    }
    if (kind === "create") {
      result.user = { ...result.user, id: encode(publicKey.user.id) };
    }
    if (JSON.stringify(result).length > 256 * 1024) throw new TypeError("WebAuthn request exceeds its limit");
    return result;
  }
  function credential(json) {
    const data = JSON.parse(json);
    if (data.type !== "public-key" || data.id !== data.rawId || typeof data.response !== "object") {
      throw new TypeError("Invalid public-key credential response");
    }
    const response = { clientDataJSON: decode(data.response.clientDataJSON) };
    for (const field of ["attestationObject", "authenticatorData", "signature", "userHandle"]) {
      if (field in data.response) response[field] = data.response[field] === null ? null : decode(data.response[field]);
    }
    if (data.response.attestationObject) {
      response.getAuthenticatorData = () => decode(data.response.authenticatorData);
      response.getPublicKey = () => data.response.publicKey ? decode(data.response.publicKey) : null;
      response.getPublicKeyAlgorithm = () => data.response.publicKeyAlgorithm;
      response.getTransports = () => [...(data.response.transports ?? [])];
    }
    return { id: data.id, rawId: decode(data.rawId), type: "public-key",
      authenticatorAttachment: data.authenticatorAttachment ?? "platform", response,
      getClientExtensionResults: () => JSON.parse(JSON.stringify(data.clientExtensionResults ?? {})),
      toJSON: () => JSON.parse(JSON.stringify(data)) };
  }
  globalThis.KeychainWebAuthn = { encode, decode, serialize, credential };
})();
