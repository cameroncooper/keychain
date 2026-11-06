# Driver interface validation

Current copies: local `experiment/sep-biometric-decrypt` through `85aabf1657`.
The running functional module is from `3d562e4551`; the later commit adds header,
client and documentation without changing kernel execution. Signing review
branch remains separately preserved through `bbeb7c0900`. No upstream PR opened.

On J293/M1, 2026-11-05, the cleaned functional module passed:

- Saved wrapped biometric key decrypts the exact expected disposable 32 bytes
  after a warm reboot, without a diagnostic signature or negative preflight.
- Immediate second POLL returns ENODATA: plaintext delivery is consumed.
- One authentication-tag bit changed: request returns EIO (-5), output buffer
  remains all zero. Generic EIO does not identify the precise firmware stage.
- Finger explicitly removed, fresh request with valid ciphertext: timeout and
  no plaintext. A previous matched context did not satisfy the new request.
- The original saved signing-only key signs a new prehashed digest using the
  unchanged signing interface; independent OpenSSL verification passes.

Earlier signing review validation also covered disposable creation, context
cleanup, normal fingerprint matching and saved signing-key warm reboot.

Six focused source tests cover encoding, credential-match fields, request
ownership/cancel/expiry, and abandoned plaintext expiry without polling. Normal
ARM64 module builds pass. KUnit-enabled object compilation for the original five
signing cases needed a temporary workaround for an unrelated baseline generic
assertion; the workaround was removed. No KUnit runtime pass is claimed.
Autonomous plaintext expiry is source-tested, not separately hardware-observed.

The new reference envelope passed independent SOFTWARE decryption, context
substitution refusal and tag-mutation rejection checks. C structure sizes,
pointer offsets and ioctl constants were compile-checked against the Rust ABI.
The new reusable Python decrypt_into wrapper and context-bearing envelope have
not yet been positively exercised together against hardware; the raw concrete
ioctls and cipher profile were. The application's provider should perform that
end-to-end disposable check before migrating any real vault data.

Cold power-cycle, suspend, other hardware, enrollment-set invalidation,
multi-user/broker isolation, native private-key import, P-384, vault migration
and recovery are not established. The application must keep these unsupported
rather than infer them from biometric primitive success. The currently loaded
module is temporary, and GET_INFO signing capability alone does not distinguish
this local decrypt extension.
