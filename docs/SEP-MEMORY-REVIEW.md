# Selected-secret memory review

Reviewed 2026-11-06 against this repository's Cargo.lock and locally resolved
crate source. This is a source review of specific allocations and destructors,
not proof that the optimized binary erases every compiler, register or stack copy.
The iCloud write flag remains disabled pending the remaining review and live gates.

## Application-owned storage

| Operation | Storage and cleanup | Remaining exposure |
| --- | --- | --- |
| SEP plaintext delivery | `SecretBuffer` maps its final size, checks mlock, MADV_DONTDUMP and MADV_DONTFORK before input; Drop wipes the whole mapping before unlock/unmap | Driver/kernel internal copies require separate review |
| Selected passkey generation | Random bytes arrive directly in SecretBuffer, then are sealed before that mapping is dropped | P-256 public derivation creates library scalar temporaries |
| Assertion / registration | `SelectedScalar` borrows a context-checked scalar only during the authorized operation; no serializer or raw accessor | SigningKey and elliptic-curve arithmetic use ordinary stack objects |
| CKKS upload encoding | Fixed protected X9.63 and 64-KiB plist buffers; serializer sees a zero placeholder, real private bytes inserted afterward; encryption is in place | Crypto primitive internal copies are outside these buffers |
| Independent fetch verification | Decrypt/unwrap into protected buffers; private plist data erased before owned metadata parsing; destination wiped on authentication failure | Account TLK/class-key resolution remains zeroizing heap memory |
| TOTP generation | Borrowed URI structure; locked decoded query/normalized seed/base32 destinations; wiping finalized MAC/output code; decoder failure wipes the whole protected destination | Compiler and HMAC/digest scratch remain outside the protected allocations; generated code intentionally leaves the process when revealed |

The broker becomes nondumpable before serving. The installed unit disables core
dumps, bounds locked memory and restricts the broker to AF_UNIX. Apple HTTP and
helper exec remain in the separate service, started before a selected scalar is
live. These policies reduce exposure; they do not make ordinary heap or thread
stack pages mlocked. `MADV_DONTFORK` protects only the dedicated mappings, so
fork/exec with live secret temporaries remains prohibited.

## Resolved primitive implementations

The following findings come from the exact versions in Cargo.lock:

- `ecdsa 0.16.9`, `src/signing.rs`: SigningKey Drop zeroizes its stored scalar.
  `elliptic-curve 0.13.8`, `src/secret_key.rs` and `src/ecdh.rs`: SecretKey and
  SharedSecret own zeroize-on-drop storage. This does not cover all copies made
  during parsing, public derivation or arithmetic.
- `ecdsa 0.16.9`, `src/hazmat.rs`: deterministic signing serializes the private
  scalar and derives an RFC6979 nonce. `rfc6979 0.4.0`, `src/lib.rs`: HmacDrbg
  retains HMAC state and a chaining value without a wiping Drop implementation.
  `hmac 0.12.1` also provides no general zeroize-on-drop guarantee for its digest
  state. Consequently, successful SigningKey destruction alone does not establish
  complete signing scratch erasure. The same limitation applies to TOTP's HMAC.
- `aes 0.8.4` and `cmac 0.7.2`: explicitly enabled `zeroize` features provide
  retained key/MAC cleanup. `aes-siv 0.7.0`, `src/siv.rs`: Drop wipes the retained
  encryption key. Existing in-place SIV tests establish interoperability and
  destination cleanup on rejection, not complete primitive scratch erasure.
- `aes-gcm 0.10.3`, `src/lib.rs`: the optional `zeroize` feature wipes its temporary
  GHASH key. It does not implicitly enable all transitive cleanup. The manifest
  now also enables `ghash 0.5.1` and `polyval 0.6.2` zeroize features. GHASH wipes
  construction intermediates and POLYVAL's soft32/soft64 and x86 CLMUL backends
  implement state cleanup. Asahi's normal aarch64 build selects soft64.
- `polyval 0.6.2`, `src/backend.rs` and `src/backend/pmull.rs`: the opt-in
  `polyval_armv8` backend has a commented-out cleanup implementation. Enabling
  that custom cfg changes this review's conclusion and needs an explicit fix or
  reviewed backend choice. No claim of complete cleanup applies to arbitrary
  custom RUSTFLAGS/builds.

Feature unification in Cargo.toml deliberately enables the transitive AES-GCM
cleanup even where the application does not directly call GHASH/POLYVAL APIs.
Cargo.lock retains the existing primitive versions; these are feature changes,
not a cryptographic algorithm or wire-format change.

## TOTP corrections and evidence

The generator previously parsed a second owned seed-bearing URL, collected query
values into ordinary strings, created unwiped normalization/decoded-seed buffers,
and dropped a heap MAC without wiping it. It also silently clamped invalid
settings and overflowed the expiry calculation at extreme timestamps.

It now bounds input to 4096 bytes and 32 query parameters, rejects duplicate
security parameters (including percent-encoded names), invalid algorithms,
invalid digit/period values and unrepresentable expiry. URI labels remain opaque;
percent-encoded, spaced, lowercase and padded base32 seeds remain supported.
Base32 decoding writes into an already-owned locked buffer so partial decoding
errors cannot bypass cleanup. Form decoding and normalization also use final-size
protected buffers; there is no seed-bearing owned Url, query String or seed Vec.
The source URI remains borrowed and the original software vault is unchanged. GeneratedCode wipes its owned code on drop and
redacts it from Debug; normal reveal output remains intentional.

Tests use only published synthetic RFC 6238 seeds. All eighteen vectors across
SHA-1/SHA-256/SHA-512 and six timestamps pass, alongside malformed/duplicate,
partial-decoding, input-bound, expiry-bound and redacted-debug checks. These tests
verify behavior and owner lifetimes by source inspection; they do not scan live
process memory or prove that compiler copies have disappeared.

## Remaining implementation and acceptance work

1. Harden or replace the reviewed signing/HMAC scratch path without introducing
   custom cryptographic algorithms. Validate the actual supported backend and
   optimized build, including errors and panic/unwind. Keep the narrower memory
   claims above until this is established.
2. Validate the implemented changed-login staging/verified-update path on hardware
   for [login migration/reveal](SEP-LOGIN-REVEAL.md). CLI protected selection uses
   the metadata index; the encrypted source journal remains an explicit recovery
   copy. Content verification uses HMAC with a random key inside the sealed
   payload; its primitive/compiler scratch shares the HMAC limits above. No raw
   TOTP seed or passkey scalar belongs in reveal IPC.
3. Exercise real protected assertion/registration, abort/session-lock/expiry and
   post-reboot persistence with user readiness and disposable credentials.
4. Complete fresh account authentication/bootstrap and explicitly scoped Apple
   write/fetch/other-device validation before enabling iCloud creation.

Protected root unsealing remains the separately specified follow-up. This review
does not justify retiring the old recovery copy, changing enrollment or resetting
account/ADI state.

Validation for this change: 202 workspace tests passed (21 intentionally ignored),
plus 17 privileged library tests run separately with synthetic keys/server data.
Formatting, strict Clippy and the release build passed. Updated service binaries
were installed with a retained backup and no write-flag change. Installed
broker/native-host availability passed without biometric capture. No real account
bootstrap, migration, login or Apple write was performed during this review.
