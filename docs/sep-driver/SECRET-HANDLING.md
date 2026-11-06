# Handling decrypted secrets in the keychain process

Design guidance for the keychain agent, not a claim that these protections are
already implemented. Use [DECRYPTION.md](DECRYPTION.md) for the actual driver API
and [VALIDATION.md](VALIDATION.md) for the evidence and limits. These practices
apply especially to downloaded/synced passkey scalars that must sign in software.

## Recommended boundary

Keep decryption and software signing in a small dedicated helper/broker:

```text
validated request -> authorize selected credential -> SEP biometric decrypt
                  -> validate item binding -> software sign -> wipe -> signature
```

Return only the signature to the browser host or main application. Prefer an
operation such as sign(selected_credential, validated_request) over an API that
returns a private key or decrypts arbitrary caller-supplied blobs. The trusted
component must resolve the key and enforce policy itself. This boundary can be
an on-demand process; it does not inherently require an always-running daemon.

For new device-bound passkeys, prefer SEP-native signing: the host need never
receive the private scalar. For an existing synced passkey, the current decrypt
primitive returns plaintext to Linux; a helper limits exposure but does not make
that imported scalar a non-exportable SEP-native key. Native private-key import
has not been established.

## Keep plaintext scope and lifetime small

- Decrypt only the selected item after authorization. Avoid unlocking or caching
  a vault-wide root merely to perform one passkey assertion.
- Keep the secret for one bounded operation. Wipe it immediately after use,
  including key objects and crypto-library state, on success, cancellation and
  ordinary error paths. A timeout must not depend on a client polling again.
- Treat close, client disconnect and worker failure as cleanup paths. Do not
  transfer secrets to background tasks with unclear ownership/lifetime.
- Do not silently convert one successful scan into permission for future
  assertions. Reuse/caching requires a separately designed, explicit policy.
- Do not log secrets, serialize them in diagnostic errors, place them in command
  arguments/environment variables, or write them to plaintext temporary files.
  Passkey signing must not use the clipboard.

The driver's five-second undelivered-result limit applies to its retained output,
not to any application copy. The application owns the latter's cleanup.

## Memory allocation and erasure

Use a dedicated allocation for secret bytes, created at its final capacity before
filling it. Prefer a maintained secret-memory abstraction over scattered unsafe
system calls. Dedicated page-aligned mappings let page protections apply without
sharing pages with unrelated allocator objects. Respect the runtime page size;
do not assume 4096-byte pages just because the ioctl buffer capacity is 4096.

In Rust, use zeroizing containers and cryptographic key types with documented
cleanup. Borrow secret data where possible. Avoid Clone/Copy, String, formatting,
JSON, unnecessary byte conversions and buffer growth. Review the signing library's
imported key representation, expanded state, scratch allocations and destruction
behavior: wiping only the original scalar buffer is insufficient.

Zeroization must resist compiler removal. RustCrypto zeroize provides that for
the storage it reaches; it cannot erase previous reallocation copies, compiler
moves, register/stack spills or undocumented crypto-library temporaries. Heap
allocation reduces some accidental copying but does not establish perfect erasure.
RAII cleanup covers normal returns/unwinding, not every abort or forced kill.

The Python client/envelope is a reference for ABI and format, not a production
secret-memory implementation. Python immutable bytes and backend temporaries
cannot all be reliably wiped. Preserve this distinction in the application.

## Linux memory protections

Establish protections before receiving plaintext, check return values, and define
explicit failure behavior rather than silently claiming unavailable protection:

- Lock secret mappings with mlock() before filling them to prevent swapping of
  those pages. Set an appropriate bounded RLIMIT_MEMLOCK/service configuration.
  Locking one input buffer does not lock copies inside the signing library.
- Mark secret mappings MADV_DONTDUMP. Set PR_SET_DUMPABLE to 0 for the helper after
  establishing its final credentials, and ensure crash reporting cannot capture
  secrets. This restricts ordinary ptrace access; sufficiently privileged access
  is a different threat. Do not assume RLIMIT_CORE=0 alone configures every
  system crash collector appropriately.
- Avoid fork/exec while secrets exist. Use close-on-exec file descriptors and
  explicit descriptor ownership. If secret mappings may coexist with fork,
  consider MADV_DONTFORK with a deliberately compatible process model.
- Wipe before unlocking/unmapping secret buffers. mlock() does not prevent RAM
  being included in a hibernation image. Supporting hibernation needs a separate
  policy for wiping live keys and protecting the image.

memfd_secret() is not a drop-in output buffer for this driver: its mappings cannot
be accessed through ordinary kernel userspace-copy paths, so the decrypt ioctl
cannot copy directly into them. Starting with an ordinary dedicated mapping that
is locked and excluded from dumps avoids inventing an extra copy stage. Secret
memory also cannot contain every temporary of an arbitrary crypto library.

## Authorize the operation and the caller

Use a restricted IPC endpoint and kernel-supplied peer credentials such as
SO_PEERCRED for Unix sockets. Never trust a user ID, application name, biometric
success boolean or key-owner field merely because the client supplied it.
SO_PEERCRED authenticates process credentials, not a particular trustworthy
application among all processes with that UID. Strong same-user application
isolation needs an appropriate sandbox/portal or other trusted identity boundary.

Enforce selected-key ownership, algorithm, purpose and request bounds in the
trusted component. Verify the decrypted item's authenticated context against
trusted selected-record state before using it. Context must include enough
identity/purpose information to reject substitution. Public-key encryption does
not authenticate who created an item; preserve authenticated application storage.
Replay/rollback protection needs separate trusted state.

Keep WebAuthn RP/origin, credential selection and exact assertion-data validation
inside the trusted authorization design. If a compromised client can choose an
arbitrary digest, the broker must not claim it has independently established its
website or intent. SEP biometric matching does not itself validate browser origin.

Give the helper only the device, filesystem and IPC access it requires. Keep
Apple account networking, browser parsing, plugins and general application logic
outside it. Coordinate the existing exclusive SEP device access with fprintd.
An opened device descriptor may require no ongoing broad root privileges, but
verify actual permission checks before designing privilege dropping. Do not run
the entire browser/native host as root to solve the device-permission problem.

## Practical validation before real data

Keep checks focused on the promised guarantees:

1. Show a disposable passkey assertion returns a valid signature without passing
   its scalar through browser IPC, logs or temporary files.
2. Exercise wrong item binding, cancellation, client disconnect and a signing
   failure; confirm cleanup and that an unauthorized caller cannot obtain a
   signature or invoke an arbitrary decrypt endpoint.
3. Verify the deployed helper is nondumpable and its intended secret mapping is
   locked/dump-excluded; deliberately test protection-setup failure handling.

Use synthetic secrets for diagnostic inspection. Do not collect production keys
in a core dump to test the implementation. These checks supplement, rather than
replace, the existing driver primitive tests. They do not justify automatic vault
migration before its transaction and recovery behavior are validated.

Process hardening reduces ordinary process access and accidental retention. It
cannot protect host plaintext against a compromised helper, an attacker with
sufficient debugging privileges or a compromised kernel. Keep that limitation
separate from the stronger private-key confinement of SEP-native signing.

## Primary references

- [RustCrypto zeroize: guarantees and copying limitations](https://docs.rs/zeroize/latest/zeroize/)
- [Linux mlock: memory locking and hibernation limitations](https://man7.org/linux/man-pages/man2/mlock.2.html)
- [Linux madvise: MADV_DONTDUMP and MADV_DONTFORK](https://man7.org/linux/man-pages/man2/madvise.2.html)
- [Linux PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)
- [Unix socket peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html)
- [Linux memfd_secret and system-call buffer restrictions](https://man7.org/linux/man-pages/man2/memfd_secret.2.html)
