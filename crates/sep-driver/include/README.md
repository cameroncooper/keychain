# Pinned SEP UAPI

`linux/apple-sep.h` is an unmodified source-only copy supplied in
`~/.local/share/aurora-sep/application-keys/include/linux/apple-sep.h`, from
linux-aurora commit `56800a8bf` (PR 407). Its SPDX expression permits use under
MIT or GPL-2.0 WITH Linux-syscall-note.

Application operations use only `SEP_KEY_*`. `build.rs` compiles and executes
`tests/abi.c` against this header to generate ioctl/limit/capability constants
and compile-time Rust structure size/offset assertions. No hand-maintained
numeric ioctl table or old BIO application-key bindings remain. Native 64-bit
little-endian Linux builds require a C compiler; cross compilation is explicitly
refused rather than guessing a target ABI from a host probe.
