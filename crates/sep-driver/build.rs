use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=include/linux/apple-sep.h");
    println!("cargo:rerun-if-changed=tests/abi.c");
    // The supported deployment is native 64-bit Linux. Do not accidentally run
    // a host ABI probe when cross-compiling for a different target.
    assert_eq!(
        env::var("HOST").unwrap_or_else(|e| panic!("HOST: {e}")),
        env::var("TARGET").unwrap_or_else(|e| panic!("TARGET: {e}")),
        "SEP bindings require a native build against the vendored UAPI"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap_or_else(|| panic!("OUT_DIR missing")));
    let probe = out.join("sep-abi");
    let status = Command::new("cc")
        .args([
            "-std=c11",
            "-Wall",
            "-Werror",
            "-Iinclude",
            "tests/abi.c",
            "-o",
        ])
        .arg(&probe)
        .status()
        .unwrap_or_else(|e| panic!("compile SEP UAPI probe: {e}"));
    assert!(status.success(), "SEP UAPI probe compilation failed");
    let result = Command::new(probe)
        .output()
        .unwrap_or_else(|e| panic!("run SEP UAPI probe: {e}"));
    assert!(result.status.success(), "SEP UAPI probe failed");
    std::fs::write(out.join("abi.rs"), result.stdout)
        .unwrap_or_else(|e| panic!("write SEP ABI constants: {e}"));
}
