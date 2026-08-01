//! Supplies the AArch64 cross link with a `libgcc_s` the Fedora cross toolchain
//! does not ship.
//!
//! Rust's `std` for `*-unknown-linux-gnu` links `-lgcc_s` for the unwinder. The
//! `gcc-aarch64-linux-gnu` package ships only the static `libgcc.a` — there is no
//! `libgcc_s.so` anywhere on the box and none in Fedora's cross sysroot — so the
//! link dies on `cannot find -lgcc_s`. The C probes never hit this because C does
//! not pull in an unwinder.
//!
//! Point `-lgcc_s` at the static archive instead. The probes are built
//! `panic = "abort"`, so the unwinder is never entered; this only has to satisfy
//! the reference.
//!
//! This runs from `support`, which every probe depends on, so the link search
//! path propagates to all three binaries without a build script each.

use std::path::PathBuf;
use std::process::Command;

const CROSS_TARGET: &str = "aarch64-unknown-linux-gnu";
const CROSS_GCC: &str = "aarch64-linux-gnu-gcc";
const SHIM_NAME: &str = "libgcc_s.a";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").unwrap_or_default();
    if target != CROSS_TARGET { return; }

    let Some(libgcc) = static_libgcc() else {
        println!("cargo:warning={CROSS_GCC} did not report a libgcc archive; the aarch64 link will fail on -lgcc_s");
        return;
    };
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR")).join("gcc-shim");
    std::fs::create_dir_all(&out).expect("create the gcc shim dir");
    let shim = out.join(SHIM_NAME);
    let _ = std::fs::remove_file(&shim);
    std::fs::copy(&libgcc, &shim).expect("stage libgcc.a as libgcc_s.a");
    println!("cargo:rustc-link-search=native={}", out.display());
}

/// Absolute path of the cross toolchain's static libgcc, as the compiler reports
/// it — never a hard-coded version directory, which changes with every GCC bump.
fn static_libgcc() -> Option<PathBuf> {
    let out = Command::new(CROSS_GCC).arg("-print-libgcc-file-name").output().ok()?;
    if !out.status.success() { return None; }
    let path = PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    path.is_file().then_some(path)
}
