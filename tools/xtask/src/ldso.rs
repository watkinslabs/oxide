// xtask ldso — build the oxide dynamic linker (docs/59§5) and run the
// dynamic-link smoke: a no-libc PIE that uses our ld-linux as PT_INTERP,
// exercising self-relocation + the app's R_*_RELATIVE relocs + handoff on
// the HOST kernel.
//
// Usage:
//   xtask ldso          build ld-linux-x86-64.so.2 (+ aarch64 if installed)
//   xtask ldso --check  build + run the no-libc PIE through our ld:
//                       expect exit 42 and "ld-ok" on stdout.
//
// Lockstep (CLAUDE.md): aarch64 ld-linux-aarch64.so.1 builds here when the
// target is installed; the aarch64 *run* is the QEMU milestone.
use crate::cmds::run;
use std::path::PathBuf;
use std::process::Command;

const X86: &str = "x86_64-unknown-linux-gnu";
const ARM: &str = "aarch64-unknown-linux-gnu";

pub(crate) fn cmd_ldso(rest: &[String]) -> Result<(), u8> {
    let check = rest.iter().any(|a| a == "--check");
    build_ldso(X86, "ld-linux-x86-64.so.2")?;
    if target_installed(ARM) { build_ldso(ARM, "ld-linux-aarch64.so.1")?; }
    else { eprintln!("xtask ldso: aarch64 target not installed; skipping (rustup target add {ARM})"); }
    if check { check_raw_pie_x86()?; }
    Ok(())
}

// Build the ldso crate as a self-contained ld-linux .so. Linked with
// rust-lld directly (multi-arch, no cross-gcc needed) so the same path
// builds x86_64 and aarch64: our own _start as entry, PIC, no undefined
// symbols (the rtld is self-contained), soname per arch.
fn build_ldso(triple: &str, soname: &str) -> Result<(), u8> {
    eprintln!("xtask ldso: building {soname} for {triple}");
    let mut c = Command::new("cargo");
    c.args(["rustc", "-p", "ldso", "--release", "--features", "freestanding",
            "--target", triple, "--crate-type", "cdylib", "--",
            "-C", "linker-flavor=ld.lld", "-C", "linker=rust-lld",
            "-C", &format!("link-arg=--soname={soname}"),
            "-C", "link-arg=--entry=_start", "-C", "link-arg=--no-undefined",
            // -Bsymbolic pre-binds the rtld's own symbol refs (e.g. the global
            // allocator) to RELATIVE relocs, which self-reloc applies; without
            // it those stay GLOB_DAT/JUMP_SLOT and call through an unrelocated
            // GOT before the rtld can resolve them.
            "-C", "link-arg=-Bsymbolic",
            "-C", "relocation-model=pic", "-C", "panic=abort"]);
    run(c)
}

fn ldso_path(triple: &str) -> PathBuf {
    PathBuf::from("target").join(triple).join("release").join("libldso.so")
}

fn target_installed(triple: &str) -> bool {
    std::path::Path::new(&format!("{}/lib/rustlib/{triple}", sysroot())).exists()
}

fn sysroot() -> String {
    Command::new("rustc").args(["--print", "sysroot"]).output()
        .ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}

// Compile the no-libc PIE with our ld as PT_INTERP and run it on the host.
fn check_raw_pie_x86() -> Result<(), u8> {
    let so = ldso_path(X86);
    if !so.exists() { eprintln!("xtask ldso: {} missing", so.display()); return Err(1); }
    let abs = std::fs::canonicalize(&so).map_err(|_| 1u8)?;
    let dir = abs.parent().unwrap().to_path_buf();
    let bin = "target/ldso-raw-pie";

    let mut cc = Command::new("cc");
    cc.args(["-fPIE", "-pie", "-nostdlib", "-nostartfiles", "-Wl,-e,_start",
             &format!("-Wl,--dynamic-linker={}", abs.display()),
             &format!("-Wl,-rpath,{}", dir.display()),
             "userspace/ldso_smoke/raw_pie.c", "-o", bin]);
    run(cc)?;

    eprintln!("xtask ldso: running {bin} through {}", abs.display());
    let out = Command::new(format!("./{bin}")).output()
        .map_err(|e| { eprintln!("xtask ldso: run failed: {e}"); 1u8 })?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let code = out.status.code().unwrap_or(-1);
    eprintln!("xtask ldso: exit={code} stdout={stdout:?}");
    if code == 42 && stdout.contains("ld-ok") {
        eprintln!("xtask ldso: G12d rtld dynamic-run smoke PASS (self-reloc + app RELATIVE + handoff)");
    } else {
        eprintln!("xtask ldso: G12d rtld dynamic-run smoke FAIL");
        return Err(1);
    }
    check_libc_linked_x86(&abs)
}

// Link a tiny PIE against our libc.so.6 and run it through our ld: proves
// DT_NEEDED loading + JUMP_SLOT/GLOB_DAT resolution against a real shared lib.
fn check_libc_linked_x86(ld_abs: &std::path::Path) -> Result<(), u8> {
    let so = crate::glibc::sharedlib_path(X86);
    crate::glibc::build_sharedlib(X86)?;
    if !so.exists() { eprintln!("xtask ldso: {} missing", so.display()); return Err(1); }
    let dir = PathBuf::from("target/ldso-dynroot");
    let _ = std::fs::create_dir_all(&dir);
    let libc = dir.join("libc.so.6");
    std::fs::copy(&so, &libc).map_err(|_| 1u8)?;
    let dirabs = std::fs::canonicalize(&dir).map_err(|_| 1u8)?;
    let bin = "target/ldso-dyn-libc";

    let mut cc = Command::new("cc");
    cc.args(["-fPIE", "-pie", "-nostdlib", "-nostartfiles", "-Wl,-e,_start",
             &format!("-Wl,--dynamic-linker={}", ld_abs.display()),
             &format!("-Wl,-rpath,{}", dirabs.display()),
             &format!("-L{}", dirabs.display()), "-l:libc.so.6",
             "userspace/ldso_smoke/dyn_libc.c", "-o", bin]);
    run(cc)?;

    eprintln!("xtask ldso: running {bin} (libc.so.6-linked) through our ld");
    let out = Command::new(format!("./{bin}"))
        .env("LD_LIBRARY_PATH", &dirabs)
        .output()
        .map_err(|e| { eprintln!("xtask ldso: run failed: {e}"); 1u8 })?;
    let code = out.status.code().unwrap_or(-1);
    eprintln!("xtask ldso: libc-linked exit={code} (want 13 = strlen(\"hello-dynamic\"))");
    if code == 13 {
        eprintln!("xtask ldso: G12g rtld DT_NEEDED libc.so.6 link+run PASS");
    } else {
        eprintln!("xtask ldso: G12g rtld DT_NEEDED link+run FAIL");
        return Err(1);
    }
    check_tls_pie_x86(ld_abs)
}

// Run a PIE with its own __thread variable through our ld: proves the static
// TLS block + thread-pointer setup positions thread-locals correctly.
fn check_tls_pie_x86(ld_abs: &std::path::Path) -> Result<(), u8> {
    let dir = ld_abs.parent().unwrap();
    let bin = "target/ldso-tls-pie";
    let mut cc = Command::new("cc");
    cc.args(["-fPIE", "-pie", "-nostdlib", "-nostartfiles", "-Wl,-e,_start",
             &format!("-Wl,--dynamic-linker={}", ld_abs.display()),
             &format!("-Wl,-rpath,{}", dir.display()),
             "userspace/ldso_smoke/tls_pie.c", "-o", bin]);
    run(cc)?;
    eprintln!("xtask ldso: running {bin} (__thread) through our ld");
    let out = Command::new(format!("./{bin}")).output()
        .map_err(|e| { eprintln!("xtask ldso: run failed: {e}"); 1u8 })?;
    let code = out.status.code().unwrap_or(-1);
    eprintln!("xtask ldso: tls exit={code} (want 7 = __thread tvar)");
    if code == 7 {
        eprintln!("xtask ldso: G12g rtld static-TLS run PASS");
        Ok(())
    } else {
        eprintln!("xtask ldso: G12g rtld static-TLS run FAIL");
        Err(1)
    }
}
