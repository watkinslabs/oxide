// xtask glibc — build oxide-libc (docs/59) artifacts + the G2 entry-path
// smoke. Builds libc.a (and later libc.so.6) via `cargo rustc
// --features freestanding`, selecting the per-arch version script.
//
// Usage:
//   xtask glibc            build libc.a for the host-runnable arch(es)
//   xtask glibc --check    build + link userspace/glibc_hello against
//                          libc.a and run it (x86_64 host): expect exit 0
//                          and the greeting on stdout.
//
// Lockstep (CLAUDE.md): aarch64 staticlib compiles here when the
// aarch64-unknown-linux-gnu target is installed; the aarch64 *run* is the
// QEMU boot milestone (docs/59§6 G2).
use crate::cmds::run;
use std::path::PathBuf;
use std::process::Command;

const X86: &str = "x86_64-unknown-linux-gnu";
const ARM: &str = "aarch64-unknown-linux-gnu";

pub(crate) fn cmd_glibc(rest: &[String]) -> Result<(), u8> {
    let check = rest.iter().any(|a| a == "--check");
    build_staticlib(X86)?;
    if target_installed(ARM) { build_staticlib(ARM)?; }
    else { eprintln!("xtask glibc: aarch64 target not installed; skipping its staticlib (add with `rustup target add {ARM}`)"); }
    if check { check_hello_x86()?; }
    Ok(())
}

fn build_staticlib(triple: &str) -> Result<(), u8> {
    eprintln!("xtask glibc: building libc.a for {triple}");
    let mut c = Command::new("cargo");
    c.args(["rustc", "-p", "glibc", "--release", "--features", "freestanding",
            "--target", triple, "--crate-type", "staticlib"]);
    run(c)
}

fn staticlib_path(triple: &str) -> PathBuf {
    PathBuf::from("target").join(triple).join("release").join("libglibc.a")
}

fn target_installed(triple: &str) -> bool {
    Command::new("rustc").args(["--print", "target-list"]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l == triple))
        .unwrap_or(false)
        && std::path::Path::new(&format!("{}/lib/rustlib/{triple}", sysroot())).exists()
}

fn sysroot() -> String {
    Command::new("rustc").args(["--print", "sysroot"]).output()
        .ok().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}

// Compile + static-link userspace/glibc_hello against libc.a and run it.
fn check_hello_x86() -> Result<(), u8> {
    let lib = staticlib_path(X86);
    if !lib.exists() { eprintln!("xtask glibc: {} missing", lib.display()); return Err(1); }
    let obj = "target/glibc-hello.o";
    let bin = "target/glibc-hello";

    let mut cc = Command::new("cc");
    cc.args(["-c", "-O2", "-fno-stack-protector", "-fno-pie", "-ffreestanding",
             "userspace/glibc_hello/hello.c", "-o", obj]);
    run(cc)?;

    let mut ld = Command::new("cc");
    ld.args(["-static", "-no-pie", "-nostdlib", obj]);
    ld.arg(&lib);
    ld.args(["-o", bin]);
    run(ld)?;

    eprintln!("xtask glibc: running {bin}");
    let out = Command::new(format!("./{bin}")).output()
        .map_err(|e| { eprintln!("xtask glibc: run failed: {e}"); 1u8 })?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let code = out.status.code().unwrap_or(-1);
    eprintln!("xtask glibc: exit={code} stdout={stdout:?}");
    if code == 0 && stdout.contains("hello from oxide-libc") {
        eprintln!("xtask glibc: G2 entry-path smoke PASS");
        Ok(())
    } else {
        eprintln!("xtask glibc: G2 entry-path smoke FAIL");
        Err(1)
    }
}
