// Command dispatch helpers + spec-lint/test/doc-check subcommands.
// Split out of main.rs to keep both files under the 1000-line cap
// (`docs/08§7`). All items here are crate-private; main.rs reaches
// them via `use crate::cmds::*`.

use std::ffi::OsStr;
use std::process::Command;

pub(crate) fn stub(name: &str, awaiting_spec: &str) -> Result<(), u8> {
    eprintln!("xtask {name}: not yet implemented (awaiting `{awaiting_spec}` freeze + crate scaffold)");
    Err(64)
}

// ---------------------------------------------------------------------------
// spec-lint
// ---------------------------------------------------------------------------

pub(crate) fn cmd_spec_lint(rest: &[String]) -> Result<(), u8> {
    // Pass-through to the spec-lint binary.
    let mut c = Command::new("cargo");
    c.args(["run", "--quiet", "-p", "spec-lint", "--", "all"]);
    for a in rest { c.arg(a); }
    run(c)
}

// ---------------------------------------------------------------------------
// kernel
// ---------------------------------------------------------------------------

/// True if `out` is missing or older than any of `srcs`.
fn is_stale(out: &str, srcs: &[&str]) -> bool {
    let ot = match std::fs::metadata(out).and_then(|m| m.modified()) {
        Ok(t) => t,
        Err(_) => return true,
    };
    srcs.iter().any(|s| {
        std::fs::metadata(s)
            .and_then(|m| m.modified())
            .map(|st| st > ot)
            .unwrap_or(false)
    })
}

/// Build phase: ensure the `include_bytes!`-consumed blobs exist + are fresh
/// before the kernel compiles. These are gitignored build artifacts: the
/// vDSO is assembled from `vdso/*.S` (vdso/build.sh); the rootfs is generated
/// by `xtask rootfs`. (The hand-rolled smoke ELFs have no source and stay
/// tracked.) docs/53.
pub(crate) fn ensure_blobs(arch: &str, rest: &[String]) -> Result<(), u8> {
    let vso = format!("kernel/blobs/vdso-{arch}.so");
    let vsrc = format!("vdso/vdso-{arch}.S");
    if is_stale(&vso, &[&vsrc, "vdso/vdso.lds", "vdso/build.sh"]) {
        eprintln!("xtask: vdso ({arch}) missing/stale -> vdso/build.sh");
        let mut c = Command::new("sh");
        c.arg("vdso/build.sh");
        run(c)?;
    }
    let img = format!("kernel/blobs/rootfs-{arch}.img");
    if !std::path::Path::new(&img).exists() {
        eprintln!("xtask: rootfs ({arch}) missing -> xtask rootfs");
        crate::cmd_rootfs(rest)?;
    }
    Ok(())
}

pub(crate) fn cmd_kernel(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").ok_or_else(|| {
        eprintln!("xtask kernel: --arch <x86_64|aarch64> required");
        2u8
    })?;
    ensure_blobs(&arch, rest)?;
    let profile = parse_arg(rest, "--profile").unwrap_or("release".into());
    let features = parse_arg(rest, "--features");
    let target = match arch.as_str() {
        "x86_64"  => "./targets/x86_64-unknown-oxide-kernel.json",
        "aarch64" => "./targets/aarch64-unknown-oxide-kernel.json",
        other => { eprintln!("xtask kernel: unsupported arch `{other}`"); return Err(2); }
    };
    let (boot_pkg, bin_pkg) = match arch.as_str() {
        "x86_64"  => ("boot-x86_64",  "kernel-bin-x86_64"),
        "aarch64" => ("boot-aarch64", "kernel-bin-aarch64"),
        _ => unreachable!(),
    };
    let mut c = Command::new("cargo");
    c.args([
        "build",
        "-Z", "build-std=core,compiler_builtins,alloc",
        "-Z", "build-std-features=compiler-builtins-mem",
        "-Z", "unstable-options",
        "-Z", "json-target-spec",
        "--target", target,
        "--profile", &profile,
        "-p", "kmain",
        "-p", boot_pkg,
        "-p", bin_pkg,
    ]);
    if let Some(f) = features.as_ref() {
        c.args(["--features", f.as_str()]);
    }
    run(c)
}


// ---------------------------------------------------------------------------
// test
// ---------------------------------------------------------------------------

pub(crate) fn cmd_test(rest: &[String]) -> Result<(), u8> {
    let mode = rest.iter().map(|s| s.as_str()).find(|s| s.starts_with("--")).unwrap_or("--hosted");
    match mode {
        "--hosted" => {
            let mut c = Command::new("cargo");
            c.args(["test", "--workspace"]);
            run(c)
        }
        "--kernel" | "--loom" | "--miri" | "--proptest" => {
            eprintln!("xtask test {mode}: not yet implemented (awaiting `42` freeze + first kernel crate)");
            Err(64)
        }
        other => { eprintln!("xtask test: unknown mode `{other}`"); Err(2) }
    }
}

// ---------------------------------------------------------------------------
// doc-check
// ---------------------------------------------------------------------------

pub(crate) fn cmd_doc_check(_rest: &[String]) -> Result<(), u8> {
    // Equivalent to `spec-lint manifest + xref` per 02§6 + 02§5.
    let mut c = Command::new("cargo");
    c.args(["run", "--quiet", "-p", "spec-lint", "--", "manifest"]);
    run(c.clone_for_xref())?;
    let mut c = Command::new("cargo");
    c.args(["run", "--quiet", "-p", "spec-lint", "--", "xref"]);
    run(c)
}

// Quick shim because Command isn't Clone. We just rebuild it.
trait CommandExt { fn clone_for_xref(&mut self) -> Command; }
impl CommandExt for Command {
    fn clone_for_xref(&mut self) -> Command {
        let mut c = Command::new(self.get_program());
        for a in self.get_args() { c.arg(a); }
        c
    }
}

// ---------------------------------------------------------------------------
// shared
// ---------------------------------------------------------------------------

pub(crate) fn run(mut c: Command) -> Result<(), u8> {
    let status = c.status().map_err(|e| { eprintln!("xtask: spawn failed: {e}"); 1u8 })?;
    if status.success() { Ok(()) }
    else { Err(status.code().unwrap_or(1) as u8) }
}

pub(crate) fn parse_arg(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter().enumerate();
    while let Some((_, a)) = iter.next() {
        if a == flag {
            if let Some((_, v)) = iter.next() { return Some(v.clone()); }
        }
        if let Some(rest) = a.strip_prefix(&format!("{flag}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

#[allow(dead_code)]
fn _osstr_keepalive(_: &OsStr) {}
