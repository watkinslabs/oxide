// Command dispatch helpers + spec-lint/test/doc-check subcommands.
// Split out of main.rs to keep both files under the 1000-line cap
// (`docs/08§7`). All items here are crate-private; main.rs reaches
// them via `use crate::cmds::*`.

use std::ffi::OsStr;
use std::process::Command;

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

/// Build phase: regenerate and validate the `include_bytes!`-consumed vDSO
/// before the kernel compiles. These are gitignored build artifacts: the
/// vDSO is assembled from `vdso/*.S` (vdso/build.sh); the rootfs is generated
/// by `xtask rootfs`. (The hand-rolled smoke ELFs have no source and stay
/// tracked.) docs/53.
pub(crate) fn ensure_blobs(arch: &str, rest: &[String], skip_rootfs: bool) -> Result<(), u8> {
    eprintln!("xtask: build and validate vDSO ({arch})");
    let mut c = Command::new("sh");
    c.arg("crates/kernel/syscalls/vdso/build.sh").arg(arch);
    run(c)?;
    // Compile-only CI still builds and validates the real vDSO, then skips the
    // local rootfs artifact required only by the boot gate.
    if skip_rootfs || std::env::var_os("OXIDE_STUB_BLOBS").is_some() { return Ok(()); }
    let id = parse_arg(rest, "--id");
    let repo = crate::image_qemu::repo_root();
    let img = crate::buildns::blobs_dir(&repo, id.as_deref()).join(format!("root-{arch}.img"));
    if !img.exists() {
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
    let id = parse_arg(rest, "--id");
    if let Some(ref id) = id { crate::buildns::validate(id)?; }
    // `--check`: type-check only (`cargo check`), no codegen, no link, no ELF
    // snapshot, no rootfs. Purpose is the feature-gated COMPILE gate — code
    // inside `#[cfg(feature = …)]` blocks is invisible to a default build, so
    // the routine gate needs a cheap way to compile it on both arches.
    let check_only = rest.iter().any(|a| a == "--check");
    ensure_blobs(&arch, rest, check_only)?;
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
    // `--clean-kernel`: `cargo clean -p <pkg>` the kernel packages in the SHARED
    // target/ so they recompile from scratch (rules out stale compiled
    // artifacts). Default absent reuses valid Cargo artifacts without cleaning.
    let clean_kernel = rest.iter().any(|a| a == "--clean-kernel");
    if clean_kernel {
        let mut k = Command::new("cargo");
        k.args([
            "clean",
            "-Z", "unstable-options",
            "-Z", "json-target-spec",
            "--target", target,
            "--profile", &profile,
            "-p", "kmain",
            "-p", boot_pkg,
            "-p", bin_pkg,
        ]);
        run(k)?;
    }
    // Always build in the DEFAULT target/ (no CARGO_TARGET_DIR override) so
    // Cargo reuses compiled artifacts across ids — only crates that changed
    // recompile. Build lock serializes builds, so sharing target/ is safe. An
    // id'd build then snapshots its ELF below. Profile codegen is non-incremental.
    let mut c = Command::new("cargo");
    c.args([
        if check_only { "check" } else { "build" },
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
    run(c)?;
    if check_only { return Ok(()); }
    // Snapshot: copy the freshly built ELF from the shared cargo build location
    // into the build's namespace (`target/builds/<id-or-"default">/...`) so a
    // running instance boots a stable ISO decoupled from later builds that reuse
    // the shared target/. C90: EVERY build snapshots, incl. the no-id `default`.
    {
        let prof_dir = if profile == "dev" { "debug" } else { profile.as_str() };
        let repo = crate::image_qemu::repo_root();
        let src = crate::buildns::kernel_elf_build(&repo, &arch, prof_dir);
        let dst = crate::buildns::kernel_elf(&repo, id.as_deref(), &arch, prof_dir);
        if let Some(p) = dst.parent() {
            std::fs::create_dir_all(p).map_err(|e| { eprintln!("xtask: snapshot mkdir failed: {e}"); 1u8 })?;
        }
        std::fs::copy(&src, &dst).map_err(|e| {
            eprintln!("xtask: snapshot copy {} -> {} failed: {e}", src.display(), dst.display());
            1u8
        })?;
    }
    Ok(())
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
        "--loom" => cmd_test_loom(rest),
        "--kernel" | "--miri" | "--proptest" => {
            eprintln!("xtask test {mode}: not yet implemented (awaiting `42` freeze + first kernel crate)");
            Err(64)
        }
        other => { eprintln!("xtask test: unknown mode `{other}`"); Err(2) }
    }
}

fn cmd_test_loom(rest: &[String]) -> Result<(), u8> {
    let mut c = Command::new("cargo");
    c.args(["test", "-p", "network-namespace", "-p", "net"]);
    for a in rest { if a != "--loom" { c.arg(a); } }

    let flags = std::env::var("RUSTFLAGS").unwrap_or_default();
    let flags = if flags.is_empty() { "--cfg loom".into() }
                else { format!("{flags} --cfg loom") };
    c.env("RUSTFLAGS", flags);
    if std::env::var_os("LOOM_MAX_PREEMPTIONS").is_none() {
        c.env("LOOM_MAX_PREEMPTIONS", "6");
    }
    run(c)
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
