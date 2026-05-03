// xtask: sole CI entry point per docs/07§8.
//
// Subcommand surface (07§8):
//   xtask kernel    --arch <x86_64|aarch64> --profile <release|dev|debug-build>
//   xtask user      --arch <a>
//   xtask image     --arch <a>
//   xtask test      [--hosted|--kernel|--loom|--miri|--proptest]
//   xtask qemu      --arch <a> [--gdb] [--smp N] [--mem MB]
//   xtask soak      --arch <a> --duration H
//   xtask bench     --arch <a>
//   xtask spec-lint
//   xtask doc-check
//
// Implementation status (P0-03 skeleton):
//   spec-lint  : implemented (delegates to tools/spec-lint binary)
//   kernel     : implemented for build (-Z build-std + target JSON);
//                kernel crate doesn't exist yet -> errors at cargo level
//   test       : --hosted implemented (delegates to `cargo test`)
//   user, image, qemu, soak, bench, doc-check : stubs that print
//                "not yet implemented; awaiting <spec>"

use std::ffi::OsStr;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() { return usage(); }

    let cmd = args[0].as_str();
    let rest = &args[1..];

    let res = match cmd {
        "spec-lint" => cmd_spec_lint(rest),
        "kernel"    => cmd_kernel(rest),
        "test"      => cmd_test(rest),
        "user"      => stub("user", "29a"),
        "image"     => stub("image", "39"),
        "qemu"      => cmd_qemu(rest),
        "soak"      => stub("soak", "40"),
        "bench"     => stub("bench", "04"),
        "doc-check" => cmd_doc_check(rest),
        "-h" | "--help" => return usage(),
        _ => { eprintln!("xtask: unknown subcommand `{cmd}`"); return usage(); }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: xtask <kernel|user|image|test|qemu|soak|bench|spec-lint|doc-check> [args]");
    ExitCode::from(2)
}

fn stub(name: &str, awaiting_spec: &str) -> Result<(), u8> {
    eprintln!("xtask {name}: not yet implemented (awaiting `{awaiting_spec}` freeze + crate scaffold)");
    Err(64)
}

// ---------------------------------------------------------------------------
// spec-lint
// ---------------------------------------------------------------------------

fn cmd_spec_lint(rest: &[String]) -> Result<(), u8> {
    // Pass-through to the spec-lint binary.
    let mut c = Command::new("cargo");
    c.args(["run", "--quiet", "-p", "spec-lint", "--", "all"]);
    for a in rest { c.arg(a); }
    run(c)
}

// ---------------------------------------------------------------------------
// kernel
// ---------------------------------------------------------------------------

fn cmd_kernel(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").ok_or_else(|| {
        eprintln!("xtask kernel: --arch <x86_64|aarch64> required");
        2u8
    })?;
    let profile = parse_arg(rest, "--profile").unwrap_or("release".into());
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
        "-p", "kernel",
        "-p", boot_pkg,
        "-p", bin_pkg,
    ]);
    run(c)
}

// ---------------------------------------------------------------------------
// qemu — Limine UEFI boot under qemu-system-{x86_64,aarch64}
// ---------------------------------------------------------------------------

fn cmd_qemu(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").ok_or_else(|| {
        eprintln!("xtask qemu: --arch <x86_64|aarch64> required");
        2u8
    })?;
    let profile = parse_arg(rest, "--profile").unwrap_or("release".into());

    // 1. Build the kernel ELF + boot crate via the existing kernel command.
    cmd_kernel(rest)?;

    let repo = repo_root();
    let vendor = repo.join("vendor");
    if !vendor.join("limine/BOOTX64.EFI").exists() || !vendor.join("firmware/ovmf-x64.fd").exists() {
        eprintln!("xtask qemu: vendor/ not populated. Run `tools/fetch-vendor.sh` first.");
        return Err(2);
    }

    // dev-profile builds land under `target/<target>/debug/`; release/custom
    // profile names match the directory.
    let prof_dir = if profile == "dev" { "debug".to_string() } else { profile.clone() };
    let kernel_elf = repo.join(format!(
        "target/{arch}-unknown-oxide-kernel/{prof_dir}/oxide-{arch}",
    ));
    if !kernel_elf.exists() {
        eprintln!("xtask qemu: kernel ELF not at {}", kernel_elf.display());
        return Err(2);
    }

    match arch.as_str() {
        "x86_64"  => qemu_run_x86_64(&repo, &kernel_elf),
        "aarch64" => qemu_run_aarch64(&repo, &kernel_elf),
        other => { eprintln!("xtask qemu: unsupported arch `{other}`"); Err(2) }
    }
}

fn repo_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR is `<repo>/tools/xtask`; pop two levels.
    let here = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(here)
        .ancestors().nth(2).map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap())
}

fn qemu_run_x86_64(repo: &std::path::Path, kernel_elf: &std::path::Path) -> Result<(), u8> {
    let img = build_esp_image(
        repo, "x86_64",
        &repo.join("vendor/limine/BOOTX64.EFI"),
        kernel_elf,
        "BOOTX64.EFI",
        "oxide-x86_64",
    )?;
    let ovmf = repo.join("vendor/firmware/ovmf-x64.fd");
    let mut c = Command::new("qemu-system-x86_64");
    c.args([
        "-machine", "q35",
        "-cpu", "qemu64",
        "-m", "256M",
        "-bios", ovmf.to_str().unwrap(),
        "-drive", &format!("format=raw,file={}", img.display()),
        "-serial", "stdio",
        "-display", "none",
        "-no-reboot",
        "-no-shutdown",
    ]);
    eprintln!("xtask qemu: launching qemu-system-x86_64 (Ctrl-A x to quit)");
    run(c)
}

fn qemu_run_aarch64(repo: &std::path::Path, kernel_elf: &std::path::Path) -> Result<(), u8> {
    if which("qemu-system-aarch64").is_none() {
        eprintln!("xtask qemu: qemu-system-aarch64 not on PATH; install your distro's qemu-system-aarch64 package.");
        return Err(2);
    }
    let img = build_esp_image(
        repo, "aarch64",
        &repo.join("vendor/limine/BOOTAA64.EFI"),
        kernel_elf,
        "BOOTAA64.EFI",
        "oxide-aarch64",
    )?;
    let ovmf = repo.join("vendor/firmware/ovmf-aarch64.fd");
    let mut c = Command::new("qemu-system-aarch64");
    c.args([
        "-machine", "virt",
        "-cpu", "cortex-a72",
        "-m", "256M",
        "-bios", ovmf.to_str().unwrap(),
        "-drive", &format!("format=raw,file={}", img.display()),
        "-serial", "stdio",
        "-display", "none",
        "-no-reboot",
    ]);
    eprintln!("xtask qemu: launching qemu-system-aarch64 (Ctrl-A x to quit)");
    run(c)
}

/// Assemble a 64 MiB FAT32 EFI System Partition image holding the
/// Limine UEFI bootloader at `EFI/BOOT/<bootname>`, our kernel ELF
/// at `boot/limine/<kernel-name>`, and a minimal `limine.conf`.
/// QEMU's built-in `fat:rw:dir` pseudo-disk is FAT16 and OVMF is
/// finicky about it; mkfs.fat + mcopy gives us a real ESP layout.
fn build_esp_image(
    repo: &std::path::Path,
    arch: &str,
    boot_efi: &std::path::Path,
    kernel_elf: &std::path::Path,
    boot_name: &str,
    kernel_name: &str,
) -> Result<std::path::PathBuf, u8> {
    use std::fs;
    let img = repo.join(format!("target/qemu-esp-{arch}.img"));
    let _ = fs::remove_file(&img);

    // 64 MiB FAT32 image — well above mkfs.fat's 32 MiB FAT32 floor.
    {
        let mut c = Command::new("dd");
        c.args(["if=/dev/zero", "bs=1M", "count=64",
                &format!("of={}", img.display())]);
        run(c)?;
    }
    {
        let mut c = Command::new("mkfs.fat");
        c.args(["-F32", "-n", "OXIDE", img.to_str().unwrap()]);
        run(c)?;
    }

    // Tiny limine.conf written to a temp file; mtools will copy it in.
    let cfg_path = repo.join(format!("target/qemu-esp-{arch}.limine.conf"));
    let cfg = format!(
        "timeout: 0
serial: yes
default_entry: 1

/oxide
    protocol: limine
    path: boot():/boot/limine/{kernel_name}
",
    );
    fs::write(&cfg_path, cfg).map_err(|_| 1u8)?;

    // mmd / mcopy: build the layout inside the FAT image.
    let img_s = img.to_str().unwrap();
    for dir in ["::/EFI", "::/EFI/BOOT", "::/boot", "::/boot/limine"] {
        let mut c = Command::new("mmd");
        c.args(["-i", img_s, dir]);
        // mmd -D s skip-if-exists isn't portable; allow failure on existing dirs.
        let _ = c.status();
    }
    let mut c = Command::new("mcopy");
    c.args(["-i", img_s,
            boot_efi.to_str().unwrap(),
            &format!("::/EFI/BOOT/{boot_name}")]);
    run(c)?;
    let mut c = Command::new("mcopy");
    c.args(["-i", img_s,
            kernel_elf.to_str().unwrap(),
            &format!("::/boot/limine/{kernel_name}")]);
    run(c)?;
    let mut c = Command::new("mcopy");
    c.args(["-i", img_s,
            cfg_path.to_str().unwrap(),
            "::/boot/limine/limine.conf"]);
    run(c)?;

    Ok(img)
}

fn which(prog: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for p in std::env::split_paths(&path) {
        let cand = p.join(prog);
        if cand.is_file() { return Some(cand); }
    }
    None
}

// ---------------------------------------------------------------------------
// test
// ---------------------------------------------------------------------------

fn cmd_test(rest: &[String]) -> Result<(), u8> {
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

fn cmd_doc_check(_rest: &[String]) -> Result<(), u8> {
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

fn run(mut c: Command) -> Result<(), u8> {
    let status = c.status().map_err(|e| { eprintln!("xtask: spawn failed: {e}"); 1u8 })?;
    if status.success() { Ok(()) }
    else { Err(status.code().unwrap_or(1) as u8) }
}

fn parse_arg(args: &[String], flag: &str) -> Option<String> {
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
