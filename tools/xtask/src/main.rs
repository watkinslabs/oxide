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
        "image"     => cmd_image(rest),
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

/// Build the bootable artifact for `--arch`.
///
/// Default = GPT disk image with a real FAT32 ESP partition holding
/// the Limine UEFI loader + kernel — matches what `39§*` calls for
/// and what we'll eventually ship to users. `--format=iso` produces
/// a hybrid BIOS+UEFI ISO instead (BIOS El Torito + UEFI El Torito);
/// useful for "burn to CD" workflows but Limine ≥ 9 has a known
/// UEFI volume-detection bug on hybrid CDs.
fn cmd_image(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").ok_or_else(|| {
        eprintln!("xtask image: --arch <x86_64|aarch64> required");
        2u8
    })?;
    let format = parse_arg(rest, "--format").unwrap_or_else(|| "disk".into());
    cmd_kernel(rest)?;
    let repo = repo_root();
    let kernel_elf = kernel_elf_path(&repo, &arch, rest)?;
    check_vendor(&repo)?;
    match format.as_str() {
        "disk" => build_disk_image(&repo, &arch, &kernel_elf).map(|_| ()),
        "iso"  => build_iso(&repo, &arch, &kernel_elf).map(|_| ()),
        other  => { eprintln!("xtask image: --format must be disk|iso (got `{other}`)"); Err(2) }
    }
}

fn cmd_qemu(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").ok_or_else(|| {
        eprintln!("xtask qemu: --arch <x86_64|aarch64> required");
        2u8
    })?;
    let format = parse_arg(rest, "--format").unwrap_or_else(|| "disk".into());
    cmd_kernel(rest)?;
    let repo = repo_root();
    let kernel_elf = kernel_elf_path(&repo, &arch, rest)?;
    check_vendor(&repo)?;
    match (arch.as_str(), format.as_str()) {
        ("x86_64",  "disk") => qemu_run_x86_64_disk(&repo, &build_disk_image(&repo, &arch, &kernel_elf)?),
        ("aarch64", "disk") => qemu_run_aarch64_disk(&repo, &build_disk_image(&repo, &arch, &kernel_elf)?),
        ("x86_64",  "iso")  => qemu_run_x86_64(&repo,    &build_iso(&repo, &arch, &kernel_elf)?),
        ("aarch64", "iso")  => qemu_run_aarch64(&repo,   &build_iso(&repo, &arch, &kernel_elf)?),
        (a, f) => { eprintln!("xtask qemu: unsupported (arch={a}, format={f})"); Err(2) }
    }
}

fn check_vendor(repo: &std::path::Path) -> Result<(), u8> {
    let vendor = repo.join("vendor");
    let ok = vendor.join("limine/BOOTX64.EFI").exists()
        && vendor.join("limine/limine-bios-cd.bin").exists()
        && vendor.join("limine/limine-uefi-cd.bin").exists()
        && vendor.join("limine/limine").exists()
        && vendor.join("firmware/ovmf-x64.fd").exists();
    if !ok {
        eprintln!("xtask: vendor/ not populated. Run `tools/fetch-vendor.sh` first.");
        return Err(2);
    }
    Ok(())
}

fn kernel_elf_path(repo: &std::path::Path, arch: &str, rest: &[String]) -> Result<std::path::PathBuf, u8> {
    let profile = parse_arg(rest, "--profile").unwrap_or("release".into());
    let prof_dir = if profile == "dev" { "debug".to_string() } else { profile };
    let p = repo.join(format!("target/{arch}-unknown-oxide-kernel/{prof_dir}/oxide-{arch}"));
    if !p.exists() {
        eprintln!("xtask: kernel ELF not at {}", p.display());
        return Err(2);
    }
    Ok(p)
}

fn repo_root() -> std::path::PathBuf {
    let here = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(here)
        .ancestors().nth(2).map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap())
}

/// Assemble a GPT-partitioned disk image with a single FAT32 ESP
/// holding the Limine UEFI loader + our kernel + limine.conf. The
/// shipping format per `39§*`. Boots cleanly under OVMF on both
/// arches because the firmware sees a real ESP via GPT type GUID
/// (no nested El Torito boot image, no Limine volume-detection bug).
///
/// Layout:
///   GPT header
///   Partition 1: ESP (FAT32) at LBA 2048, ~62 MiB
///     /EFI/BOOT/<BOOTX64|BOOTAA64>.EFI ← Limine UEFI loader
///     /EFI/BOOT/limine.conf            ← Limine ≥ 9 looks here
///     /boot/limine/oxide-<arch>        ← kernel ELF
///     /boot/limine/limine.conf         ← BIOS auto-discovery path
///   GPT backup header
fn build_disk_image(
    repo: &std::path::Path,
    arch: &str,
    kernel_elf: &std::path::Path,
) -> Result<std::path::PathBuf, u8> {
    use std::fs;
    let limine = repo.join("vendor/limine");
    let img = repo.join(format!("target/oxide-{arch}.img"));
    let _ = fs::remove_file(&img);

    let (boot_efi_src, boot_efi_dst, kernel_name) = match arch {
        "x86_64"  => ("BOOTX64.EFI",  "BOOTX64.EFI",  "oxide-x86_64"),
        "aarch64" => ("BOOTAA64.EFI", "BOOTAA64.EFI", "oxide-aarch64"),
        other => { eprintln!("xtask image: unsupported arch `{other}`"); return Err(2); }
    };

    // 64 MiB image. Anything smaller and parted complains about
    // backup-GPT placement on aarch64.
    {
        let mut c = Command::new("dd");
        c.args(["if=/dev/zero", "bs=1M", "count=64",
                &format!("of={}", img.display()), "status=none"]);
        run(c)?;
    }

    // GPT label + single ESP partition occupying everything past
    // the GPT header.
    {
        let mut c = Command::new("parted");
        c.args(["-s", img.to_str().unwrap(),
                "mklabel", "gpt",
                "mkpart", "ESP", "fat32", "1MiB", "100%",
                "set", "1", "esp", "on"]);
        run(c)?;
    }

    // Partition 1 starts at 1 MiB = byte offset 1048576 by parted's
    // alignment policy. Compute precisely from the GPT for safety.
    let part_offset_bytes = part_start_bytes(&img)?;

    // Format the ESP in-place via mtools' `@@<offset>` syntax. mtools
    // honors the offset for every operation against this image.
    let img_at = format!("{}@@{part_offset_bytes}", img.display());
    {
        let mut c = Command::new("mformat");
        c.args(["-i", &img_at, "-F", "-v", "OXIDE-ESP", "::"]);
        run(c)?;
    }

    // Build the directory tree.
    for d in ["::/EFI", "::/EFI/BOOT", "::/boot", "::/boot/limine"] {
        let mut c = Command::new("mmd");
        c.args(["-i", &img_at, d]);
        let _ = c.status();
    }

    let cfg = format!(
        "timeout: 0\nserial: yes\ndefault_entry: 1\n\n/oxide\n    protocol: limine\n    path: boot():/boot/limine/{kernel_name}\n",
    );
    let cfg_path = repo.join(format!("target/oxide-{arch}.limine.conf"));
    fs::write(&cfg_path, &cfg).map_err(|_| 1u8)?;

    let mcopy = |from: &str, to: &str| -> Result<(), u8> {
        let mut c = Command::new("mcopy");
        c.args(["-i", &img_at, from, to]);
        run(c)
    };
    mcopy(limine.join(boot_efi_src).to_str().unwrap(),
          &format!("::/EFI/BOOT/{boot_efi_dst}"))?;
    mcopy(cfg_path.to_str().unwrap(), "::/EFI/BOOT/limine.conf")?;
    mcopy(kernel_elf.to_str().unwrap(),
          &format!("::/boot/limine/{kernel_name}"))?;
    mcopy(cfg_path.to_str().unwrap(), "::/boot/limine/limine.conf")?;

    eprintln!("xtask image: produced {}", img.display());
    Ok(img)
}

/// Parse `parted unit B print` machine output to extract partition 1's
/// start byte. Output form: `1:1048576B:67075583B:66027008B:fat32::esp;`
fn part_start_bytes(img: &std::path::Path) -> Result<u64, u8> {
    use std::process::Stdio;
    let out = Command::new("parted")
        .args(["-m", "-s", img.to_str().unwrap(), "unit", "B", "print"])
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| { eprintln!("parted: {e}"); 1u8 })?;
    if !out.status.success() {
        eprintln!("parted: exit {}", out.status);
        return Err(1);
    }
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("1:") {
            // rest = "1048576B:67075583B:..." — first field is start.
            let start = rest.split(':').next().unwrap_or("");
            let n = start.trim_end_matches('B').parse::<u64>()
                .map_err(|_| { eprintln!("parted: bad start `{start}`"); 1u8 })?;
            return Ok(n);
        }
    }
    eprintln!("parted: no partition 1 in output:\n{s}");
    Err(1)
}

/// Assemble the canonical Limine hybrid BIOS+UEFI ISO per `36§7`.
///
/// Layout in the ISO root:
///   `/limine-bios.sys`              ← BIOS stage 2
///   `/limine-bios-cd.bin`           ← El Torito BIOS boot record
///   `/limine-uefi-cd.bin`           ← El Torito UEFI boot image
///   `/EFI/BOOT/<BOOTX64|BOOTAA64>.EFI` ← UEFI loader fallback path
///   `/boot/limine/limine.conf`      ← config
///   `/boot/limine/oxide-<arch>`     ← our kernel ELF
///
/// `mkisofs` (or genisoimage clone) builds the El Torito CD; the
/// `limine` host tool then writes the BIOS MBR via `bios-install`
/// (no-op for aarch64 since ARM has no BIOS path).
fn build_iso(
    repo: &std::path::Path,
    arch: &str,
    kernel_elf: &std::path::Path,
) -> Result<std::path::PathBuf, u8> {
    use std::fs;
    let limine = repo.join("vendor/limine");
    let stage = repo.join(format!("target/iso-stage-{arch}"));
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(stage.join("EFI/BOOT")).map_err(|_| 1u8)?;
    fs::create_dir_all(stage.join("boot/limine")).map_err(|_| 1u8)?;

    // Limine binaries at ISO root + EFI fallback path.
    fs::copy(limine.join("limine-bios.sys"),    stage.join("limine-bios.sys")).map_err(|_| 1u8)?;
    fs::copy(limine.join("limine-bios-cd.bin"), stage.join("limine-bios-cd.bin")).map_err(|_| 1u8)?;
    fs::copy(limine.join("limine-uefi-cd.bin"), stage.join("limine-uefi-cd.bin")).map_err(|_| 1u8)?;
    let (boot_efi_src, boot_efi_dst, kernel_name) = match arch {
        "x86_64"  => ("BOOTX64.EFI",  "BOOTX64.EFI",  "oxide-x86_64"),
        "aarch64" => ("BOOTAA64.EFI", "BOOTAA64.EFI", "oxide-aarch64"),
        other => { eprintln!("xtask image: unsupported arch `{other}`"); return Err(2); }
    };
    fs::copy(limine.join(boot_efi_src),  stage.join(format!("EFI/BOOT/{boot_efi_dst}"))).map_err(|_| 1u8)?;
    fs::copy(kernel_elf, stage.join(format!("boot/limine/{kernel_name}"))).map_err(|_| 1u8)?;

    // limine.conf next to the UEFI loader (Limine ≥ 9 looks here
    // first), and at /boot/limine/ for the BIOS path. Keeping both
    // copies in sync is fine because the kernel path is identical.
    // `boot():` is the device Limine itself loaded from. On the
    // BIOS El Torito path that's the ISO directly; on UEFI El
    // Torito it's the small embedded UEFI image (a Limine ≥ 9 quirk
    // that requires xorriso's `-isohybrid-gpt-basdat` to work
    // around). We boot via SeaBIOS for x86 to dodge the UEFI
    // quirk; aarch64 stays UEFI but doesn't have a BIOS path.
    let cfg = format!(
        "timeout: 0\nserial: yes\ndefault_entry: 1\n\n/oxide\n    protocol: limine\n    path: boot():/boot/limine/{kernel_name}\n",
    );
    fs::write(stage.join("EFI/BOOT/limine.conf"),    &cfg).map_err(|_| 1u8)?;
    fs::write(stage.join("boot/limine/limine.conf"), &cfg).map_err(|_| 1u8)?;

    // El Torito CD via xorriso (preferred) or mkisofs/genisoimage.
    // The `-isohybrid-gpt-basdat` flag is xorriso-only; under
    // genisoimage we just drop it (the resulting ISO still boots
    // under QEMU `-cdrom` for both BIOS + UEFI; the GPT-hybrid bit
    // matters for USB-stick boot, which is not in our v1 test path).
    let iso_path = repo.join(format!("target/oxide-{arch}.iso"));
    let xorriso = which("xorriso");
    let mut c = Command::new(if xorriso.is_some() { "xorriso" } else { "mkisofs" });
    if xorriso.is_some() {
        c.args(["-as", "mkisofs"]);
    }
    c.args([
        "-R", "-r", "-J",
        "-b", "limine-bios-cd.bin",
        "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
        "-eltorito-alt-boot",
        "-e", "limine-uefi-cd.bin",
        "-no-emul-boot",
    ]);
    if xorriso.is_some() {
        c.args(["-isohybrid-gpt-basdat"]);
    }
    c.args([
        "-o", iso_path.to_str().unwrap(),
        stage.to_str().unwrap(),
    ]);
    run(c)?;

    // Stamp the BIOS boot sector (no-op for aarch64; the limine tool
    // itself just patches the MBR — safe on an aarch64 ISO too).
    let mut c = Command::new(limine.join("limine"));
    c.args(["bios-install", iso_path.to_str().unwrap()]);
    run(c)?;

    eprintln!("xtask image: produced {}", iso_path.display());
    Ok(iso_path)
}

fn qemu_run_x86_64_disk(repo: &std::path::Path, img: &std::path::Path) -> Result<(), u8> {
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
    eprintln!("xtask qemu: launching qemu-system-x86_64 with GPT disk image (UEFI)");
    run(c)
}

fn qemu_run_aarch64_disk(repo: &std::path::Path, img: &std::path::Path) -> Result<(), u8> {
    if which("qemu-system-aarch64").is_none() {
        eprintln!("xtask qemu: qemu-system-aarch64 not on PATH; install qemu-system-aarch64.");
        return Err(2);
    }
    let ovmf = repo.join("vendor/firmware/ovmf-aarch64.fd");
    let mut c = Command::new("qemu-system-aarch64");
    c.args([
        "-machine", "virt",
        "-cpu", "cortex-a72",
        "-m", "256M",
        "-bios", ovmf.to_str().unwrap(),
        "-drive", &format!("format=raw,file={},if=virtio", img.display()),
        "-serial", "stdio",
        "-display", "none",
        "-no-reboot",
    ]);
    eprintln!("xtask qemu: launching qemu-system-aarch64 with GPT disk image (UEFI)");
    run(c)
}

fn qemu_run_x86_64(_repo: &std::path::Path, iso: &std::path::Path) -> Result<(), u8> {
    // SeaBIOS path — Limine ≥ 9 has a UEFI El Torito volume-
    // detection bug ("Could not meaningfully match the boot device
    // handle...") that triggers even with xorriso's
    // `-isohybrid-gpt-basdat`. Real fix is to ship a proper
    // GPT-partitioned disk image (per `39§*`) where the ESP is a
    // first-class partition rather than a CD's nested boot image —
    // that lands when initramfs / userspace does. SeaBIOS works
    // perfectly for the smoke test.
    let mut c = Command::new("qemu-system-x86_64");
    c.args([
        "-machine", "q35",
        "-cpu", "qemu64",
        "-m", "256M",
        "-cdrom", iso.to_str().unwrap(),
        "-serial", "stdio",
        "-display", "none",
        "-no-reboot",
        "-no-shutdown",
    ]);
    eprintln!("xtask qemu: launching qemu-system-x86_64 (Ctrl-A x to quit, SeaBIOS)");
    run(c)
}

fn qemu_run_aarch64(repo: &std::path::Path, iso: &std::path::Path) -> Result<(), u8> {
    if which("qemu-system-aarch64").is_none() {
        eprintln!("xtask qemu: qemu-system-aarch64 not on PATH; install your distro's qemu-system-aarch64 package.");
        return Err(2);
    }
    let ovmf = repo.join("vendor/firmware/ovmf-aarch64.fd");
    let mut c = Command::new("qemu-system-aarch64");
    c.args([
        "-machine", "virt",
        "-cpu", "cortex-a72",
        "-m", "256M",
        "-bios", ovmf.to_str().unwrap(),
        "-cdrom", iso.to_str().unwrap(),
        "-serial", "stdio",
        "-display", "none",
        "-no-reboot",
    ]);
    eprintln!("xtask qemu: launching qemu-system-aarch64 (Ctrl-A x to quit)");
    run(c)
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
