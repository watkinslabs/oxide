// `xtask image`, `xtask grub` per `07§8`. Limine is gone on both arches:
// x86 boots via GRUB multiboot2, aarch64 via the GRUB EFI-stub `linux`
// path (arm64 Image + self-boot MMU trampoline). `image` is a thin alias
// that builds the GRUB boot artifact without launching qemu; `grub`
// builds + boots. Helpers are pub(crate) so main can dispatch.

use std::process::Command;

use crate::{parse_arg, run};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// `xtask image --arch <arch>` — build the bootable artifact
/// (`target/oxide-<arch>-grub.iso`) without launching qemu. Limine is
/// gone, so this is a thin alias for `grub --arch <arch> --build-only`:
/// one "produce the boot artifact" entry point for external harnesses
/// (qemu-mcp, accept.py, run-smokes.sh).
pub(crate) fn cmd_image(rest: &[String]) -> Result<(), u8> {
    let mut args = rest.to_vec();
    if !rest.iter().any(|a| a == "--build-only") {
        args.push("--build-only".into());
    }
    cmd_grub(&args)
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

pub(crate) fn repo_root() -> std::path::PathBuf {
    let here = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(here)
        .ancestors().nth(2).map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::env::current_dir().unwrap())
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
// grub — self-bootstrap boot (x86 multiboot2 + aarch64 EFI-stub `linux`)
// ---------------------------------------------------------------------------

/// `xtask grub --arch <x86_64|aarch64>` — build a GRUB-bootable artifact
/// that loads our kernel DIRECTLY (x86 multiboot2; aarch64 EFI-stub
/// `linux`), replacing Limine, and boot it under QEMU.
pub(crate) fn cmd_grub(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").unwrap_or_else(|| "x86_64".into());
    if arch == "aarch64" {
        return cmd_grub_aarch64(rest);
    }
    if arch != "x86_64" {
        eprintln!("xtask grub: arch must be x86_64 or aarch64");
        return Err(2);
    }
    let smp: u32 = parse_arg(rest, "--smp").and_then(|s| s.parse().ok()).unwrap_or(1);
    crate::cmd_rootfs(rest)?;
    // `debug-boot` by default — installs the UART klog sink without the
    // debug-sched/debug-vmm bring-up smokes. Those smokes (e.g. ksched RR)
    // `sti; hlt` on a deliberately-disarmed timer and deadlock — a
    // debug-all property. Override with `--features debug-all`.
    let mut kr: Vec<String>;
    let kargs: &[String] = if parse_arg(rest, "--features").is_none() {
        kr = rest.to_vec();
        kr.push("--features".into());
        kr.push("debug-boot".into());
        &kr[..]
    } else { rest };
    crate::cmd_kernel(kargs)?;
    let repo = repo_root();
    let kernel_elf = kernel_elf_path(&repo, &arch, rest)?;
    let iso = build_grub_iso(&repo, &arch, &kernel_elf)?;
    // `--build-only`: produce the GRUB ISO + rootfs but skip the qemu launch.
    // The qemu-mcp / accept.py use this to build the boot artifact, then
    // spawn their own qemu against it.
    if rest.iter().any(|a| a == "--build-only") {
        println!("xtask grub: built {} (--build-only, not launching qemu)", iso.display());
        return Ok(());
    }
    qemu_run_grub_x86_64(&repo, &iso, smp)
}

/// GRUB on aarch64 (Limine-free): build the EFI-stub flat Image, stage it
/// + a grub.cfg that `linux`-boots it, `grub2-mkrescue` an EFI ISO using
/// the vendored arm64-efi GRUB modules (no host grub2-efi-aa64 install
/// needed — see tools/fetch-grub.sh), then boot under OVMF. OVMF loads
/// GRUB, GRUB's `linux` loads our PE Image, the kernel's EFI stub exits
/// boot services + drops the MMU and joins the self-boot trampoline. The
/// rootfs is embedded in the kernel (ext4::rootfs `include_bytes!`), so
/// root mounts without a block device; the EFI stub's ACPI RSDP brings up
/// PCI (virtio-net/gpu).
fn cmd_grub_aarch64(rest: &[String]) -> Result<(), u8> {
    let smp: u32 = parse_arg(rest, "--smp").and_then(|s| s.parse().ok()).unwrap_or(1);
    crate::cmd_rootfs(rest)?;
    // debug-boot by default — UART klog sink, no bring-up smokes (parity
    // with the x86 grub path). Override with --features debug-all.
    let mut kr: Vec<String>;
    let kargs: &[String] = if parse_arg(rest, "--features").is_none() {
        kr = rest.to_vec();
        kr.push("--features".into());
        kr.push("debug-boot".into());
        &kr[..]
    } else { rest };
    crate::cmd_kernel(kargs)?;
    let repo = repo_root();
    let kernel_elf = kernel_elf_path(&repo, "aarch64", rest)?;
    let image = build_arm_image(&repo, &kernel_elf)?;
    let iso = build_grub_arm_iso(&repo, &image)?;
    // `--build-only`: produce the ISO but skip the qemu launch (qemu-mcp /
    // boot-smoke build the artifact then spawn their own qemu).
    if rest.iter().any(|a| a == "--build-only") {
        println!("xtask grub: built {} (--build-only, not launching qemu)", iso.display());
        return Ok(());
    }
    qemu_run_aarch64_grub(&repo, &iso, smp)
}

/// objcopy the aarch64 kernel ELF → flat arm64 `Image` (arm64 Image
/// header + PE32+/EFI header + MMU trampoline at byte 0). The artifact is
/// what GRUB `linux`, UEFI LoadImage, U-Boot `booti`, and QEMU `-kernel`
/// all load.
fn build_arm_image(
    repo: &std::path::Path,
    kernel_elf: &std::path::Path,
) -> Result<std::path::PathBuf, u8> {
    let image = repo.join("target/oxide-aarch64.Image");
    let objcopy = if which("rust-objcopy").is_some() { "rust-objcopy" }
                  else if which("llvm-objcopy").is_some() { "llvm-objcopy" }
                  else {
                      eprintln!("xtask grub: need rust-objcopy or llvm-objcopy on PATH");
                      return Err(2);
                  };
    let mut c = Command::new(objcopy);
    c.args(["-O", "binary", kernel_elf.to_str().unwrap(), image.to_str().unwrap()]);
    run(c)?;
    eprintln!("xtask grub: produced {}", image.display());
    Ok(image)
}

/// Stage the EFI-stub Image + a grub.cfg (`linux /boot/oxide-aarch64.Image`)
/// and grub2-mkrescue an EFI ISO with the vendored arm64-efi modules.
fn build_grub_arm_iso(
    repo: &std::path::Path,
    image: &std::path::Path,
) -> Result<std::path::PathBuf, u8> {
    use std::fs;
    let mods = repo.join("vendor/grub/arm64-efi");
    if !mods.join("modinfo.sh").exists() {
        eprintln!("xtask grub: vendored arm64-efi modules missing — run tools/fetch-grub.sh");
        return Err(2);
    }
    let stage = repo.join("target/grub-stage-aarch64");
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(stage.join("boot/grub")).map_err(|_| 1u8)?;
    fs::copy(image, stage.join("boot/oxide-aarch64.Image")).map_err(|_| 1u8)?;
    // GRUB's arm64 serial console differs from x86; use the firmware
    // console (OVMF routes it to the PL011 → -serial). `linux` boots our
    // PE Image as an EFI application.
    let cfg = "set timeout=1\nset default=0\nterminal_input console\nterminal_output console\n\n\
               menuentry \"oxide (EFI-stub)\" {\n    \
               linux /boot/oxide-aarch64.Image\n    \
               boot\n}\n";
    fs::write(stage.join("boot/grub/grub.cfg"), cfg).map_err(|_| 1u8)?;
    let iso = repo.join("target/oxide-aarch64-grub.iso");
    let _ = fs::remove_file(&iso);
    let mkrescue = if which("grub2-mkrescue").is_some() { "grub2-mkrescue" } else { "grub-mkrescue" };
    let mut c = Command::new(mkrescue);
    c.args(["-d", mods.to_str().unwrap(), "-o", iso.to_str().unwrap(), stage.to_str().unwrap()]);
    run(c)?;
    eprintln!("xtask grub: produced {}", iso.display());
    Ok(iso)
}

/// Boot the aarch64 GRUB EFI ISO under QEMU with OVMF. Semihosting is on
/// (the kernel's early klog uses it until device_map remaps PL011); GIC
/// v3+ITS as the kernel expects; rootfs embedded in the Image (no block
/// device). OXIDE_QEMU_UART_SOCK routes serial to a unix socket (the
/// boot-smoke/login scripts feed scripted keystrokes that way); else
/// headless stdio for CI or a muxed stdio + GTK display interactively.
fn qemu_run_aarch64_grub(
    repo: &std::path::Path,
    iso: &std::path::Path,
    smp: u32,
) -> Result<(), u8> {
    if which("qemu-system-aarch64").is_none() {
        eprintln!("xtask grub: qemu-system-aarch64 not on PATH; install qemu-system-aarch64.");
        return Err(2);
    }
    let ovmf = repo.join("vendor/firmware/ovmf-aarch64.fd");
    let smp_str = smp.to_string();
    let headless = std::env::var("OXIDE_QEMU_HEADLESS").is_ok();
    // Same OXIDE_QEMU_UART_SOCK plumbing as the x86 launcher.
    let uart_chardev: String = match std::env::var("OXIDE_QEMU_UART_SOCK") {
        Ok(p) if !p.is_empty() => {
            let _ = std::fs::remove_file(&p);
            format!("socket,id=ser0,path={},server=on,wait=off", p)
        }
        _ => if headless { "stdio,id=ser0,signal=off".to_string() }
             else { "stdio,id=ser0,mux=on,signal=off".to_string() },
    };
    let mut c = Command::new("qemu-system-aarch64");
    c.args([
        "-machine", "virt,gic-version=3,its=on",
        "-cpu", "cortex-a72",
        "-smp", &smp_str,
        "-m", "2G",
        "-bios", ovmf.to_str().unwrap(),
        "-cdrom", iso.to_str().unwrap(),
        "-boot", "d",
        "-semihosting-config", "enable=on,target=native",
        "-netdev", "user,id=net0,hostfwd=tcp::2222-:22",
        "-device", "virtio-net-pci,netdev=net0,bus=pcie.0,disable-legacy=on",
        // virtio-gpu scanout + keyboard for the graphical console (fbcon
        // paints here; no GOP on this path). Without them only serial gets
        // output and the GTK window stays blank.
        "-device", "virtio-gpu-pci,bus=pcie.0",
        "-device", "virtio-keyboard-pci,bus=pcie.0",
        "-chardev", uart_chardev.as_str(),
        "-serial", "chardev:ser0",
        "-display", if headless { "none" } else { "gtk" },
        "-no-reboot",
    ]);
    eprintln!("xtask grub: launching qemu-system-aarch64 (OVMF→GRUB→EFI-stub), smp={smp}, headless={headless}");
    run(c)
}

/// Stage `boot/oxide-<arch>` + a `grub.cfg` that `multiboot2`-loads it,
/// then `grub2-mkrescue` into a hybrid BIOS+UEFI ISO.
fn build_grub_iso(
    repo: &std::path::Path,
    arch: &str,
    kernel_elf: &std::path::Path,
) -> Result<std::path::PathBuf, u8> {
    use std::fs;
    let stage = repo.join(format!("target/grub-stage-{arch}"));
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(stage.join("boot/grub")).map_err(|_| 1u8)?;
    fs::copy(kernel_elf, stage.join(format!("boot/oxide-{arch}"))).map_err(|_| 1u8)?;
    let cfg = format!(
        "set timeout=3\nset default=0\nserial --unit=0 --speed=115200\nterminal_input serial console\nterminal_output serial console\n\n\
         menuentry \"oxide (multiboot2)\" {{\n    \
         multiboot2 /boot/oxide-{arch} BOOT_IMAGE=/boot/oxide-{arch} root=/dev/oxide0 ro quiet console=ttyS0,115200\n    \
         boot\n}}\n");
    fs::write(stage.join("boot/grub/grub.cfg"), cfg).map_err(|_| 1u8)?;
    let iso = repo.join(format!("target/oxide-{arch}-grub.iso"));
    let _ = fs::remove_file(&iso);
    let mkrescue = if which("grub2-mkrescue").is_some() { "grub2-mkrescue" } else { "grub-mkrescue" };
    let mut c = Command::new(mkrescue);
    c.args(["-o", iso.to_str().unwrap(), stage.to_str().unwrap()]);
    run(c)?;
    eprintln!("xtask grub: produced {}", iso.display());
    Ok(iso)
}

/// Boot the GRUB ISO under QEMU (SeaBIOS El Torito). Attaches the ext4
/// rootfs as virtio-blk (/dev/oxide0) and serial→stdio for the console.
fn qemu_run_grub_x86_64(
    repo: &std::path::Path,
    iso: &std::path::Path,
    smp: u32,
) -> Result<(), u8> {
    let rootfs = repo.join("kernel/blobs/rootfs-x86_64.img");
    let smp_str = smp.to_string();
    let accel = if std::env::var("OXIDE_QEMU_KVM").is_ok()
        && std::path::Path::new("/dev/kvm").exists()
    { "kvm" } else { "tcg" };
    // Headless (CI / boot-smoke / login-smoke): a `stdio,signal=off`
    // chardev so piped stdin reaches the guest UART RX byte-for-byte (the
    // login-smoke feeds a FIFO this way). Plain `-serial stdio`
    // line-buffers + handles signals and drops scripted keystrokes.
    // Interactive: mux=on so Ctrl-A C reaches the QEMU monitor.
    let headless = std::env::var("OXIDE_QEMU_HEADLESS").is_ok();
    let uart_chardev = if headless {
        "stdio,id=ser0,signal=off"
    } else {
        "stdio,id=ser0,mux=on,signal=off"
    };
    let mut c = Command::new("qemu-system-x86_64");
    // Optional CPU/interrupt tracing: OXIDE_QEMU_DINT=<file> adds
    // `-d int,guest_errors -D <file>` so a boot fault's exception
    // cascade (the #PF preceding a #DF, with CR2/error code) is
    // captured. Routed through the make/xtask path so it survives the
    // boot-smoke setsid wrapper (direct qemu gets sandbox-killed).
    if let Ok(p) = std::env::var("OXIDE_QEMU_DINT") {
        if !p.is_empty() {
            c.args(["-d", "int,guest_errors", "-D", p.as_str()]);
        }
    }
    c.args([
        "-machine", "q35",
        "-accel", accel,
        "-cpu", "Haswell-v4",
        "-smp", &smp_str,
        "-m", "1G",
        "-cdrom", iso.to_str().unwrap(),
        "-boot", "d",
        "-drive", &format!("if=none,id=hd0,format=raw,file={}", rootfs.display()),
        "-device", "virtio-blk-pci,drive=hd0,bus=pcie.0,serial=oxide-virt-blk-0",
        "-netdev", "user,id=net0,hostfwd=tcp::2222-:22",
        "-device", "virtio-net-pci,netdev=net0,bus=pcie.0,disable-legacy=on",
        // -vga none: q35 otherwise adds a default std-VGA that becomes the
        // PRIMARY display, so the GTK window shows that (blank — we never
        // drive it) and the virtio-gpu console is a hidden secondary. Removing
        // it makes virtio-gpu THE display, so fbcon's rendered console is what
        // the window shows. (Verified: virtio-gpu fb carries the glyphs.)
        "-vga", "none",
        // virtio-gpu scanout + virtio-keyboard for the visual console so
        // fbcon renders + the GTK window takes keyboard input.
        "-device", "virtio-gpu-pci,bus=pcie.0",
        "-device", "virtio-keyboard-pci,bus=pcie.0",
        "-chardev", uart_chardev,
        "-serial", "chardev:ser0",
        // GTK window by default so the virtio-gpu console is visible +
        // responsive; OXIDE_QEMU_HEADLESS=1 suppresses for CI/smoke.
        "-display", if headless { "none" } else { "gtk" },
        "-no-reboot",
    ]);
    eprintln!("xtask grub: launching qemu (GRUB→multiboot2), smp={smp}, accel={accel}, headless={headless}");
    run(c)
}
