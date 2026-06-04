// `xtask grub` and `xtask selfboot` — GRUB-bootable ISO (x86_64
// multiboot2 + aarch64 EFI-stub) and the Limine-free aarch64 `-kernel`
// self-boot path per `07§8`. These share kernel-build + ELF-path
// resolution helpers (kernel_elf_path, repo_root, which). Helpers are
// pub(crate) so main can dispatch but consumers outside this module are
// restricted.

use std::process::Command;

use crate::{parse_arg, run};

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

/// `xtask grub --arch x86_64` — build a GRUB-bootable ISO that loads our
/// kernel DIRECTLY via Multiboot2 (the self-bootstrap path replacing
/// Limine) and boot it under QEMU. WIP: until the 32→64-bit long-mode
/// trampoline lands, GRUB loads the kernel and jumps to it but the
/// kernel can't run (entry is 64-bit higher-half; GRUB hands off in
/// 32-bit). This target lets that path be iterated.
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
    // `debug-boot` by default — mirrors the prior login path
    // (`make qemu-x86`): installs the UART klog sink without the
    // debug-sched/debug-vmm bring-up smokes. Those smokes (e.g. ksched
    // RR) `sti; hlt` on a deliberately-disarmed timer and deadlock — a
    // debug-all property, not a GRUB issue. Override with `--features
    // debug-all` to run them.
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
    qemu_run_grub_x86_64(&repo, &iso, smp)
}

/// GRUB on aarch64: build the EFI-stub Image, stage it + a grub.cfg that
/// `linux`-boots it, `grub2-mkrescue` an EFI ISO using the vendored
/// arm64-efi GRUB modules (no host grub2-efi-aa64 install needed), then
/// boot under OVMF. OVMF loads GRUB, GRUB's `linux` loads our PE Image,
/// the kernel's EFI stub exits boot services and joins the trampoline.
fn cmd_grub_aarch64(rest: &[String]) -> Result<(), u8> {
    let smp: u32 = parse_arg(rest, "--smp").and_then(|s| s.parse().ok()).unwrap_or(1);
    crate::cmd_rootfs(rest)?;
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
    qemu_run_aarch64_grub(&repo, &iso, smp)
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
/// v3+ITS as the kernel expects; rootfs embedded in the Image.
fn qemu_run_aarch64_grub(
    repo: &std::path::Path,
    iso: &std::path::Path,
    smp: u32,
) -> Result<(), u8> {
    if which("qemu-system-aarch64").is_none() {
        eprintln!("xtask grub: qemu-system-aarch64 not on PATH; install your distro's qemu-system-aarch64 package.");
        return Err(2);
    }
    let ovmf = repo.join("vendor/firmware/ovmf-aarch64.fd");
    let smp_str = smp.to_string();
    let headless = std::env::var("OXIDE_QEMU_HEADLESS").is_ok();
    let uart_chardev = if headless { "stdio,id=ser0,signal=off" }
                       else { "stdio,id=ser0,mux=on,signal=off" };
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
        "-chardev", uart_chardev,
        "-serial", "chardev:ser0",
        "-display", if headless { "none" } else { "gtk" },
        "-no-reboot",
    ]);
    eprintln!("xtask grub: launching qemu-system-aarch64 (OVMF→GRUB→EFI-stub), smp={smp}, headless={headless}");
    run(c)
}

/// Limine-free aarch64 boot: objcopy the kernel ELF to a flat arm64
/// `Image` (the self-bootstrap trampoline owns MMU/GIC/EL setup) and
/// boot it via QEMU `-kernel` — the same Image protocol U-Boot `booti`
/// and GRUB `linux` use, so this artifact is what any bootloader loads.
/// No Limine, no OVMF, no ESP.
pub(crate) fn cmd_selfboot(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").unwrap_or_else(|| "aarch64".into());
    if arch != "aarch64" {
        eprintln!("xtask selfboot: only aarch64 (x86 self-boot is the GRUB multiboot2 path: `xtask grub --arch x86_64`)");
        return Err(2);
    }
    let smp: u32 = parse_arg(rest, "--smp").and_then(|s| s.parse().ok()).unwrap_or(1);
    crate::cmd_rootfs(rest)?;
    // debug-boot by default — UART klog sink, no bring-up smokes (parity
    // with `make qemu-arm`). Override with --features.
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
    let image = build_arm_image(&repo, &kernel_elf)?;
    qemu_run_aarch64_selfboot(&repo, &image, smp)
}

/// objcopy the kernel ELF → flat arm64 `Image` (header + trampoline at
/// byte 0). Reuses the toolchain's `rust-objcopy` (else `llvm-objcopy`).
fn build_arm_image(
    repo: &std::path::Path,
    kernel_elf: &std::path::Path,
) -> Result<std::path::PathBuf, u8> {
    let image = repo.join("target/oxide-aarch64.Image");
    let objcopy = if which("rust-objcopy").is_some() { "rust-objcopy" }
                  else if which("llvm-objcopy").is_some() { "llvm-objcopy" }
                  else {
                      eprintln!("xtask selfboot: need rust-objcopy or llvm-objcopy on PATH");
                      return Err(2);
                  };
    let mut c = Command::new(objcopy);
    c.args(["-O", "binary", kernel_elf.to_str().unwrap(), image.to_str().unwrap()]);
    run(c)?;
    eprintln!("xtask selfboot: produced {}", image.display());
    Ok(image)
}

/// Boot the flat arm64 Image directly via QEMU `-kernel` (no firmware).
/// GIC must be v3+ITS (the kernel's GICv3 driver); rootfs is embedded in
/// the Image, so no block device is attached.
fn qemu_run_aarch64_selfboot(
    _repo: &std::path::Path,
    image: &std::path::Path,
    smp: u32,
) -> Result<(), u8> {
    if which("qemu-system-aarch64").is_none() {
        eprintln!("xtask selfboot: qemu-system-aarch64 not on PATH; install your distro's qemu-system-aarch64 package.");
        return Err(2);
    }
    let smp_str = smp.to_string();
    let headless = std::env::var("OXIDE_QEMU_HEADLESS").is_ok();
    let uart_chardev = if headless { "stdio,id=ser0,signal=off" }
                       else { "stdio,id=ser0,mux=on,signal=off" };
    let mut c = Command::new("qemu-system-aarch64");
    c.args([
        "-machine", "virt,gic-version=3,its=on",
        "-cpu", "cortex-a72",
        "-smp", &smp_str,
        "-m", "2G",
        "-kernel", image.to_str().unwrap(),
        "-netdev", "user,id=net0,hostfwd=tcp::2222-:22",
        "-device", "virtio-net-pci,netdev=net0,bus=pcie.0,disable-legacy=on",
        // virtio-gpu scanout + keyboard for the graphical console — the
        // kernel's dev_virtio_gpu_modern paints fbcon to this scanout
        // (the framebuffer source on arm; there is no GOP here). Without
        // these the only output is serial.
        "-device", "virtio-gpu-pci,bus=pcie.0",
        "-device", "virtio-keyboard-pci,bus=pcie.0",
        "-chardev", uart_chardev,
        "-serial", "chardev:ser0",
        "-display", if headless { "none" } else { "gtk" },
        "-no-reboot",
    ]);
    eprintln!("xtask selfboot: launching qemu-system-aarch64 (-kernel Image, no Limine/OVMF), smp={smp}, headless={headless}");
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
        // virtio-gpu scanout + virtio-keyboard for the visual console so
        // fbcon renders + the GTK window takes keyboard input. Without
        // these the GRUB path has no display/input device at all.
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
