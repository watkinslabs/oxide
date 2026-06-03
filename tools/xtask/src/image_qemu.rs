// `xtask image` and `xtask qemu` per `07§8`. The image and qemu
// commands share most of their setup (arch validation, kernel
// build, bootloader vendor check, kernel-ELF path resolution) so
// they live together. Helper functions are pub(crate) so main
// can dispatch but consumers outside this module are restricted.

use std::process::Command;

use crate::{parse_arg, run, cmd_kernel};

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
pub(crate) fn cmd_image(rest: &[String]) -> Result<(), u8> {
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

pub(crate) fn cmd_qemu(rest: &[String]) -> Result<(), u8> {
    let arch = parse_arg(rest, "--arch").ok_or_else(|| {
        eprintln!("xtask qemu: --arch <x86_64|aarch64> required");
        2u8
    })?;
    let format = parse_arg(rest, "--format").unwrap_or_else(|| "disk".into());
    let smp: u32 = parse_arg(rest, "--smp")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    // Rebuild userspace rootfs first so kernel/blobs/rootfs.img
    // (which the kernel `include_bytes!`s) reflects every userspace/
    // *.c edit. Without this, source changes ship to disk only on the
    // next explicit `xtask rootfs`, leading to "I changed the code
    // but nothing changed" surprises.
    // Per-arch rootfs first so the kernel `include_bytes!`s the
    // matching arm/x86 image. cmd_rootfs takes --arch; cmd_qemu's
    // `rest` already carries it.
    crate::cmd_rootfs(rest)?;
    // Interactive boot tool: default to debug-all so the kernel
    // actually emits klog output to serial. Production / CI builds
    // pin --features explicitly per `04` R06; only the bare `xtask
    // qemu --arch X` invocation gets the debug envelope.
    let mut kernel_rest: Vec<String>;
    let kernel_args: &[String] = if parse_arg(rest, "--features").is_none() {
        kernel_rest = rest.to_vec();
        kernel_rest.push("--features".into());
        kernel_rest.push("debug-all".into());
        &kernel_rest[..]
    } else {
        rest
    };
    cmd_kernel(kernel_args)?;
    let repo = repo_root();
    let kernel_elf = kernel_elf_path(&repo, &arch, rest)?;
    check_vendor(&repo)?;
    match (arch.as_str(), format.as_str()) {
        ("x86_64",  "disk") => qemu_run_x86_64_disk(&repo, &build_disk_image(&repo, &arch, &kernel_elf)?, smp),
        ("aarch64", "disk") => qemu_run_aarch64_disk(&repo, &build_disk_image(&repo, &arch, &kernel_elf)?, smp),
        ("x86_64",  "iso")  => qemu_run_x86_64(&repo,    &build_iso(&repo, &arch, &kernel_elf)?, smp),
        ("aarch64", "iso")  => qemu_run_aarch64(&repo,   &build_iso(&repo, &arch, &kernel_elf)?, smp),
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

pub(crate) fn repo_root() -> std::path::PathBuf {
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

    // 512 MiB image. The kernel ELF include_bytes!s the rootfs, so the
    // ESP must hold a kernel as large as the rootfs + code (a 64 MiB
    // rootfs alone overflowed the old ~62 MiB ESP → mcopy "Disk full").
    // 512 MiB leaves room for a 128 MiB rootfs (Track D6 systemd) + code.
    // Host disk only; not RAM.
    {
        let mut c = Command::new("dd");
        c.args(["if=/dev/zero", "bs=1M", "count=512",
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

    let console = match arch {
        "x86_64"  => "ttyS0,115200",
        "aarch64" => "ttyAMA0,115200",
        _         => "ttyS0,115200",
    };
    let cfg = format!(
        "timeout: 0\nserial: yes\nverbose: yes\ndefault_entry: 1\n\n/oxide\n    protocol: limine\n    path: boot():/boot/limine/{kernel_name}\n    cmdline: BOOT_IMAGE=/boot/limine/{kernel_name} root=/dev/oxide0 ro quiet console={console}\n",
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
    let console = match arch {
        "x86_64"  => "ttyS0,115200",
        "aarch64" => "ttyAMA0,115200",
        _         => "ttyS0,115200",
    };
    let cfg = format!(
        "timeout: 0\nserial: yes\nverbose: yes\ndefault_entry: 1\n\n/oxide\n    protocol: limine\n    path: boot():/boot/limine/{kernel_name}\n    cmdline: BOOT_IMAGE=/boot/limine/{kernel_name} root=/dev/oxide0 ro quiet console={console}\n",
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

fn qemu_run_x86_64_disk(repo: &std::path::Path, img: &std::path::Path, smp: u32) -> Result<(), u8> {
    let ovmf = repo.join("vendor/firmware/ovmf-x64.fd");
    let smp_str = smp.to_string();
    // OXIDE_QEMU_UART_SOCK=<path>: use unix-socket chardev for the
    // guest UART instead of stdio. With piped stdin QEMU's stdio
    // chardev doesn't reliably forward bytes to the guest RX register;
    // a unix socket plus an external socat bridge is the canonical
    // automated-input path.
    let uart_chardev: String = match std::env::var("OXIDE_QEMU_UART_SOCK") {
        Ok(p) if !p.is_empty() => {
            let _ = std::fs::remove_file(&p);
            format!("socket,id=ser0,path={},server=on,wait=off", p)
        }
        _ => if std::env::var("OXIDE_QEMU_HEADLESS").is_ok() {
            "stdio,id=ser0,signal=off".to_string()
        } else {
            "stdio,id=ser0,mux=on,signal=off".to_string()
        }
    };
    let mut c = Command::new("qemu-system-x86_64");
    // F207: KVM is opt-in (set OXIDE_QEMU_KVM=1). TCG default — KVM
    // exposes a boot-time kernel bug (HLT/IF semantics, MSR delta vs
    // TCG) that wedges at "keymap loaded"; fix lives in a follow-up.
    // KVM with TCG-friendly kernel cuts host CPU from 100% to idle on
    // guest HLT, which matters for long-running interactive sessions.
    let accel = if std::env::var("OXIDE_QEMU_KVM").is_ok()
        && std::path::Path::new("/dev/kvm").exists()
    { "kvm" } else { "tcg" };
    c.args([
        "-machine", "q35",
        "-accel", accel,
        // x86 baseline = Haswell-v4 (BMI2/AVX2 era, 2013+). LLVM
        // emits SHRX/etc. by default for the kernel target; older
        // CPU models (qemu64) trap #UD on those.
        "-cpu", "Haswell-v4",
        "-smp", &smp_str,
        "-m", "1G",
        "-bios", ovmf.to_str().unwrap(),
        // Boot drive attached as virtio-blk-pci (not legacy IDE) so the
        // F19-F30 modern virtio-pci transport bring-up runs on x86 the
        // same way it does on aarch64. Mirrors the aarch64 launcher
        // (qemu_run_aarch64_disk below). serial=oxide-virt-blk-0 makes
        // VIRTIO_BLK_T_GET_ID return a recognizable string (F31).
        "-drive",  &format!("if=none,id=hd0,format=raw,file={}", img.display()),
        "-device", "virtio-blk-pci,drive=hd0,bus=pcie.0,serial=oxide-virt-blk-0",
        // virtio-gpu is the kernel's primary display target — our
        // dev_virtio_gpu_modern paints `oxide kernel ready` to its
        // scanout at boot. `-vga none` disables QEMU's q35 default
        // stdvga (bochs-display, vendor 1234:1111) — without this,
        // GTK shows that empty stdvga framebuffer and our virtio-gpu
        // scanout (which the host accepts with RESP_OK_NODATA) goes
        // to a second head GTK never selects.
        "-vga",    "none",
        "-device", "virtio-gpu-pci,bus=pcie.0",
        // virtio keyboard for `46` (input). Mouse removed — kernel
        // doesn't process pointer events yet and the wheel-input
        // events were just spamming the serial log.
        "-device", "virtio-keyboard-pci,bus=pcie.0",
        // F135: modern virtio-net so AF_PACKET / DHCP have a real
        // device. `user` backend is qemu's slirp NAT — gives the
        // guest 10.0.2.x with a DHCP server at 10.0.2.2. No
        // external visibility (slirp is host-isolated), but
        // sufficient for verifying DHCPDISCOVER reaches a server.
        // F196: host:2222 → guest:22 for ssh access.
        "-netdev", "user,id=net0,hostfwd=tcp::2222-:22",
        "-device", "virtio-net-pci,netdev=net0,bus=pcie.0,disable-legacy=on",
        // Serial: dedicated chardev with `mux=on,signal=off` so Ctrl-A
        // is QEMU's monitor escape and Ctrl-C reaches the guest.
        // Plain `-serial stdio` puts host stdin in line-buffered cooked
        // mode and drops single keystrokes — the kernel's tty line-
        // discipline then sees malformed input ("the sh fucking up").
        // `-nographic` would do the same but also kill `-display none`.
        // Interactive: stdio with mux=on (Ctrl-A C → monitor).
        // Headless (OXIDE_QEMU_HEADLESS=1): plain stdio without mux so
        // piped stdin reaches the guest UART RX. stdio chardev in QEMU
        // forwards stdin → guest RBR when stdin is not a TTY too;
        // mux=on routes those bytes to the multiplexer instead. The
        // log goes to stdout either way; redirect via shell as usual.
        "-chardev", uart_chardev.as_str(),
        "-serial", "chardev:ser0",
        // GTK on by default so virtio-gpu scanout is visible.
        // OXIDE_QEMU_HEADLESS=1 suppresses for CI / soak runs.
        // -no-shutdown was REMOVED — that flag plus GTK was the
        // wedge: kernel halt → QEMU stays alive → unkillable
        // window. Without it, halt exits cleanly and the GTK
        // window closes on its own.
        "-display", if std::env::var("OXIDE_QEMU_HEADLESS").is_ok() { "none" } else { "gtk" },
        "-no-reboot",
    ]);
    eprintln!("xtask qemu: launching qemu-system-x86_64 (q35 + Haswell-v4 + stdio chardev), smp={}", smp);
    eprintln!("xtask qemu: Ctrl-A C → QEMU monitor; Ctrl-A X → quit; Ctrl-C reaches guest. OXIDE_QEMU_HEADLESS=1 for headless.");
    run(c)
}

fn qemu_run_aarch64_disk(repo: &std::path::Path, img: &std::path::Path, smp: u32) -> Result<(), u8> {
    if which("qemu-system-aarch64").is_none() {
        eprintln!("xtask qemu: qemu-system-aarch64 not on PATH; install qemu-system-aarch64.");
        return Err(2);
    }
    let ovmf = repo.join("vendor/firmware/ovmf-aarch64.fd");
    let smp_str = smp.to_string();
    // Same OXIDE_QEMU_UART_SOCK plumbing as x86 — see qemu_run_x86_64_disk.
    let uart_chardev: String = match std::env::var("OXIDE_QEMU_UART_SOCK") {
        Ok(p) if !p.is_empty() => {
            let _ = std::fs::remove_file(&p);
            format!("socket,id=ser0,path={},server=on,wait=off", p)
        }
        _ => if std::env::var("OXIDE_QEMU_HEADLESS").is_ok() {
            "stdio,id=ser0,signal=off".to_string()
        } else {
            "stdio,id=ser0,mux=on,signal=off".to_string()
        }
    };
    let mut c = Command::new("qemu-system-aarch64");
    c.args([
        "-machine", "virt,gic-version=3,its=on",
        "-cpu", "cortex-a72",
        "-smp", &smp_str,
        // 512 MiB so Limine's high-memory allocator can fit the 64 MiB
        // BSS reservation alongside UEFI/edk2 overhead on aarch64. With
        // 256 MiB Limine OOMed during kernel load. x86 with 256 MiB
        // works because OVMF x64 leaves more headroom.
        "-m", "1G",
        "-bios", ovmf.to_str().unwrap(),
        // Drive on the `virt` machine: explicit virtio-blk-pci so
        // OVMF aarch64 sees it as a UEFI block device and walks the
        // GPT for our ESP. Plain `-drive if=virtio` defaults to the
        // legacy MMIO transport which OVMF on virt sometimes ignores;
        // attaching as virtio-blk-pci through the virt-machine's
        // synthetic PCIe root is the path edk2 reliably discovers.
        "-drive",  &format!("if=none,id=hd0,format=raw,file={}", img.display()),
        "-device", "virtio-blk-pci,drive=hd0,bus=pcie.0,serial=oxide-virt-blk-0",
        // virtio-gpu only — same reasoning as x86. Kernel's
        // dev_virtio_gpu_modern paints to this scanout.
        "-device", "virtio-gpu-pci,bus=pcie.0",
        // virtio keyboard for `46`. Mouse removed; same reason.
        "-device", "virtio-keyboard-pci,bus=pcie.0",
        // F135: virtio-net for AF_PACKET / DHCP. Same slirp NAT
        // backend as x86.
        // F196: host:2222 → guest:22 for ssh access.
        "-netdev", "user,id=net0,hostfwd=tcp::2222-:22",
        "-device", "virtio-net-pci,netdev=net0,bus=pcie.0,disable-legacy=on",
        "-chardev", uart_chardev.as_str(),
        "-serial", "chardev:ser0",
        // GTK on by default for ARM too — `virt` machine wires
        // virtio-gpu-pci to the synthetic PCIe root, OVMF aarch64
        // exposes a UEFI GOP and the kernel scanout driver paints
        // pixels there. Headless toggle for soak/CI runs.
        "-display", if std::env::var("OXIDE_QEMU_HEADLESS").is_ok() { "none" } else { "gtk" },
        "-no-reboot",
        // Semihosting target=native lets the boot crate emit debug
        // chars via `hlt #0xf000` while we're still pre-MMIO.
        "-semihosting-config", "enable=on,target=native",
    ]);
    eprintln!("xtask qemu: launching qemu-system-aarch64 (virt + cortex-a72 + stdio chardev), smp={}", smp);
    eprintln!("xtask qemu: Ctrl-A C → QEMU monitor; Ctrl-A X → quit. OXIDE_QEMU_HEADLESS=1 for headless.");
    run(c)
}

fn qemu_run_x86_64(_repo: &std::path::Path, iso: &std::path::Path, smp: u32) -> Result<(), u8> {
    // SeaBIOS path — Limine ≥ 9 has a UEFI El Torito volume-
    // detection bug ("Could not meaningfully match the boot device
    // handle...") that triggers even with xorriso's
    // `-isohybrid-gpt-basdat`. Real fix is to ship a proper
    // GPT-partitioned disk image (per `39§*`) where the ESP is a
    // first-class partition rather than a CD's nested boot image —
    // that lands when initramfs / userspace does. SeaBIOS works
    // perfectly for the smoke test.
    let smp_str = smp.to_string();
    let mut c = Command::new("qemu-system-x86_64");
    c.args([
        "-machine", "q35",
        // x86 baseline = Haswell-v4 (BMI2/AVX2 era, 2013+). LLVM
        // emits SHRX/etc. by default for the kernel target; older
        // CPU models (qemu64) trap #UD on those. Future PR: target-
        // feature gating in `targets/x86_64-unknown-oxide-kernel.json`
        // so the kernel runs on plain qemu64 too.
        "-cpu", "Haswell-v4",
        "-smp", &smp_str,
        "-m", "1G",
        "-cdrom", iso.to_str().unwrap(),
        "-serial", "stdio",
        "-display", "none",
        "-no-reboot",
        "-no-shutdown",
    ]);
    eprintln!("xtask qemu: launching qemu-system-x86_64 (Ctrl-A x to quit, SeaBIOS), smp={}", smp);
    run(c)
}

fn qemu_run_aarch64(repo: &std::path::Path, iso: &std::path::Path, smp: u32) -> Result<(), u8> {
    if which("qemu-system-aarch64").is_none() {
        eprintln!("xtask qemu: qemu-system-aarch64 not on PATH; install your distro's qemu-system-aarch64 package.");
        return Err(2);
    }
    let ovmf = repo.join("vendor/firmware/ovmf-aarch64.fd");
    let smp_str = smp.to_string();
    let mut c = Command::new("qemu-system-aarch64");
    c.args([
        "-machine", "virt,gic-version=3,its=on",
        "-cpu", "cortex-a72",
        "-smp", &smp_str,
        "-m", "1G",
        "-bios", ovmf.to_str().unwrap(),
        "-cdrom", iso.to_str().unwrap(),
        "-serial", "stdio",
        "-display", "none",
        "-no-reboot",
    ]);
    eprintln!("xtask qemu: launching qemu-system-aarch64 (Ctrl-A x to quit), smp={}", smp);
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
    // `debug-boot` by default — mirrors the Limine login path
    // (`make qemu-x86`, QEMU_FEATURES_X86=debug-boot): installs the UART
    // klog sink without the debug-sched/debug-vmm bring-up smokes. Those
    // smokes (e.g. ksched RR) `sti; hlt` on a deliberately-disarmed timer
    // and deadlock — a debug-all property, not a GRUB issue. Override
    // with `--features debug-all` to run them.
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
        "-chardev", uart_chardev,
        "-serial", "chardev:ser0",
        "-display", "none",
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
    // with `make qemu-arm` QEMU_FEATURES). Override with --features.
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
        "-chardev", uart_chardev,
        "-serial", "chardev:ser0",
        "-display", "none",
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
    // chardev — same as the Limine headless path — so piped stdin
    // reaches the guest UART RX byte-for-byte (the login-smoke feeds a
    // FIFO this way). Plain `-serial stdio` line-buffers + handles
    // signals and drops scripted keystrokes. Interactive: mux=on so
    // Ctrl-A C reaches the QEMU monitor.
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
        // virtio-gpu scanout + virtio-keyboard for the visual console —
        // same devices as the Limine path so fbcon renders + the GTK
        // window takes keyboard input. Without these the GRUB path has
        // no display/input device at all (was -display none only).
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
