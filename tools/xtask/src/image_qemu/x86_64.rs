use std::process::Command;

use crate::run;

use super::common::{ensure_ahci_img, ensure_nvme_img, ssh_fwd_netdev, which};

/// Stage `boot/oxide-<arch>` + a `grub.cfg` that `multiboot2`-loads it,
/// then `grub2-mkrescue` into a hybrid BIOS+UEFI ISO.
pub(super) fn build_grub_iso(
    repo: &std::path::Path,
    id: Option<&str>,
    arch: &str,
    kernel_elf: &std::path::Path,
) -> Result<std::path::PathBuf, u8> {
    use std::fs;
    let stage = crate::buildns::grub_stage(repo, id, arch);
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(stage.join("boot/grub")).map_err(|_| 1u8)?;
    fs::copy(kernel_elf, stage.join(format!("boot/oxide-{arch}"))).map_err(|_| 1u8)?;
    let cfg = format!(
        "set timeout=0\nset default=0\nserial --unit=0 --speed=115200\nterminal_input serial console\nterminal_output serial console\n\n\
         menuentry \"oxide (multiboot2)\" {{\n    \
         multiboot2 /boot/oxide-{arch} BOOT_IMAGE=/boot/oxide-{arch} root=/dev/oxide0 ro quiet console=ttyS0,115200 console=tty0\n    \
         boot\n}}\n");
    fs::write(stage.join("boot/grub/grub.cfg"), cfg).map_err(|_| 1u8)?;
    let iso = crate::buildns::iso_path(repo, id, arch);
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
pub(super) fn qemu_run_grub_x86_64(
    repo: &std::path::Path,
    id: Option<&str>,
    iso: &std::path::Path,
    smp: u32,
) -> Result<(), u8> {
    let blobs = crate::buildns::blobs_dir(repo, id);
    let root_img = blobs.join("root-x86_64.img");
    let home_img = blobs.join("home-x86_64.img");
    // D3.5: NVMe scratch disk for the drv-nvme bring-up.
    let nvme_img = ensure_nvme_img(repo, id, "x86_64");
    let nvme_drive = format!("id=nvm0,if=none,format=raw,file={}", nvme_img.display());
    // D3.6: AHCI/SATA scratch disk for the drv-ahci bring-up.
    let ahci_img = ensure_ahci_img(repo, id, "x86_64");
    let ahci_drive = format!("id=sata0,if=none,format=raw,file={}", ahci_img.display());
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
    let netdev = ssh_fwd_netdev();
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
    // OXIDE_QEMU_GDB=1 exposes a gdb stub on tcp::1234 (no pause) so a
    // wedged/idle SMP boot can be inspected per-CPU (rip/backtrace) when the
    // in-kernel serial-sysrq path can't run. OXIDE_QEMU_GDB=wait also passes
    // -S (start halted) to set breakpoints before the first instruction.
    if let Ok(g) = std::env::var("OXIDE_QEMU_GDB") {
        if !g.is_empty() {
            c.args(["-gdb", "tcp::1234"]);
            if g == "wait" { c.arg("-S"); }
        }
    }
    // OXIDE_QEMU_QMP_SOCK=<path>: expose a QMP control socket so the
    // keyboard-login smoke can inject real virtio-keyboard events
    // (`send-key`) — testing framebuffer keystroke input end-to-end, not
    // just the serial UART RX path.
    let qmp_arg = std::env::var("OXIDE_QEMU_QMP_SOCK").ok().filter(|s| !s.is_empty())
        .map(|s| format!("unix:{s},server,nowait"));
    if let Some(ref q) = qmp_arg {
        c.args(["-qmp", q.as_str()]);
    }
    c.args([
        "-machine", "q35",
        "-accel", accel,
        "-cpu", "Haswell-v4",
        "-smp", &smp_str,
        "-m", "2G",
        "-cdrom", iso.to_str().unwrap(),
        "-boot", "d",
        // Stage-2: ROOT + HOME disks. The kernel identifies each by the
        // virtio-blk serial (oxide-root / oxide-home) via GET_ID.
        "-drive", &format!("if=none,id=root,format=raw,file={}", root_img.display()),
        "-device", "virtio-blk-pci,drive=root,bus=pcie.0,serial=oxide-root",
        "-drive", &format!("if=none,id=home,format=raw,file={}", home_img.display()),
        "-device", "virtio-blk-pci,drive=home,bus=pcie.0,serial=oxide-home",
        "-netdev", netdev.as_str(),
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
        // F458: virtio-mouse (relative pointer) → /dev/input/event1. Relative
        // (not absolute/tablet) so QMP input-send-event works headless.
        "-device", "virtio-mouse-pci,id=ptr0,bus=pcie.0",
        // D3.1: virtio-rng entropy source. The kernel seeds its RNG from
        // this at boot and backs /dev/hwrng with it.
        "-device", "virtio-rng-pci,bus=pcie.0,disable-legacy=on",
        // D3.3: virtio-vsock (modern id 0x1053). guest-cid=3; the host
        // peer is always CID 2. Needs /dev/vhost-vsock on the host.
        "-device", "vhost-vsock-pci,guest-cid=3,disable-legacy=on,bus=pcie.0",
        // F454: virtio-snd (modern id 0x1059). Null audio backend is enough
        // for the CONTROLQ probe (config harvest + PCM_INFO); PR-C swaps to
        // a wav backend to capture real PCM output.
        "-audiodev", "none,id=snd0",
        "-device", "virtio-sound-pci,audiodev=snd0,disable-legacy=on,bus=pcie.0",
        // D3.5: NVMe controller + its scratch backing disk (drv-nvme brings
        // it up, registers nvme0n1, self-tests an LBA-0 read).
        "-drive", nvme_drive.as_str(),
        "-device", "nvme,serial=oxnvme,drive=nvm0,bus=pcie.0",
        // D3.6: AHCI HBA + a SATA disk on it. drv-ahci enumerates the
        // ich9-ahci controller (class 0x010601), brings up port 0, registers
        // sata0, and self-tests an LBA-0 read.
        "-device", "ich9-ahci,id=ahci,bus=pcie.0",
        "-drive", ahci_drive.as_str(),
        "-device", "ide-hd,drive=sata0,bus=ahci.0",
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
