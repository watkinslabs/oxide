use std::process::Command;

use crate::run;

use super::common::{ensure_ahci_img, ensure_nvme_img, ssh_fwd_netdev, which};

/// objcopy the aarch64 kernel ELF → flat arm64 `Image` (arm64 Image
/// header + PE32+/EFI header + MMU trampoline at byte 0). The artifact is
/// what GRUB `linux`, UEFI LoadImage, U-Boot `booti`, and QEMU `-kernel`
/// all load.
pub(super) fn build_arm_image(
    repo: &std::path::Path,
    id: Option<&str>,
    kernel_elf: &std::path::Path,
) -> Result<std::path::PathBuf, u8> {
    let image = crate::buildns::arm_image(repo, id);
    if let Some(p) = image.parent() { let _ = std::fs::create_dir_all(p); }
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
pub(super) fn build_grub_arm_iso(
    repo: &std::path::Path,
    id: Option<&str>,
    image: &std::path::Path,
) -> Result<std::path::PathBuf, u8> {
    use std::fs;
    let mods = repo.join("vendor/grub/arm64-efi");
    if !mods.join("modinfo.sh").exists() {
        eprintln!("xtask grub: vendored arm64-efi modules missing — run tools/fetch-grub.sh");
        return Err(2);
    }
    let stage = crate::buildns::grub_stage(repo, id, "aarch64");
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(stage.join("boot/grub")).map_err(|_| 1u8)?;
    fs::copy(image, stage.join("boot/oxide-aarch64.Image")).map_err(|_| 1u8)?;
    // GRUB's arm64 serial console differs from x86; use the firmware
    // console (OVMF routes it to the PL011 → -serial). `linux` boots our
    // PE Image as an EFI application.
    let cfg = "set timeout=0\nset default=0\nterminal_input console\nterminal_output console\n\n\
               menuentry \"oxide (EFI-stub)\" {\n    \
               linux /boot/oxide-aarch64.Image\n    \
               boot\n}\n";
    fs::write(stage.join("boot/grub/grub.cfg"), cfg).map_err(|_| 1u8)?;
    let iso = crate::buildns::iso_path(repo, id, "aarch64");
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
/// v3+ITS as the kernel expects; root mounts from the root-aarch64.img
/// virtio-blk disk attached below. OXIDE_QEMU_UART_SOCK routes serial to a unix socket (the
/// boot-smoke/login scripts feed scripted keystrokes that way); else
/// headless stdio for CI or a muxed stdio + GTK display interactively.
pub(super) fn qemu_run_aarch64_grub(
    repo: &std::path::Path,
    id: Option<&str>,
    iso: &std::path::Path,
    smp: u32,
) -> Result<(), u8> {
    if which("qemu-system-aarch64").is_none() {
        eprintln!("xtask grub: qemu-system-aarch64 not on PATH; install qemu-system-aarch64.");
        return Err(2);
    }
    let blobs = crate::buildns::blobs_dir(repo, id);
    let ovmf = repo.join("vendor/firmware/ovmf-aarch64.fd");
    let root_img = blobs.join("root-aarch64.img");
    let home_img = blobs.join("home-aarch64.img");
    // D3.5: NVMe scratch disk for the drv-nvme bring-up (lockstep with x86).
    let nvme_img = ensure_nvme_img(repo, id, "aarch64");
    let nvme_drive = format!("id=nvm0,if=none,format=raw,file={}", nvme_img.display());
    // D3.6: AHCI/SATA scratch disk for the drv-ahci bring-up (lockstep w/ x86).
    let ahci_img = ensure_ahci_img(repo, id, "aarch64");
    let ahci_drive = format!("id=sata0,if=none,format=raw,file={}", ahci_img.display());
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
    // Stage-2: ROOT + HOME disks attached as virtio-blk on aarch64 too
    // (lockstep with x86). The kernel identifies each by the virtio-blk
    // serial (oxide-root / oxide-home) via GET_ID.
    let root_drive = format!("if=none,id=root,format=raw,file={}", root_img.display());
    let home_drive = format!("if=none,id=home,format=raw,file={}", home_img.display());
    let netdev = ssh_fwd_netdev();
    let mut c = Command::new("qemu-system-aarch64");
    // OXIDE_QEMU_QMP_SOCK: QMP control socket for the keyboard-login smoke
    // (real virtio-keyboard `send-key` injection) — same as the x86 path.
    let qmp_arg = std::env::var("OXIDE_QEMU_QMP_SOCK").ok().filter(|s| !s.is_empty())
        .map(|s| format!("unix:{s},server,nowait"));
    if let Some(ref q) = qmp_arg {
        c.args(["-qmp", q.as_str()]);
    }
    c.args([
        "-machine", "virt,gic-version=3,its=on",
        "-cpu", "cortex-a72",
        "-smp", &smp_str,
        "-m", "2G",
        "-bios", ovmf.to_str().unwrap(),
        "-cdrom", iso.to_str().unwrap(),
        "-boot", "d",
        "-semihosting-config", "enable=on,target=native",
        "-drive", root_drive.as_str(),
        "-device", "virtio-blk-pci,drive=root,bus=pcie.0,serial=oxide-root,disable-legacy=on",
        "-drive", home_drive.as_str(),
        "-device", "virtio-blk-pci,drive=home,bus=pcie.0,serial=oxide-home,disable-legacy=on",
        "-netdev", netdev.as_str(),
        "-device", "virtio-net-pci,netdev=net0,bus=pcie.0,disable-legacy=on",
        // virtio-gpu scanout + keyboard for the graphical console (fbcon
        // paints here; no GOP on this path). Without them only serial gets
        // output and the GTK window stays blank.
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
        // D3.5: NVMe controller + scratch backing disk (lockstep with x86).
        "-drive", nvme_drive.as_str(),
        "-device", "nvme,serial=oxnvme,drive=nvm0,bus=pcie.0",
        // D3.6: AHCI HBA + a SATA disk on it (lockstep with x86). drv-ahci
        // enumerates the ich9-ahci controller, brings up port 0, registers
        // sata0, and self-tests an LBA-0 read.
        "-device", "ich9-ahci,id=ahci,bus=pcie.0",
        "-drive", ahci_drive.as_str(),
        "-device", "ide-hd,drive=sata0,bus=ahci.0",
        "-chardev", uart_chardev.as_str(),
        "-serial", "chardev:ser0",
        "-display", if headless { "none" } else { "gtk" },
        "-no-reboot",
    ]);
    eprintln!("xtask grub: launching qemu-system-aarch64 (OVMF→GRUB→EFI-stub), smp={smp}, headless={headless}");
    run(c)
}
