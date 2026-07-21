use std::process::Command;

use crate::run;

use super::common::{ensure_ahci_extra_img, ensure_ahci_img, ensure_nvme_extra_img, ensure_nvme_img, ensure_virtio_blk_extra_img, ssh_fwd_netdev, which};

const ARM_GRUB_REQUIRED_MODULES: [&str; 2] = ["modinfo.sh", "linux.mod"];

fn arm_grub_modules_missing(mods: &std::path::Path) -> Vec<&'static str> {
    ARM_GRUB_REQUIRED_MODULES.into_iter().filter(|name| !mods.join(name).is_file()).collect()
}

/// objcopy the aarch64 kernel ELF → flat arm64 `Image` (arm64 Image
/// header + PE32+/EFI header + MMU trampoline at byte 0). The artifact is
/// what GRUB `linux`, UEFI LoadImage, U-Boot `booti`, and QEMU `-kernel`
/// all load.
pub(crate) fn build_arm_image(
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
    let missing = arm_grub_modules_missing(&mods);
    if !missing.is_empty() {
        eprintln!("xtask grub: incomplete vendored arm64-efi modules (missing {}) — run tools/fetch-vendor.sh", missing.join(", "));
        return Err(2);
    }
    let stage = crate::buildns::grub_stage(repo, id, "aarch64");
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(stage.join("boot/grub")).map_err(|_| 1u8)?;
    fs::copy(image, stage.join("boot/oxide-aarch64.Image")).map_err(|_| 1u8)?;
    // GRUB's arm64 serial console differs from x86; use the firmware
    // console (OVMF routes it to the PL011 → -serial). Keep ttyAMA0 as the
    // last console= entry: Linux console ordering makes that the preferred
    // /dev/console, so early systemd and headless conformance output reach
    // QEMU's serial transport while the VT remains registered for graphics.
    // `linux` boots our PE Image as an EFI application.
    let cfg = "set timeout=0\nset default=0\nterminal_input console\nterminal_output console\n\n\
               menuentry \"oxide (EFI-stub)\" {\n    \
               linux /boot/oxide-aarch64.Image console=tty0 console=ttyAMA0,115200\n    \
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
/// virtio-blk disk attached below.
/// OXIDE_QEMU_UART_SOCK routes serial to a unix socket (the
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
    // Per-launch vhost-vsock guest CID (host-global — see qemu_vsock_cid), so
    // concurrent worktree boots don't collide on a hardcoded CID. cid / cid+1.
    let vsock_cid: u32 = std::env::var("OXIDE_QEMU_VSOCK_CID").ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| crate::buildns::qemu_vsock_cid(repo, id));
    let vsock_dev = format!("vhost-vsock-pci,guest-cid={vsock_cid},disable-legacy=on,bus=pcie.0");
    let vsock_dev2 = format!("vhost-vsock-pci,guest-cid={},disable-legacy=on,bus=pcie.0", vsock_cid + 1);
    let mut c = Command::new("qemu-system-aarch64");
    // Opt-in remote GDB support mirrors the x86 launcher.  `wait` starts
    // halted so an investigator can install breakpoints before firmware runs;
    // any other nonempty value starts normally with a live stub.  Deriving the
    // port from the build namespace keeps concurrent worktrees independent.
    if let Ok(g) = std::env::var("OXIDE_QEMU_GDB") {
        if !g.is_empty() {
            let gdb_port: u16 = std::env::var("OXIDE_QEMU_GDB_PORT").ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| crate::buildns::qemu_host_port(repo, id, 0));
            c.args(["-gdb", &format!("tcp::{gdb_port}")]);
            eprintln!("xtask arm: gdb stub on tcp::{gdb_port}");
            if g == "wait" { c.arg("-S"); }
        }
    }
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
        "-device", vsock_dev.as_str(),
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
        "-device", "ide-hd,drive=sata0,bus=ahci.0,serial=oxahci0",
        "-chardev", uart_chardev.as_str(),
        "-serial", "chardev:ser0",
        "-display", if headless { "none" } else { "gtk" },
        "-no-reboot",
    ]);
    if std::env::var_os("OXIDE_VIRTIO_NET_MULTIDEV_SMOKE").is_some() {
        c.args([
            "-netdev", "user,id=net1",
            "-device", "virtio-net-pci-non-transitional,netdev=net1,bus=pcie.0",
        ]);
    }
    if std::env::var_os("OXIDE_VIRTIO_RNG_REBIND_SMOKE").is_some()
        || std::env::var_os("OXIDE_VIRTIO_PARENT_CHILD_REBIND_SMOKE").is_some() {
        c.args([
            "-device", "virtio-rng-pci,bus=pcie.0,disable-legacy=on",
        ]);
    }
    if std::env::var_os("OXIDE_VIRTIO_BLK_MULTIDEV_SMOKE").is_some() {
        let scratch = ensure_virtio_blk_extra_img(repo, id, "aarch64");
        let drive = format!("if=none,id=blkscratch,format=raw,file={}", scratch.display());
        c.args([
            "-drive", drive.as_str(),
            "-device", "virtio-blk-pci,drive=blkscratch,bus=pcie.0,serial=oxide-scratch,disable-legacy=on",
        ]);
    }
    if std::env::var_os("OXIDE_VIRTIO_SND_MULTIDEV_SMOKE").is_some() {
        c.args([
            "-audiodev", "none,id=snd1",
            "-device", "virtio-sound-pci,audiodev=snd1,disable-legacy=on,bus=pcie.0",
        ]);
    }
    if std::env::var_os("OXIDE_VIRTIO_GPU_MULTIDEV_SMOKE").is_some() {
        c.args([
            "-device", "virtio-gpu-pci,id=gpu1,bus=pcie.0",
        ]);
    }
    if std::env::var_os("OXIDE_VIRTIO_VSOCK_MULTIDEV_SMOKE").is_some() {
        c.args([
            "-device", vsock_dev2.as_str(),
        ]);
    }
    if std::env::var_os("OXIDE_STORAGE_MULTICTRL_SMOKE").is_some() {
        let nvme1 = ensure_nvme_extra_img(repo, id, "aarch64");
        let ahci1 = ensure_ahci_extra_img(repo, id, "aarch64");
        let nvme1_drive = format!("id=nvm1,if=none,format=raw,file={}", nvme1.display());
        let ahci1_drive = format!("id=sata1,if=none,format=raw,file={}", ahci1.display());
        c.args([
            "-drive", nvme1_drive.as_str(),
            "-device", "nvme,serial=oxnvme1,drive=nvm1,bus=pcie.0",
            "-device", "ich9-ahci,id=ahci1,bus=pcie.0",
            "-drive", ahci1_drive.as_str(),
            "-device", "ide-hd,drive=sata1,bus=ahci1.0,serial=oxahci1",
        ]);
    }
    eprintln!("xtask grub: launching qemu-system-aarch64 (OVMF→GRUB→EFI-stub), smp={smp}, headless={headless}");
    run(c)
}

#[cfg(test)]
mod tests {
    use super::arm_grub_modules_missing;
    use std::path::{Path, PathBuf};

    struct Fixture(PathBuf);

    impl Fixture {
        fn modules(&self) -> &Path { &self.0 }
    }

    impl Drop for Fixture {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }

    fn fixture(case: &str, files: &[&str]) -> Fixture {
        let path = std::env::temp_dir().join(format!("oxide-arm-grub-modules-{}-{case}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        for file in files { std::fs::write(path.join(file), b"").unwrap(); }
        Fixture(path)
    }

    #[test]
    fn arm_grub_modules_complete() {
        let f = fixture("complete", &["modinfo.sh", "linux.mod"]);
        assert!(arm_grub_modules_missing(f.modules()).is_empty());
    }

    #[test]
    fn arm_grub_modules_missing_modinfo() {
        let f = fixture("missing-modinfo", &["linux.mod"]);
        assert_eq!(arm_grub_modules_missing(f.modules()), ["modinfo.sh"]);
    }

    #[test]
    fn arm_grub_modules_missing_linux() {
        let f = fixture("missing-linux", &["modinfo.sh"]);
        assert_eq!(arm_grub_modules_missing(f.modules()), ["linux.mod"]);
    }
}
