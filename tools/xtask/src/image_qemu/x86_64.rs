use std::process::Command;

use crate::run;

use super::common::{ensure_ahci_extra_img, ensure_ahci_img, ensure_nvme_extra_img, ensure_nvme_img, ensure_virtio_blk_extra_img, ssh_fwd_netdev, which};

const X86_OVMF_CODE: &str = "/usr/share/OVMF/OVMF_CODE.fd";
const X86_OVMF_VARS: &str = "/usr/share/OVMF/OVMF_VARS.fd";

#[derive(Clone, Copy, Eq, PartialEq)]
enum HardwareProfile { Default, NativePci }

impl HardwareProfile {
    fn from_env() -> Result<Self, u8> {
        match std::env::var("OXIDE_QEMU_PROFILE").as_deref() {
            Err(_) | Ok("default") => Ok(Self::Default),
            Ok("native-pci") => Ok(Self::NativePci),
            Ok(value) => {
                eprintln!("xtask grub: unknown OXIDE_QEMU_PROFILE={value}; expected default or native-pci");
                Err(2)
            }
        }
    }

    fn nic_device(self) -> &'static str {
        self.nic_device_for(std::env::var("OXIDE_QEMU_NIC").ok().as_deref())
    }

    fn nic_device_for(self, selector: Option<&str>) -> &'static str {
        match self {
            Self::Default if selector == Some("e1000") =>
                "e1000,netdev=net0,bus=pcie.0",
            Self::Default if selector == Some("e1000e") =>
                "e1000e,netdev=net0,bus=pcie.0",
            Self::Default => "virtio-net-pci,netdev=net0,bus=pcie.0,disable-legacy=on",
            Self::NativePci => "e1000,netdev=net0,bus=pcie.0",
        }
    }

    /// Non-virtio input devices supplied by this hardware profile.
    fn input_devices(self) -> &'static [&'static str] {
        match self {
            Self::Default => &[],
            // Keep these as a named contract rather than anonymous arguments
            // in the QEMU command: this profile is the regression lane for
            // Oxide's PCI xHCI and descriptor-driven USB HID stack.
            Self::NativePci => &[
                "qemu-xhci,id=xhci,bus=pcie.0",
                "usb-kbd,bus=xhci.0",
                "usb-tablet,bus=xhci.0",
            ],
        }
    }
}

fn validate_nic_selector() -> Result<(), u8> {
    match std::env::var("OXIDE_QEMU_NIC").as_deref() {
        Err(_) | Ok("virtio") | Ok("e1000") | Ok("e1000e") => Ok(()),
        Ok(value) => {
            eprintln!("xtask grub: unknown OXIDE_QEMU_NIC={value}; expected virtio, e1000, or e1000e");
            Err(2)
        }
    }
}

fn x86_uefi_vars(blobs: &std::path::Path) -> Result<std::path::PathBuf, u8> {
    let code = std::path::Path::new(X86_OVMF_CODE);
    let seed = std::path::Path::new(X86_OVMF_VARS);
    if !code.is_file() || !seed.is_file() {
        eprintln!("xtask grub: x86 UEFI needs {X86_OVMF_CODE} and {X86_OVMF_VARS}");
        return Err(2);
    }
    let vars = blobs.join("ovmf-x86_64-vars.fd");
    if !vars.is_file() { std::fs::copy(seed, &vars).map_err(|_| 1u8)?; }
    Ok(vars)
}

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
    let args = super::bootargs::kernel_cmdline(arch, &format!("/boot/oxide-{arch}"));
    let cfg = x86_grub_cfg(arch, &args);
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

/// GRUB configuration shared by BIOS and UEFI x86 images.
///
/// The Multiboot framebuffer request remains optional so a broken GOP never
/// blocks serial recovery, but `gfxpayload=keep` makes a valid firmware mode
/// an explicit handoff contract for simpledrm rather than an accidental GRUB
/// default. # C: O(config bytes)
fn x86_grub_cfg(arch: &str, args: &str) -> String {
    format!(
        "set timeout=0\nset default=0\nset gfxpayload=keep\nserial --unit=0 --speed=115200\nterminal_input serial console\nterminal_output serial console\n\n\
         menuentry \"oxide (multiboot2)\" {{\n    \
         multiboot2 /boot/oxide-{arch} {args}\n    \
         boot\n}}\n")
}

/// Boot the GRUB ISO under QEMU. `OXIDE_QEMU_UEFI=1` selects OVMF; the
/// default is SeaBIOS. Both firmware paths enter the same GRUB multiboot2
/// handoff. `native-pci` boots the ext4 rootfs from AHCI and uses e1000 plus
/// an emulated PCI xHCI controller with standard USB keyboard and tablet.
pub(super) fn qemu_run_grub_x86_64(
    repo: &std::path::Path,
    id: Option<&str>,
    iso: &std::path::Path,
    smp: u32,
) -> Result<(), u8> {
    let profile = HardwareProfile::from_env()?;
    validate_nic_selector()?;
    let blobs = crate::buildns::blobs_dir(repo, id);
    let uefi = std::env::var_os("OXIDE_QEMU_UEFI").is_some();
    let ovmf_vars = if uefi { Some(x86_uefi_vars(&blobs)?) } else { None };
    let root_img = blobs.join("root-x86_64.img");
    let home_img = blobs.join("home-x86_64.img");
    // D3.5: NVMe scratch disk for the drv-nvme bring-up.
    let nvme_img = ensure_nvme_img(repo, id, "x86_64");
    let nvme_drive = format!("id=nvm0,if=none,format=raw,file={}", nvme_img.display());
    // D3.6: AHCI/SATA scratch disk for the drv-ahci bring-up.
    let ahci_img = ensure_ahci_img(repo, id, "x86_64");
    let ahci_drive = format!("id=sata0,if=none,format=raw,file={}", ahci_img.display());
    let smp_str = smp.to_string();
    // KVM by default when /dev/kvm exists (a heavy glibc GNOME root is
    // impractically slow under TCG). Force TCG with OXIDE_QEMU_TCG=1 for the
    // timing-sensitive bugs that only repro under emulation.
    let accel = if std::env::var("OXIDE_QEMU_TCG").is_err()
        && std::path::Path::new("/dev/kvm").exists()
    { "kvm" } else { "tcg" };
    // Headless (CI / boot-smoke / login-smoke): a `stdio,signal=off`
    // chardev so piped stdin reaches the guest UART RX byte-for-byte (the
    // login-smoke feeds a FIFO this way). Plain `-serial stdio`
    // line-buffers + handles signals and drops scripted keystrokes.
    // Interactive: mux=on so Ctrl-A C reaches the QEMU monitor.
    let headless = std::env::var("OXIDE_QEMU_HEADLESS").is_ok();
    let gpu_dev = super::common::virtio_gpu_device_arg(None);
    // Local physical-framebuffer proof: make std-VGA the firmware display and
    // omit virtio-gpu so the kernel must consume GRUB's framebuffer handoff.
    // Ordinary desktop/smoke launches keep their unchanged virtio-gpu path.
    let simplefb_only = profile == HardwareProfile::NativePci || std::env::var_os("OXIDE_QEMU_SIMPLEFB").is_some();
    let legacy_vga = if simplefb_only { "std" } else { "none" };
    let uart_chardev = match std::env::var("OXIDE_QEMU_UART_SOCK") {
        Ok(p) if !p.is_empty() => {
            let _ = std::fs::remove_file(&p);
            format!("socket,id=ser0,path={},server=on,wait=off", p)
        }
        _ => if headless {
            "stdio,id=ser0,signal=off".to_string()
        } else {
            "stdio,id=ser0,mux=on,signal=off".to_string()
        },
    };
    // Every launch keeps its serial stream on disk as well as wherever the
    // caller is watching it: a boot's console output is the primary evidence
    // about that boot, and evidence living only in a scrollback cannot be
    // re-read. `serial_log` owns where it goes.
    let (uart_chardev, serial_log) = super::serial_log::with_logfile(uart_chardev, "x86_64");
    if let Some(p) = &serial_log { println!("xtask: serial log -> {}", p.display()); }
    let netdev = ssh_fwd_netdev();
    let nic_device = profile.nic_device();
    let pcap_args = super::common::pcap_filter_args();
    // vhost-vsock guest CID is a HOST-GLOBAL kernel resource: only one qemu on
    // the whole machine may own a given CID. Hardcoding 3 made concurrent boots
    // from DIFFERENT worktrees collide ("vhost-vsock: unable to set guest cid:
    // Address already in use") — worktrees isolate the filesystem, not the CID
    // namespace. Derive a stable per-worktree CID from the repo path (+id) so
    // parallel worktrees coexist; override with OXIDE_QEMU_VSOCK_CID. CIDs 0-2
    // are reserved; the multidev smoke needs a second CID, so pick an even base
    // ≥100 and use base / base+1.
    let vsock_cid: u32 = std::env::var("OXIDE_QEMU_VSOCK_CID").ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| crate::buildns::qemu_vsock_cid(repo, id));
    let vsock_dev = format!("vhost-vsock-pci,guest-cid={vsock_cid},disable-legacy=on,bus=pcie.0");
    let vsock_dev2 = format!("vhost-vsock-pci,guest-cid={},disable-legacy=on,bus=pcie.0", vsock_cid + 1);
    let pidfile = crate::buildns::qemu_pidfile(repo, id, "x86_64");
    let _ = std::fs::remove_file(&pidfile);
    let mut c = Command::new("qemu-system-x86_64");
    c.args(["-pidfile", pidfile.to_str().unwrap()]);
    if let Some(ref vars) = ovmf_vars {
        c.args([
            "-drive", &format!("if=pflash,format=raw,readonly=on,file={X86_OVMF_CODE}"),
            "-drive", &format!("if=pflash,format=raw,file={}", vars.display()),
        ]);
    }
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
    // OXIDE_QEMU_GDB=1 exposes a gdb stub (no pause) so a wedged/idle SMP boot
    // can be inspected per-CPU (rip/backtrace) when the in-kernel serial-sysrq
    // path can't run. OXIDE_QEMU_GDB=wait also passes -S (start halted) to set
    // breakpoints before the first instruction. The port is per-launch (a fixed
    // 1234 collides across concurrent worktrees); override with OXIDE_QEMU_GDB_PORT.
    if let Ok(g) = std::env::var("OXIDE_QEMU_GDB") {
        if !g.is_empty() {
            let gdb_port: u16 = std::env::var("OXIDE_QEMU_GDB_PORT").ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| crate::buildns::qemu_host_port(repo, id, 0));
            c.args(["-gdb", &format!("tcp::{gdb_port}")]);
            eprintln!("xtask grub: gdb stub on tcp::{gdb_port}");
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
    c.args(&pcap_args);
    c.args([
        "-machine", "q35",
        "-accel", accel,
        "-cpu", "Haswell-v4",
        "-smp", &smp_str,
        "-m", "4G",
        "-cdrom", iso.to_str().unwrap(),
        "-boot", "d",
        "-netdev", netdev.as_str(),
        "-device", nic_device,
        // -vga none: q35 otherwise adds a default std-VGA that becomes the
        // PRIMARY display, so the GTK window shows that (blank — we never
        // drive it) and the virtio-gpu console is a hidden secondary. Removing
        // it makes virtio-gpu THE display, so fbcon's rendered console is what
        // the window shows. (Verified: virtio-gpu fb carries the glyphs.)
        "-vga", legacy_vga,
        // D3.5: NVMe controller + its scratch backing disk (drv-nvme brings
        // it up, registers nvme0n1, self-tests an LBA-0 read).
        "-drive", nvme_drive.as_str(),
        "-device", "nvme,serial=oxnvme,drive=nvm0,bus=pcie.0",
        // D3.6: AHCI HBA + a SATA disk on it. drv-ahci enumerates every
        // implemented ready ATA port and registers each as an sdX disk.
        "-device", "ich9-ahci,id=ahci,bus=pcie.0",
        "-drive", ahci_drive.as_str(),
        "-device", "ide-hd,drive=sata0,bus=ahci.0,serial=oxahci0",
        "-chardev", uart_chardev.as_str(),
        "-serial", "chardev:ser0",
        // GTK window by default so the virtio-gpu console is visible +
        // responsive; OXIDE_QEMU_HEADLESS=1 suppresses for CI/smoke.
        "-display", if headless { "none" } else { "gtk" },
        "-no-reboot",
    ]);
    for device in profile.input_devices() {
        c.args(["-device", device]);
    }
    match profile {
        HardwareProfile::Default => c.args([
            "-drive", &format!("if=none,id=root,format=raw,file={}", root_img.display()),
            "-device", "virtio-blk-pci,drive=root,bus=pcie.0,serial=oxide-root,disable-legacy=on,num-queues=2",
            "-drive", &format!("if=none,id=home,format=raw,file={}", home_img.display()),
            "-device", "virtio-blk-pci,drive=home,bus=pcie.0,serial=oxide-home,disable-legacy=on,num-queues=2",
            "-device", "virtio-keyboard-pci,bus=pcie.0",
            "-device", "virtio-mouse-pci,id=ptr0,bus=pcie.0",
            "-device", "virtio-tablet-pci,id=tablet0,bus=pcie.0",
            "-device", "virtio-rng-pci,bus=pcie.0,disable-legacy=on",
            "-device", vsock_dev.as_str(),
            "-audiodev", "none,id=snd0",
            "-device", "virtio-sound-pci,audiodev=snd0,disable-legacy=on,bus=pcie.0",
        ]),
        HardwareProfile::NativePci => c.args([
            "-device", "ich9-ahci,id=boot-ahci,bus=pcie.0",
            "-drive", &format!("if=none,id=root,format=raw,file={}", root_img.display()),
            "-device", "ide-hd,drive=root,bus=boot-ahci.0,serial=oxide-root",
            "-drive", &format!("if=none,id=home,format=raw,file={}", home_img.display()),
            "-device", "ide-hd,drive=home,bus=boot-ahci.1,serial=oxide-home",
        ]),
    };
    if !simplefb_only {
        c.args(["-device", gpu_dev.as_str()]);
    }
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
        let scratch = ensure_virtio_blk_extra_img(repo, id, "x86_64");
        let drive = format!("if=none,id=blkscratch,format=raw,file={}", scratch.display());
        c.args([
            "-drive", drive.as_str(),
            "-device", "virtio-blk-pci,drive=blkscratch,bus=pcie.0,serial=oxide-scratch,disable-legacy=on,num-queues=2",
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
        let nvme1 = ensure_nvme_extra_img(repo, id, "x86_64");
        let ahci1 = ensure_ahci_extra_img(repo, id, "x86_64");
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
    if std::env::var_os("OXIDE_AHCI_MULTIPORT_SMOKE").is_some() {
        let extra = ensure_ahci_extra_img(repo, id, "x86_64");
        let drive = format!("id=sata-multi,if=none,format=raw,file={}", extra.display());
        c.args([
            "-drive", drive.as_str(),
            "-device", "ide-hd,drive=sata-multi,bus=ahci.1,serial=oxahci-multi",
        ]);
    }
    let firmware = if uefi { "OVMF" } else { "SeaBIOS" };
    let profile_name = match profile { HardwareProfile::Default => "default", HardwareProfile::NativePci => "native-pci" };
    eprintln!("xtask grub: launching qemu ({firmware}→GRUB→multiboot2), profile={profile_name}, smp={smp}, accel={accel}, headless={headless}");
    run(c)
}

#[cfg(test)]
mod tests {
    use super::{HardwareProfile, x86_grub_cfg};

    #[test]
    fn native_profile_selects_the_native_pci_e1000() {
        assert_eq!(HardwareProfile::NativePci.nic_device(), "e1000,netdev=net0,bus=pcie.0");
    }

    #[test]
    fn default_profile_can_select_the_82574e_pci_model() {
        assert_eq!(HardwareProfile::Default.nic_device_for(Some("e1000e")), "e1000e,netdev=net0,bus=pcie.0");
    }

    #[test]
    fn native_profile_exercises_pci_xhci_and_standard_usb_hid() {
        assert_eq!(HardwareProfile::Default.input_devices(), &[] as &[&str]);
        assert_eq!(HardwareProfile::NativePci.input_devices(), &[
            "qemu-xhci,id=xhci,bus=pcie.0",
            "usb-kbd,bus=xhci.0",
            "usb-tablet,bus=xhci.0",
        ]);
    }

    #[test]
    fn x86_grub_keeps_the_firmware_framebuffer_but_retains_serial_recovery() {
        let cfg = x86_grub_cfg("x86_64", "root=/dev/root");
        assert!(cfg.contains("set gfxpayload=keep"));
        assert!(cfg.contains("terminal_input serial console"));
        assert!(cfg.contains("terminal_output serial console"));
        assert!(cfg.contains("multiboot2 /boot/oxide-x86_64 root=/dev/root"));
    }
}
