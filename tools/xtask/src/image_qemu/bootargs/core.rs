// Boot command line the image pipeline hands the bootloader, in ONE place.
use super::serial_device_name;

const DEBUG_SHELL_TTY: &str = "tty9";

fn serial_shell_requested() -> bool { std::env::var("OXIDE_SERIAL_SHELL").is_ok_and(|v| !v.is_empty() && v != "0") }

fn debug_shell_params(arch: &str) -> String {
    if serial_shell_requested() { let serial = serial_device_name(arch); format!("systemd.debug_shell={serial} systemd.mask=serial-getty@{serial}.service") }
    else { format!("systemd.debug_shell={DEBUG_SHELL_TTY}") }
}

fn bootloader_supplies_boot_image(arch: &str) -> bool { arch == "aarch64" }
fn alloc_extra(value: &str) -> String { format!("{value} ") }

pub(crate) const KERNEL_CONSOLE_PARAMS: &str = "earlycon printk.time=1";
pub(crate) const USERSPACE_CONSOLE_PARAMS: &str = "systemd.log_target=kmsg systemd.journald.forward_to_kmsg=1";
pub(crate) const SYSRQ_PARAMS: &str = "sysctl.kernel.sysrq=1 sysrq_always_enabled";
pub(crate) const SELINUX_PARAMS: &str = "enforcing=0";
pub(crate) const KERNEL_DEBUG_PARAMS: &str = "keep_bootcon initcall_debug ignore_loglevel";
pub(crate) const USERSPACE_DEBUG_PARAMS: &str = "systemd.log_level=debug systemd.log_target=console systemd.journald.forward_to_console=1";

fn extra_params() -> String {
    let mut out = String::new();
    if std::env::var("OXIDE_CMDLINE_DEBUG").is_ok_and(|v| !v.is_empty() && v != "0") {
        out.push_str(KERNEL_DEBUG_PARAMS); out.push(' '); out.push_str(USERSPACE_DEBUG_PARAMS); out.push(' ');
    }
    if let Ok(v) = std::env::var("OXIDE_CMDLINE_EXTRA") { if !v.is_empty() { out.push_str(&alloc_extra(&v)); } }
    out
}

pub(crate) fn kernel_cmdline(arch: &str, image_path: &str) -> String { kernel_cmdline_for_root(arch, image_path, "/dev/vda") }

pub(crate) fn kernel_cmdline_for_root(arch: &str, image_path: &str, root: &str) -> String {
    let ser = serial_device_name(arch);
    let shell = debug_shell_params(arch);
    let boot_image = if bootloader_supplies_boot_image(arch) { String::new() } else { format!("BOOT_IMAGE={image_path} ") };
    let extra = extra_params();
    format!(
        "{boot_image}root={root} rw {KERNEL_CONSOLE_PARAMS} {USERSPACE_CONSOLE_PARAMS} \
         {SYSRQ_PARAMS} {SELINUX_PARAMS} {extra}\
         console={ser},115200 console=tty0 \
         systemd.mask=firewalld.service systemd.mask=chronyd.service \
         systemd.mask=ModemManager.service systemd.mask=plymouth-start.service \
         systemd.mask=NetworkManager-wait-online.service \
         systemd.mask=flatpak-add-fedora-repos.service \
         {shell} oxide.bootargs=grub"
    )
}
