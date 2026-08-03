// Boot command line the image pipeline hands the bootloader, in ONE place.
//
// x86_64 (GRUB multiboot2) and aarch64 (GRUB `linux` / EFI LoadOptions) must
// pass the SAME kernel parameters — the arches differ only in the serial
// console device name (`ttyS0` 16550 vs `ttyAMA0` PL011) and the kernel image
// path. Keeping two hand-copied literals let the arm line drift (it carried
// neither `root=`, `rw`, nor any `systemd.*` parameter); the builder below is
// the single source of truth both callers format.

/// Serial console device name per arch, per Linux tty naming: 16550 lines are
/// `ttyS*`, PL011 lines are `ttyAMA*`. This is the name `console=` takes.
pub(super) fn serial_console(arch: &str) -> &'static str {
    if arch == "aarch64" { "ttyAMA0" } else { "ttyS0" }
}

/// Device node name of the boot serial line as this kernel actually publishes
/// it. The serial tty is `/dev/ttyS0` on BOTH arches — on aarch64 that node is
/// the PL011 — so parameters naming a *path* (rather than a console class)
/// must use this, not [`serial_console`]. Pointing one at `ttyAMA0` gets
/// `No such file or directory` from anything that opens it.
fn serial_devnode(_arch: &str) -> &'static str { "ttyS0" }

/// Does the bootloader prepend `BOOT_IMAGE=<path>` to the line by itself?
///
/// The `linux` command does (observed in the guest's `/proc/cmdline`), the
/// `multiboot2` command does not — it passes the arguments verbatim. Adding
/// our own on the arm side produced the parameter twice.
fn bootloader_supplies_boot_image(arch: &str) -> bool { arch == "aarch64" }

/// Kernel parameters passed by the bootloader for `arch`, loading
/// `image_path`.
///
/// `console=` order is load-bearing: Linux registers a printk console per
/// token and the LAST one backs `/dev/console`, so serial-then-VT keeps the
/// serial log while the VT stays the interactive console — identical on both
/// arches.
/// One trailing space so the caller's format string stays readable whether or
/// not extra parameters were supplied. # C: O(len)
fn alloc_extra(value: &str) -> String { format!("{value} ") }

pub(super) fn kernel_cmdline(arch: &str, image_path: &str) -> String {
    let ser = serial_console(arch);
    let dev = serial_devnode(arch);
    let boot_image = if bootloader_supplies_boot_image(arch) {
        String::new()
    } else {
        format!("BOOT_IMAGE={image_path} ")
    };
    // Extra parameters for one run, e.g. raising a service's log level from
    // boot (`systemd.setenv=SYSTEMD_LOG_LEVEL=debug`). A service that misbehaves
    // only during boot cannot be restarted to observe it: restarting is the one
    // thing that changes the state under investigation.
    let extra = match std::env::var("OXIDE_CMDLINE_EXTRA") {
        Ok(v) if !v.is_empty() => alloc_extra(&v),
        _ => String::new(),
    };
    format!(
        "{boot_image}root=/dev/oxide0 rw quiet {extra}\
         console={ser},115200 console=tty0 \
         systemd.mask=firewalld.service systemd.mask=chronyd.service \
         systemd.mask=ModemManager.service systemd.mask=plymouth-start.service \
         systemd.mask=NetworkManager-wait-online.service \
         systemd.debug_shell={dev} oxide.bootargs=grub"
    )
}

#[cfg(test)]
mod tests {
    use super::{kernel_cmdline, serial_console};

    /// Both arches carry the identical parameter set; only the console device
    /// name and who supplies `BOOT_IMAGE=` differ. Guards the drift this
    /// module removes (the arm line previously carried neither `root=`, `rw`,
    /// nor any `systemd.*` parameter).
    #[test]
    fn arches_carry_the_same_parameters() {
        let x = kernel_cmdline("x86_64", "/boot/oxide-x86_64");
        let a = kernel_cmdline("aarch64", "/boot/oxide-aarch64.Image");
        let x_rest = x.strip_prefix("BOOT_IMAGE=/boot/oxide-x86_64 ").unwrap();
        assert_eq!(x_rest.replace("console=ttyS0", "console=ttyAMA0"), a);
    }

    /// A parameter naming a device PATH must use the node the kernel actually
    /// publishes (`ttyS0` on both arches), not the console class name — the
    /// arm debug shell died with `No such file or directory` on `ttyAMA0`.
    #[test]
    fn path_valued_parameters_use_the_published_devnode() {
        for arch in ["x86_64", "aarch64"] {
            let line = kernel_cmdline(arch, "/img");
            assert!(line.contains("systemd.debug_shell=ttyS0"), "{arch}: {line}");
        }
        // ...while the console CLASS stays arch-correct.
        assert!(kernel_cmdline("aarch64", "/img").contains("console=ttyAMA0,115200"));
    }

    /// `BOOT_IMAGE=` comes from exactly one place per arch, never both: the
    /// `linux` command prepends it, the `multiboot2` command does not.
    #[test]
    fn boot_image_is_never_duplicated() {
        assert_eq!(kernel_cmdline("x86_64", "/i").matches("BOOT_IMAGE=").count(), 1);
        assert_eq!(kernel_cmdline("aarch64", "/i").matches("BOOT_IMAGE=").count(), 0,
                   "the arm bootloader adds this itself");
    }

    #[test]
    fn serial_console_names_match_the_uart_each_arch_programs() {
        assert_eq!(serial_console("x86_64"), "ttyS0");
        assert_eq!(serial_console("aarch64"), "ttyAMA0");
    }

    /// `console=` order decides `/dev/console`: the VT token must come last on
    /// both arches so the preferred console matches across the lockstep gate.
    #[test]
    fn vt_console_token_is_last_on_both_arches() {
        for arch in ["x86_64", "aarch64"] {
            let line = kernel_cmdline(arch, "/img");
            let last = line.rmatch_indices("console=").next().unwrap().0;
            assert!(line[last..].starts_with("console=tty0 "), "{arch}: {line}");
        }
    }

    /// The marker the cmdline-propagation gate greps for in `/proc/cmdline`.
    #[test]
    fn carries_the_propagation_marker() {
        for arch in ["x86_64", "aarch64"] {
            assert!(kernel_cmdline(arch, "/img").contains("oxide.bootargs=grub"));
        }
    }
}
