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

/// VT the early root shell runs on by default.
///
/// Upstream systemd's default, and it is the default for a reason: the serial
/// line gets a `serial-getty` generated from `/sys/class/tty/console/active`,
/// and two units cannot own one line. The shell stays one Alt-F9 away on the
/// screen, and the serial line carries the kernel log plus a normal login —
/// which is what a serial-console machine looks like.
const DEBUG_SHELL_TTY: &str = "tty9";

/// Device node the serial line publishes as, on both arches.
const SERIAL_DEVNODE: &str = "ttyS0";

/// The `serial-getty` instance the kernel's console list makes systemd
/// generate. A run that wants the serial line for something else has to say
/// so, because that generator will otherwise start a login on it.
const SERIAL_GETTY_UNIT: &str = "serial-getty@ttyS0.service";

/// Does this run want the root shell on the SERIAL line instead of a VT?
///
/// Every in-guest probe harness in `tools/` drives that shell over the serial
/// FIFO — typing a command and waiting for its output is how they ask the
/// running system anything. A login prompt there instead swallows the command
/// as a username, so a run that needs the control plane asks for it and gets
/// the getty masked in the same breath: one line, one owner.
fn serial_shell_requested() -> bool {
    std::env::var("OXIDE_SERIAL_SHELL").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// The debug-shell parameters this run carries: which tty, and whether the
/// login that would otherwise own it is masked. # C: O(1)
fn debug_shell_params() -> String {
    if serial_shell_requested() {
        format!("systemd.debug_shell={SERIAL_DEVNODE} systemd.mask={SERIAL_GETTY_UNIT}")
    } else {
        format!("systemd.debug_shell={DEBUG_SHELL_TTY}")
    }
}

/// Does the bootloader prepend `BOOT_IMAGE=<path>` to the line by itself?
///
/// The `linux` command does (observed in the guest's `/proc/cmdline`), the
/// `multiboot2` command does not — it passes the arguments verbatim. Adding
/// our own on the arm side produced the parameter twice.
fn bootloader_supplies_boot_image(arch: &str) -> bool { arch == "aarch64" }

/// Kernel parameters passed by the bootloader for `arch`, loading
/// `image_path`.
///
/// `console=` order is load-bearing: a printk console is registered per token
/// and the LAST one backs `/dev/console`. **The VT goes last, because the VT is
/// the console** — it is the screen a person is looking at, and the init
/// system's status output (`[  OK  ] Started ...`) belongs there.
///
/// Serial is not the console. It is the mirror: it is still a registered printk
/// console, so every kernel message reaches it, which is what makes a boot
/// readable after the fact and scrapeable by tooling. Ordering it last was
/// tried and is wrong — it takes the status output off the screen.
/// One trailing space so the caller's format string stays readable whether or
/// not extra parameters were supplied. # C: O(len)
fn alloc_extra(value: &str) -> String { format!("{value} ") }

/// Kernel parameters EVERY boot carries, so a serial log is a normal property
/// of running this image rather than something a caller has to remember to ask
/// for. This is how a distribution is configured for a serial console, plus
/// the `earlycon` a development image wants:
///
/// `earlycon` brings a console up before device init, so the pre-console
/// window is not invisible; the registering serial console then replays what
/// the ring already holds, so the log starts at the beginning either way.
/// `printk.time=1` stamps each line, which is what distinguishes a slow step
/// from a stuck one.
///
/// Deliberately NOT here: `initcall_debug` and `ignore_loglevel` change how
/// much a boot prints and how fast it runs, and a default that does not match
/// a normal boot is a default that hides the bugs only a normal boot has.
pub(super) const KERNEL_CONSOLE_PARAMS: &str = "earlycon printk.time=1";

/// What makes the serial log carry the WHOLE boot, not just the kernel's half.
///
/// `/dev/console` is one device, and on this image it is the VT — the screen
/// is where a person watches a boot. Every userspace log line therefore goes
/// to the screen and NOTHING userspace writes reaches the serial line, which
/// is why a serial capture goes quiet the moment journald takes over from
/// early kmsg logging: measured at 3.5 s of boot, with the machine still
/// running perfectly. `log_target=console` does not change that — it selects
/// which device, and that device is still the VT.
///
/// Routing the journal through `/dev/kmsg` instead puts userspace records into
/// the kernel ring, and the ring fans out to EVERY registered console. The
/// screen keeps its status output and the serial capture becomes the complete
/// boot: kernel and userspace, one ordered stream, timestamped, greppable
/// after the fact. That is the property every diagnosis in this repository
/// depends on, so it is a permanent part of the line rather than a debug
/// preset a caller has to remember.
pub(super) const USERSPACE_CONSOLE_PARAMS: &str =
    "systemd.log_target=kmsg systemd.journald.forward_to_kmsg=1";

/// The magic-SysRq enable mask this image runs with.
///
/// The kernel now ENFORCES `kernel.sysrq`, and the distribution configuration
/// in the composed image sets it to a value that permits neither the task dump
/// nor the per-CPU dump. Those two are how a wedged boot is diagnosed here —
/// the smoke gate types them at a guest that stopped answering — so an image
/// built to be debugged asks for all of them. A production configuration would
/// not, which is exactly why this is a property of the boot line rather than
/// of the kernel's default.
///
/// `sysctl.kernel.sysrq=1` alone is NOT enough and was measured not to be: the
/// image's own `/usr/lib/sysctl.d` runs after it and lowers the mask again, so
/// a task dump typed at a wedged guest answered `[sysrq] this operation is
/// disabled by kernel.sysrq`. `sysrq_always_enabled` is the kernel-side
/// parameter userspace cannot overwrite, and it is what actually keeps the
/// channel open.
pub(super) const SYSRQ_PARAMS: &str = "sysctl.kernel.sysrq=1 sysrq_always_enabled";

/// How this image runs the mandatory-access-control module.
///
/// **This is not `selinux=0`.** The module is enabled, the distribution's own
/// policy is loaded, contexts are resolved and every decision is computed and
/// reported — `enforcing=0` changes only what happens to a denial, which is
/// the same parameter a real system uses to bring a new policy up before
/// trusting it.
///
/// It is here because the check points are not yet complete: the file and
/// directory paths ask the policy, most other object classes do not, and an
/// object whose label has not been resolved is unlabeled. Enforcing against a
/// partial set of checks would refuse operations the policy permits, which
/// tells us nothing about the policy and everything about the missing wiring.
/// The parameter comes off when the remaining classes are wired, and until
/// then a boot that reaches userspace with a real policy loaded is the thing
/// being measured.
pub(super) const SELINUX_PARAMS: &str = "enforcing=0";

/// Kernel parameters that make a boot narrate itself, for the case the set
/// exists to serve: a boot that never completes and produces nothing to
/// diagnose with.
///
/// `keep_bootcon` stops the boot console being handed over and dropped when
/// the real console registers; `initcall_debug` makes each init step name
/// itself before it runs, so a step that hangs is named; `ignore_loglevel`
/// prints every record regardless of level.
pub(super) const KERNEL_DEBUG_PARAMS: &str =
    "keep_bootcon initcall_debug ignore_loglevel";

/// Userspace parameters for the same case: a service that fails during boot
/// cannot be restarted to observe it, because restarting is the one thing that
/// changes the state under investigation.
pub(super) const USERSPACE_DEBUG_PARAMS: &str =
    "systemd.log_level=debug systemd.log_target=console systemd.journald.forward_to_console=1";

/// Extra parameters this run asks for. `OXIDE_CMDLINE_DEBUG=1` prepends the
/// debug preset; `OXIDE_CMDLINE_EXTRA` appends anything else, so a caller adds
/// a parameter without editing a script and without losing the preset.
fn extra_params() -> String {
    let mut out = String::new();
    if std::env::var("OXIDE_CMDLINE_DEBUG").is_ok_and(|v| !v.is_empty() && v != "0") {
        out.push_str(KERNEL_DEBUG_PARAMS);
        out.push(' ');
        out.push_str(USERSPACE_DEBUG_PARAMS);
        out.push(' ');
    }
    if let Ok(v) = std::env::var("OXIDE_CMDLINE_EXTRA") {
        if !v.is_empty() { out.push_str(&alloc_extra(&v)); }
    }
    out
}

pub(super) fn kernel_cmdline(arch: &str, image_path: &str) -> String {
    kernel_cmdline_for_root(arch, image_path, "/dev/vda")
}

/// Compose the boot line for an explicit, already-modelled root device.
/// # C: O(command-line length)
pub(super) fn kernel_cmdline_for_root(arch: &str, image_path: &str, root: &str) -> String {
    let ser = serial_console(arch);
    let shell = debug_shell_params();
    let boot_image = if bootloader_supplies_boot_image(arch) {
        String::new()
    } else {
        format!("BOOT_IMAGE={image_path} ")
    };
    let extra = extra_params();
    // No `quiet`: the parameter is honoured now, and a line that asks for
    // silence while every consumer expects a talkative boot is a line that
    // lies. A boot that wants it can pass it through OXIDE_CMDLINE_EXTRA.
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

#[cfg(test)]
mod tests {
    use super::{kernel_cmdline, serial_console, KERNEL_CONSOLE_PARAMS, KERNEL_DEBUG_PARAMS,
                USERSPACE_CONSOLE_PARAMS, USERSPACE_DEBUG_PARAMS};
    use std::sync::Mutex;

    // The composer reads process environment; these tests mutate it.
    static ENV: Mutex<()> = Mutex::new(());

    /// Ownership of the process environment for a case that only READS the
    /// composed line. The composer reads the environment on every call, so a
    /// sibling that sets a variable mid-call changes what this case sees --
    /// which is how a case asserting the two arches compose identically saw a
    /// debug preset on one of them.
    fn env_held() -> std::sync::MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        for (k, v) in vars {
            match v { Some(v) => std::env::set_var(k, v), None => std::env::remove_var(k) }
        }
        f();
        for (k, _) in vars { std::env::remove_var(k); }
    }

    /// Both arches carry the identical parameter set; only the console device
    /// name and who supplies `BOOT_IMAGE=` differ. Guards the drift this
    /// module removes (the arm line previously carried neither `root=`, `rw`,
    /// nor any `systemd.*` parameter).
    #[test]
    fn arches_carry_the_same_parameters() {
        let _env = env_held();
        let x = kernel_cmdline("x86_64", "/boot/oxide-x86_64");
        let a = kernel_cmdline("aarch64", "/boot/oxide-aarch64.Image");
        let x_rest = x.strip_prefix("BOOT_IMAGE=/boot/oxide-x86_64 ").unwrap();
        assert_eq!(x_rest.replace("console=ttyS0", "console=ttyAMA0"), a);
    }

    /// A parameter naming a device PATH must use a node the kernel actually
    /// publishes, not a console class name — the arm debug shell died with
    /// `No such file or directory` on `ttyAMA0`. `/dev/tty1..63` exist on both
    /// arches, so the VT the shell runs on needs no arch spelling at all.
    #[test]
    fn path_valued_parameters_use_the_published_devnode() {
        with_env(&[("OXIDE_SERIAL_SHELL", None), ("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || {
            for arch in ["x86_64", "aarch64"] {
                let line = kernel_cmdline(arch, "/img");
                assert!(line.contains("systemd.debug_shell=tty9"), "{arch}: {line}");
            }
            // ...while the console CLASS stays arch-correct.
            assert!(kernel_cmdline("aarch64", "/img").contains("console=ttyAMA0,115200"));
        });
    }

    /// A run that asks for the serial control plane gets the shell there AND
    /// the login that would otherwise own that line masked, in the same line.
    /// Every in-guest probe harness types into that shell; a getty answering
    /// instead swallows the command as a username, and the harness waits for
    /// output that never comes.
    #[test]
    fn the_serial_control_plane_moves_the_shell_and_masks_the_login() {
        with_env(&[("OXIDE_SERIAL_SHELL", Some("1")), ("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || {
            for arch in ["x86_64", "aarch64"] {
                let line = kernel_cmdline(arch, "/img");
                assert!(line.split(' ').any(|t| t == "systemd.debug_shell=ttyS0"), "{arch}: {line}");
                assert!(line.split(' ').any(|t| t == "systemd.mask=serial-getty@ttyS0.service"),
                    "{arch}: the login must be masked or it takes the line: {line}");
                // The console configuration is unchanged: this moves a shell,
                // not the console.
                assert!(line.contains("console=tty0 "), "{arch}: {line}");
            }
        });
    }

    /// ...and an explicit zero is a request for the default, not a truthy
    /// string that happens to be set.
    #[test]
    fn an_explicit_zero_keeps_the_login_on_the_serial_line() {
        with_env(&[("OXIDE_SERIAL_SHELL", Some("0")), ("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || {
            let line = kernel_cmdline("x86_64", "/img");
            assert!(line.contains("systemd.debug_shell=tty9"), "{line}");
            assert!(!line.contains("systemd.mask=serial-getty"), "{line}");
        });
    }

    /// The early root shell must not sit on the serial line. The kernel reports
    /// that line in `/sys/class/tty/console/active`, so systemd generates a
    /// `serial-getty` for it; one tty cannot have two owners, and the shell
    /// squatting there is why the serial line had no login prompt.
    #[test]
    fn the_debug_shell_does_not_squat_on_the_serial_line() {
        with_env(&[("OXIDE_SERIAL_SHELL", None), ("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || {
            for (arch, ser) in [("x86_64", "ttyS0"), ("aarch64", "ttyAMA0")] {
                let line = kernel_cmdline(arch, "/img");
                for name in [ser, "ttyS0"] {
                    assert!(!line.contains(&format!("systemd.debug_shell={name}")),
                        "{arch}: the generated serial-getty owns this line: {line}");
                }
                assert!(line.contains("systemd.debug_shell="), "{arch}: {line}");
            }
        });
    }

    /// `BOOT_IMAGE=` comes from exactly one place per arch, never both: the
    /// `linux` command prepends it, the `multiboot2` command does not.
    #[test]
    fn boot_image_is_never_duplicated() {
        let _env = env_held();
        assert_eq!(kernel_cmdline("x86_64", "/i").matches("BOOT_IMAGE=").count(), 1);
        assert_eq!(kernel_cmdline("aarch64", "/i").matches("BOOT_IMAGE=").count(), 0,
                   "the arm bootloader adds this itself");
    }

    #[test]
    fn serial_console_names_match_the_uart_each_arch_programs() {
        let _env = env_held();
        assert_eq!(serial_console("x86_64"), "ttyS0");
        assert_eq!(serial_console("aarch64"), "ttyAMA0");
    }

    /// `console=` order decides `/dev/console`: the VT token must come last on
    /// both arches so the preferred console matches across the lockstep gate.
    #[test]
    fn vt_console_token_is_last_on_both_arches() {
        let _env = env_held();
        for arch in ["x86_64", "aarch64"] {
            let line = kernel_cmdline(arch, "/img");
            let last = line.rmatch_indices("console=").next().unwrap().0;
            assert!(line[last..].starts_with("console=tty0 "),
                "{arch}: /dev/console must be the VT — the screen is the console: {line}");
        }
    }

    /// The marker the cmdline-propagation gate greps for in `/proc/cmdline`.
    #[test]
    fn carries_the_propagation_marker() {
        let _env = env_held();
        for arch in ["x86_64", "aarch64"] {
            assert!(kernel_cmdline(arch, "/img").contains("oxide.bootargs=grub"));
        }
    }

    #[test]
    fn disposable_boot_image_does_not_wait_for_flatpak_network_setup() {
        let _env = env_held();
        for arch in ["x86_64", "aarch64"] {
            let line = kernel_cmdline(arch, "/img");
            assert!(line.contains("systemd.mask=flatpak-add-fedora-repos.service"),
                "{arch}: disposable image must not block boot on a remote add: {line}");
        }
    }

    /// The debug preset is what a caller passes to see a hang, so each
    /// parameter is named HERE rather than read back out of the constant
    /// under test: a check derived from its own subject cannot notice the
    /// subject losing a member. Dropping `earlycon` from the preset left this
    /// green until the list was spelled out.
    #[test]
    fn the_debug_preset_reaches_the_line() {
        const REQUIRED: [&str; 6] = [
            "keep_bootcon", "initcall_debug", "ignore_loglevel",
            "systemd.log_level=debug", "systemd.log_target=console",
            "systemd.journald.forward_to_console=1",
        ];
        with_env(&[("OXIDE_CMDLINE_DEBUG", Some("1")), ("OXIDE_CMDLINE_EXTRA", None)], || {
            let line = kernel_cmdline("x86_64", "/img");
            for p in REQUIRED { assert!(line.split(' ').any(|t| t == p), "preset lost {p}: {line}"); }
        });
        // ...and the constants themselves carry exactly those, so a parameter
        // added to one without the other is a mismatch rather than a silent
        // widening of what a debug boot means.
        let declared: usize = KERNEL_DEBUG_PARAMS.split(' ').count() + USERSPACE_DEBUG_PARAMS.split(' ').count();
        assert_eq!(declared, REQUIRED.len(), "preset changed without updating what a debug boot must carry");
    }

    /// Off by default: a boot that did not ask for the narrating preset must
    /// not get it, or the smoke gate measures a different kernel than the one
    /// it names. The console parameters are NOT part of that preset — they are
    /// what every boot carries.
    #[test]
    fn the_preset_is_absent_unless_asked_for() {
        with_env(&[("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || {
            let line = kernel_cmdline("x86_64", "/img");
            assert!(!line.contains("initcall_debug"), "{line}");
            assert!(!line.contains("ignore_loglevel"), "{line}");
            assert!(!line.contains("keep_bootcon"), "{line}");
        });
    }

    /// The dumps the smoke gate types at a wedged guest are mask-gated in the
    /// kernel, and the image's own configuration would refuse them. A boot
    /// that cannot be asked what it is stuck on is a boot nobody can diagnose.
    #[test]
    fn every_boot_asks_for_the_sysrq_commands_it_is_debugged_with() {
        with_env(&[("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || {
            for arch in ["x86_64", "aarch64"] {
                let line = kernel_cmdline(arch, "/img");
                assert!(line.split(' ').any(|t| t == "sysctl.kernel.sysrq=1"), "{arch}: {line}");
                // The sysctl is overwritten by the image's own drop-ins; the
                // kernel parameter is the half that survives them.
                assert!(line.split(' ').any(|t| t == "sysrq_always_enabled"), "{arch}: {line}");
            }
        });
    }

    /// The other half of that property: the serial log must carry USERSPACE
    /// too. `/dev/console` is the VT, so a userspace record only reaches the
    /// serial line by going through the kernel ring, which fans out to every
    /// registered console. Without this the capture goes quiet at ~3.5 s, the
    /// moment journald takes over from early kmsg logging — with the machine
    /// still running, which reads exactly like a hang and is not one.
    #[test]
    fn every_boot_routes_userspace_logging_through_the_kernel_ring() {
        with_env(&[("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || {
            for arch in ["x86_64", "aarch64"] {
                let line = kernel_cmdline(arch, "/img");
                for p in ["systemd.log_target=kmsg", "systemd.journald.forward_to_kmsg=1"] {
                    assert!(line.split(' ').any(|t| t == p), "{arch} lost {p}: {line}");
                }
                // ...without moving /dev/console off the screen to get it.
                let last = line.rmatch_indices("console=").next().unwrap().0;
                assert!(line[last..].starts_with("console=tty0 "), "{arch}: {line}");
            }
        });
        assert_eq!(USERSPACE_CONSOLE_PARAMS.split(' ').count(), 2,
            "a parameter joined the always-on userspace set without being declared here");
    }

    /// The property the whole console configuration exists for: a boot nobody
    /// configured still produces a serial log that starts at the beginning.
    /// Every token is named here rather than read from the constant under
    /// test — a check derived from its own subject cannot notice the subject
    /// losing a member.
    #[test]
    fn every_boot_carries_the_console_parameters() {
        with_env(&[("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || {
            for (arch, ser) in [("x86_64", "ttyS0"), ("aarch64", "ttyAMA0")] {
                let line = kernel_cmdline(arch, "/img");
                for p in ["earlycon", "printk.time=1", &format!("console={ser},115200"), "console=tty0"] {
                    assert!(line.split(' ').any(|t| t == p), "{arch} lost {p}: {line}");
                }
            }
        });
        assert_eq!(
            KERNEL_CONSOLE_PARAMS.split(' ').count(), 2,
            "a parameter joined the always-on set without being declared here",
        );
    }

    /// A caller adding one parameter must not have to choose between it and
    /// the preset — that choice is what makes people edit scripts.
    #[test]
    fn extra_parameters_compose_with_the_preset() {
        with_env(&[("OXIDE_CMDLINE_DEBUG", Some("1")), ("OXIDE_CMDLINE_EXTRA", Some("loglevel=8 panic=30"))], || {
            let line = kernel_cmdline("aarch64", "/img");
            assert!(line.split(' ').any(|t| t == "initcall_debug"), "{line}");
            assert!(line.split(' ').any(|t| t == "loglevel=8"), "{line}");
            assert!(line.split(' ').any(|t| t == "panic=30"), "{line}");
        });
    }

    /// `OXIDE_CMDLINE_DEBUG=0` is a request for the plain line, not a truthy
    /// string that happens to be set.
    #[test]
    fn an_explicit_zero_disables_the_preset() {
        with_env(&[("OXIDE_CMDLINE_DEBUG", Some("0")), ("OXIDE_CMDLINE_EXTRA", None)], || {
            assert!(!kernel_cmdline("x86_64", "/img").contains("initcall_debug"));
        });
    }

    /// `quiet` is honoured now, so the default line must not assert it while
    /// every consumer of that line expects a talkative boot.
    #[test]
    fn the_default_line_does_not_ask_for_silence() {
        with_env(&[("OXIDE_CMDLINE_DEBUG", None), ("OXIDE_CMDLINE_EXTRA", None)], || {
            for arch in ["x86_64", "aarch64"] {
                let line = kernel_cmdline(arch, "/img");
                assert!(!line.split(' ').any(|t| t == "quiet"), "{arch}: {line}");
            }
        });
    }
}

#[cfg(test)]
mod selinux_params_tests {
    use super::{kernel_cmdline, SELINUX_PARAMS};

    #[test]
    fn both_arches_carry_the_permissive_parameter() {
        for arch in ["x86_64", "aarch64"] {
            let line = kernel_cmdline(arch, "/boot/oxide.elf");
            assert!(line.split(' ').any(|t| t == SELINUX_PARAMS),
                    "{arch} line lost the parameter: {line}");
        }
    }

    #[test]
    fn the_module_is_never_disabled_by_the_boot_line() {
        // Disabling the module would mean the boot no longer matches the
        // distribution it is built from, which is the whole point of loading
        // its policy at all. Permissive is a mode; disabled is an absence.
        for arch in ["x86_64", "aarch64"] {
            let line = kernel_cmdline(arch, "/boot/oxide.elf");
            assert!(!line.contains("selinux=0"), "{arch}: {line}");
            assert!(!line.split(' ').any(|t| t == "selinux=off"), "{arch}: {line}");
        }
    }

    #[test]
    fn the_parameter_asks_for_permissive_and_not_for_a_disable() {
        assert_eq!(SELINUX_PARAMS, "enforcing=0");
    }
}
