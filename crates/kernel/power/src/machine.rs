// The irreversible half: driver shutdown, then the per-arch machine
// transition, matching Linux's restart/halt/power-off machine ops per arch.
//
// x86_64: POWER_OFF → QEMU/Bochs ACPI shutdown port 0x604 = 0x2000; RESTART →
//   triple fault via a zero IDTR + int3; HALT → `hlt` forever.
// aarch64: POWER_OFF → PSCI SYSTEM_OFF; RESTART → PSCI SYSTEM_RESET; HALT →
//   `wfi` forever.

use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Spinlock, TaskList as PowerListClass};

use crate::decide::{KResult, TerminalCmd};

type DriverShutdownHook = fn();

static DRIVER_SHUTDOWN_HOOK: Spinlock<Option<DriverShutdownHook>, PowerListClass> = Spinlock::new(None);
static DRIVER_SHUTDOWN_DONE: AtomicBool = AtomicBool::new(false);

/// Install the driver-core shutdown pass. `kmain` wires this after drv init so
/// power stays below the driver model in the crate graph.
/// # C: O(1)
pub fn set_driver_shutdown_hook(f: DriverShutdownHook) {
    *DRIVER_SHUTDOWN_HOOK.lock() = Some(f);
}

/// Linux `device_shutdown()` from `kernel_restart_prepare`. Idempotent.
/// # C: O(N_devices)
pub fn shutdown_devices_once() {
    if DRIVER_SHUTDOWN_DONE.swap(true, Ordering::AcqRel) { return; }
    if let Some(h) = *DRIVER_SHUTDOWN_HOOK.lock() { h(); }
}

/// Boot-time init reporter. Real per-arch dispatch lives below;
/// nothing one-time to set up at boot for v1.
/// # SAFETY: caller is the boot path; pre-init; single-CPU.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init() -> KResult<()> { Ok(()) }

/// Halt the calling CPU forever. Emits per-arch parking instruction
/// in a tight loop so the host doesn't burn cycles.
/// # SAFETY: kernel privilege required for hlt/wfi.
/// # C: O(∞)
pub unsafe fn halt() -> ! {
    loop {
        #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
        // SAFETY: hlt parks the core; legal at CPL=0; preserves flags.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
        #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
        // SAFETY: wfi parks the core until any wake event; unprivileged at EL1.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)); }
        #[cfg(not(target_os = "oxide-kernel"))]
        core::hint::spin_loop();
    }
}

/// Reset the machine. Returns only on host (test) builds.
/// x86_64: the reset ladder in `crate::reset` — the FADT-described register,
/// then the keyboard controller, then the chipset reset port, then a triple
/// fault. aarch64: PSCI SYSTEM_RESET (`hvc #0` with x0=0x84000009), which is
/// the platform's single authoritative mechanism and needs no ladder.
/// # SAFETY: clobbers IDT (x86) / traps to EL2 (arm); irreversible.
/// # C: O(1)
pub unsafe fn restart() -> ! {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        // SAFETY: caller validated the reboot request and shut the drivers down; the ladder ends in a rung that never returns.
        unsafe { crate::reset::x86::run_ladder() }
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        // SAFETY: PSCI SMC32 SYSTEM_RESET; QEMU virt + EDK2 honour PSCI; irreversible reset.
        unsafe {
            core::arch::asm!(
                "mov w0, #0x09",
                "movk w0, #0x8400, lsl #16",
                "hvc #0",
                "b   .",
                options(noreturn, nostack)
            );
        }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    // SAFETY: host build path; halt only spin-loops on host with no privileged ops.
    unsafe { halt() }
}

/// Power off the machine. v1 uses QEMU isa-debug-exit (port 0x604,
/// value 0x2000) on x86 — production hardware would walk ACPI FADT
/// PM1A_CNT and write SLP_TYP=_S5 SLP_EN; that is a follow-up. arm64
/// uses PSCI SYSTEM_OFF.
/// # SAFETY: irreversible; clobbers I/O ports / EL2 state.
/// # C: O(1)
pub unsafe fn power_off() -> ! {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        // SAFETY: QEMU + Bochs honor port 0x604 = 0x2000 = ACPI shutdown; on bare metal this is a harmless I/O write that falls through to halt.
        unsafe {
            core::arch::asm!(
                "mov dx, 0x604",
                "mov ax, 0x2000",
                "out dx, ax",
                options(nostack, preserves_flags)
            );
        }
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        // SAFETY: PSCI SMC32 SYSTEM_OFF; QEMU virt + EDK2 honor PSCI; irreversible.
        unsafe {
            core::arch::asm!(
                "mov w0, #0x08",
                "movk w0, #0x8400, lsl #16",
                "hvc #0",
                options(nostack, preserves_flags)
            );
        }
    }
    // SAFETY: power_off only reaches here when the I/O write didn't shut us down (e.g. bare metal w/o ACPI); halt is the safe terminal state.
    unsafe { halt() }
}

/// Perform a terminal transition: shut the drivers down, then transition.
/// Never returns on a kernel build.
/// # SAFETY: caller has validated CAP_SYS_BOOT, the magic pair, and the pid
/// namespace; the transition is irreversible by design.
/// # C: O(N_devices)
pub unsafe fn terminal(cmd: TerminalCmd) -> ! {
    match cmd {
        TerminalCmd::Restart => klog::write_raw(b"power_cmd restart\n"),
        TerminalCmd::PowerOff => klog::write_raw(b"power_cmd poweroff\n"),
        TerminalCmd::Halt => klog::write_raw(b"power_cmd halt\n"),
    }
    shutdown_devices_once();
    match cmd {
        // SAFETY: terminal-state primitive; caller validated CAP_SYS_BOOT + magic per `man 2 reboot`; irreversible by design.
        TerminalCmd::Restart => unsafe { restart() },
        // SAFETY: caller validated CAP_SYS_BOOT + magic; power_off is irreversible per Linux reboot(2) POWER_OFF contract.
        TerminalCmd::PowerOff => unsafe { power_off() },
        // SAFETY: caller validated CAP_SYS_BOOT + magic; halt parks every CPU; the kernel never resumes from this primitive.
        TerminalCmd::Halt => unsafe { halt() },
    }
}

/// `kernel_restart(cmd)` with the `RESTART2` command string. Linux's x86
/// `native_machine_restart(char *__unused)` ignores the string entirely and
/// arm64's PSCI reset handler does the same for every string QEMU virt
/// implements, so it is logged (Linux `pr_emerg("Restarting system with
/// command '%s'\n", cmd)`) and then the ordinary restart runs.
/// # SAFETY: same preconditions as [`terminal`]; irreversible.
/// # C: O(N_devices)
pub unsafe fn restart_with_command(cmd: &[u8]) -> ! {
    klog::write_raw(b"power_cmd restart2 '");
    klog::write_raw(cmd);
    klog::write_raw(b"'\n");
    // SAFETY: caller validated CAP_SYS_BOOT, the magic pair and the pid namespace; RESTART2 is a restart with a machine-specific hint x86 discards.
    unsafe { terminal(TerminalCmd::Restart) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decide::{classify_cmd, RebootAction};
    use crate::uapi::*;
    use core::sync::atomic::AtomicU32;

    static HITS: AtomicU32 = AtomicU32::new(0);
    fn hook() { HITS.fetch_add(1, Ordering::Release); }

    // SAFETY: hosted-test path; init has no preconditions and the host build is a no-op Ok(()).
    #[test] fn init_ok() { unsafe { assert!(init().is_ok()); } }

    #[test]
    fn the_driver_shutdown_pass_runs_exactly_once() {
        // `device_shutdown()` is not re-entrant: HALT after a failed POWER_OFF
        // must not drive every device's ->shutdown a second time.
        set_driver_shutdown_hook(hook);
        shutdown_devices_once();
        shutdown_devices_once();
        shutdown_devices_once();
        assert_eq!(HITS.load(Ordering::Acquire), 1);
        assert!(DRIVER_SHUTDOWN_DONE.load(Ordering::Acquire));
    }

    #[test]
    fn only_terminal_commands_reach_the_machine_layer() {
        // `terminal()` is the sole caller of `shutdown_devices_once`, so this
        // classification IS the "did we shut the drivers down" answer.
        for cmd in [LINUX_REBOOT_CMD_RESTART, LINUX_REBOOT_CMD_POWER_OFF,
                    LINUX_REBOOT_CMD_HALT] {
            assert!(matches!(classify_cmd(cmd), Ok(RebootAction::Terminal(_))));
        }
        assert!(matches!(classify_cmd(LINUX_REBOOT_CMD_RESTART2), Ok(RebootAction::Restart2)));
        for cmd in [LINUX_REBOOT_CMD_CAD_ON, LINUX_REBOOT_CMD_CAD_OFF] {
            assert!(matches!(classify_cmd(cmd), Ok(RebootAction::SetCad(_))));
        }
        for cmd in [LINUX_REBOOT_CMD_KEXEC, LINUX_REBOOT_CMD_SW_SUSPEND, 0xDEAD_BEEF] {
            assert!(classify_cmd(cmd).is_err());
        }
    }
}
