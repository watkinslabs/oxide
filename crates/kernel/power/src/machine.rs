// The irreversible half: driver shutdown, then the per-arch machine
// transition, matching Linux's restart/halt/power-off machine ops per arch.
//
// x86_64: POWER_OFF → QEMU/Bochs ACPI shutdown port 0x604 = 0x2000; RESTART →
//   triple fault via a zero IDTR + int3; HALT → `hlt` forever.
// aarch64: POWER_OFF → PSCI SYSTEM_OFF; RESTART → PSCI SYSTEM_RESET; HALT →
//   `wfi` forever.

use core::convert::Infallible;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Spinlock, TaskList as PowerListClass};

use crate::decide::{Error, KResult, TerminalCmd};

type DriverShutdownHook = fn();

#[cfg(target_arch = "x86_64")]
type ArchMachine = hal_x86_64::X86MachineOps;
#[cfg(target_arch = "aarch64")]
type ArchMachine = hal_aarch64::ArmMachineOps;

static DRIVER_SHUTDOWN_HOOK: Spinlock<Option<DriverShutdownHook>, PowerListClass> = Spinlock::new(None);
static MACHINE_SHUTDOWN_HOOK: Spinlock<Option<fn()>, PowerListClass> = Spinlock::new(None);
static DRIVER_SHUTDOWN_DONE: AtomicBool = AtomicBool::new(false);

/// Install the driver-core shutdown pass. `kmain` wires this after drv init so
/// power stays below the driver model in the crate graph.
/// # C: O(1)
pub fn set_driver_shutdown_hook(f: DriverShutdownHook) {
    *DRIVER_SHUTDOWN_HOOK.lock() = Some(f);
}

/// Install the architecture-wired secondary-CPU terminal stop. # C: O(1)
pub fn set_machine_shutdown_hook(f: fn()) { *MACHINE_SHUTDOWN_HOOK.lock() = Some(f); }

fn shutdown_machine() {
    let hook = *MACHINE_SHUTDOWN_HOOK.lock();
    if let Some(h) = hook { h(); }
}

/// Linux `device_shutdown()` from `kernel_restart_prepare`. Idempotent.
/// # C: O(N_devices)
pub fn shutdown_devices_once() {
    if DRIVER_SHUTDOWN_DONE.swap(true, Ordering::AcqRel) { return; }
    let hook = *DRIVER_SHUTDOWN_HOOK.lock();
    if let Some(h) = hook { h(); }
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
    // SAFETY: this public endpoint is itself the terminal machine boundary.
    unsafe { <ArchMachine as hal::MachineOps>::halt() }
}

/// Reset the machine. Returns only on host (test) builds.
/// x86_64: the reset ladder in `crate::reset` — the FADT-described register,
/// then the keyboard controller, then the chipset reset port, then a triple
/// fault. aarch64: PSCI SYSTEM_RESET through the firmware-selected conduit,
/// which is the platform's single authoritative mechanism and needs no ladder.
/// # SAFETY: clobbers IDT (x86) / traps to EL2 (arm); irreversible.
/// # C: O(1)
pub unsafe fn restart() -> ! {
    // SAFETY: caller validated the transition; the callback is the kernel's
    // architecture-independent reset policy and the HAL owns its endpoint.
    unsafe { <ArchMachine as hal::MachineOps>::restart(reset_ladder) }
}

/// Power off the machine. x86 consumes the FADT-plus-AML S5 action; arm64
/// uses PSCI SYSTEM_OFF.
/// # SAFETY: irreversible; clobbers I/O ports / EL2 state.
/// # C: O(1)
pub unsafe fn power_off() -> ! {
    // SAFETY: caller validated the transition; the callback is the kernel's
    // firmware policy and the HAL owns the final platform endpoint.
    unsafe { <ArchMachine as hal::MachineOps>::power_off(poweroff_callback) }
}

unsafe fn reset_ladder() -> ! {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        // SAFETY: the terminal owner has already stopped drivers and masked
        // interrupts; the ladder ends in a rung that never returns.
        unsafe { crate::reset::x86::run_ladder() }
    }
    #[cfg(not(all(target_os = "oxide-kernel", target_arch = "x86_64")))]
    {
        // SAFETY: hosted and non-x86 builds have no reset ladder.
        unsafe { <ArchMachine as hal::MachineOps>::halt() }
    }
}

fn poweroff_callback() {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    crate::poweroff::enter_s5();
}

/// Perform a terminal transition: shut the drivers down, then transition.
/// Never returns on a kernel build.
/// # SAFETY: caller has validated CAP_SYS_BOOT, the magic pair, and the pid
/// namespace; the transition is irreversible by design.
/// # C: O(N_devices)
pub unsafe fn terminal_claimed(_claim: &crate::transition::Claim, cmd: TerminalCmd) -> ! {
    match cmd {
        TerminalCmd::Restart => klog::announce("power_cmd restart"),
        TerminalCmd::PowerOff => klog::announce("power_cmd poweroff"),
        TerminalCmd::Halt => klog::announce("power_cmd halt"),
    }
    // Linux snapshots the log in `kernel_restart` / `kernel_power_off`,
    // BEFORE the drivers go down: a dumper whose backend rides on a device
    // has nothing to write to once that device is stopped.
    klog::kmsg_dump(klog::kmsg_dump::REASON_SHUTDOWN);
    shutdown_devices_once();
    // SAFETY: this function is the irreversible terminal boundary.
    // SAFETY: terminal transition owns the irreversible machine boundary.
    unsafe { <ArchMachine as hal::MachineOps>::mask_local_irqs(); }
    shutdown_machine();
    match cmd {
        // SAFETY: terminal-state primitive; caller validated CAP_SYS_BOOT + magic per `man 2 reboot`; irreversible by design.
        TerminalCmd::Restart => unsafe { restart() },
        // SAFETY: caller validated CAP_SYS_BOOT + magic; power_off is irreversible per Linux reboot(2) POWER_OFF contract.
        TerminalCmd::PowerOff => unsafe { power_off() },
        // SAFETY: caller validated CAP_SYS_BOOT + magic; halt parks every CPU; the kernel never resumes from this primitive.
        TerminalCmd::Halt => unsafe { halt() },
    }
}

/// Claim and perform one terminal system transition. # C: O(N_devices)
/// # SAFETY: caller has validated the command's authorization and namespace.
pub unsafe fn terminal(cmd: TerminalCmd) -> KResult<Infallible> {
    let claim = crate::transition::try_claim().ok_or(Error::Busy)?;
    // SAFETY: this wrapper retains the unique transition claim through the
    // irreversible machine endpoint and inherits the caller's authorization.
    unsafe { terminal_claimed(&claim, cmd) }
}

/// `kernel_restart(cmd)` with the `RESTART2` command string. Linux's x86
/// `native_machine_restart(char *__unused)` ignores the string entirely and
/// arm64's PSCI reset handler does the same for every string QEMU virt
/// implements, so it is logged (Linux `pr_emerg("Restarting system with
/// command '%s'\n", cmd)`) and then the ordinary restart runs.
/// # SAFETY: same preconditions as [`terminal`]; irreversible.
/// # C: O(N_devices)
pub unsafe fn restart_with_command(cmd: &[u8]) -> KResult<Infallible> {
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
    static MACHINE_HITS: AtomicU32 = AtomicU32::new(0);
    fn hook() {
        assert!(DRIVER_SHUTDOWN_HOOK.try_lock().is_some(),
            "driver shutdown callbacks run outside the hook registry spinlock");
        HITS.fetch_add(1, Ordering::Release);
    }
    fn machine_hook() {
        assert!(MACHINE_SHUTDOWN_HOOK.try_lock().is_some(),
            "machine shutdown runs outside the hook registry spinlock");
        MACHINE_HITS.fetch_add(1, Ordering::Release);
    }

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
    fn machine_shutdown_callback_runs_without_registry_spin_ownership() {
        let before = MACHINE_HITS.load(Ordering::Acquire);
        set_machine_shutdown_hook(machine_hook);
        shutdown_machine();
        assert_eq!(MACHINE_HITS.load(Ordering::Acquire), before + 1);
    }

    #[test]
    fn terminal_admission_refuses_an_existing_system_transition_before_shutdown() {
        let _guard = crate::suspend::test_lock();
        let claim = crate::transition::try_claim().expect("positive control owns transition");
        let before = HITS.load(Ordering::Acquire);
        // SAFETY: refusal occurs before the irreversible endpoint.
        assert_eq!(unsafe { terminal(TerminalCmd::Restart) }, Err(Error::Busy));
        assert_eq!(HITS.load(Ordering::Acquire), before);
        drop(claim);
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
        // KEXEC is a command, but NOT a terminal one as far as this crate is
        // concerned: the shim routes it to the kexec subsystem, which owns the
        // machine-stop sequence for a relocation. It must never fall into
        // `terminal()` and shut the drivers down behind kexec's back.
        assert!(matches!(classify_cmd(LINUX_REBOOT_CMD_KEXEC), Ok(RebootAction::Kexec)));
        assert!(matches!(classify_cmd(LINUX_REBOOT_CMD_SW_SUSPEND),
            Ok(RebootAction::Hibernate)));
        assert!(classify_cmd(0xDEAD_BEEF).is_err());
    }
}
