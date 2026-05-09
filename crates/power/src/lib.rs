// Power + reset per `32`.
//
// Owns the reboot/halt/poweroff endpoints invoked by:
//   - sys_reboot(2) (kernel/src/syscall_glue_misc.rs)
//   - panic-halt path (kernel/src/lib.rs::halt_forever)
//   - QEMU smoke shutdown (kernel/src/lib.rs end-of-boot)
//
// Linux reboot(2) ABI per `man 2 reboot`:
//   reboot(magic1, magic2, cmd, arg) where
//     magic1 = LINUX_REBOOT_MAGIC1 = 0xfee1dead
//     magic2 = LINUX_REBOOT_MAGIC2 = 0x28121969 (or one of the alts)
//   cmd ∈ { RESTART, HALT, POWER_OFF, RESTART2, CAD_ON, CAD_OFF, KEXEC }
//
// v1 mechanism map (x86_64):
//   POWER_OFF → QEMU isa-debug-exit (port 0x604 = 0x2000); fallback hlt
//   RESTART   → triple fault via lidt 0 then int3
//   HALT      → forever `hlt`
// v1 mechanism map (aarch64):
//   POWER_OFF → PSCI SYSTEM_OFF via `hvc #0` (id=0x84000008)
//   RESTART   → PSCI SYSTEM_RESET via `hvc #0` (id=0x84000009)
//   HALT      → forever `wfi`
//
// kexec is not implemented; v1 returns Inval.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { Inval, Perm, Io }

pub type KResult<T> = core::result::Result<T, Error>;

pub const LINUX_REBOOT_MAGIC1:    u32 = 0xfee1dead;
pub const LINUX_REBOOT_MAGIC2:    u32 = 0x28121969;
pub const LINUX_REBOOT_MAGIC2A:   u32 = 0x05121996;
pub const LINUX_REBOOT_MAGIC2B:   u32 = 0x16041998;
pub const LINUX_REBOOT_MAGIC2C:   u32 = 0x20112000;

pub const LINUX_REBOOT_CMD_RESTART:    u32 = 0x01234567;
pub const LINUX_REBOOT_CMD_HALT:       u32 = 0xCDEF0123;
pub const LINUX_REBOOT_CMD_CAD_ON:     u32 = 0x89ABCDEF;
pub const LINUX_REBOOT_CMD_CAD_OFF:    u32 = 0x00000000;
pub const LINUX_REBOOT_CMD_POWER_OFF:  u32 = 0x4321FEDC;
pub const LINUX_REBOOT_CMD_RESTART2:   u32 = 0xA1B2C3D4;
pub const LINUX_REBOOT_CMD_SW_SUSPEND: u32 = 0xD000FCE2;
pub const LINUX_REBOOT_CMD_KEXEC:      u32 = 0x45584543;

/// Validate the Linux reboot(2) magic numbers per `man 2 reboot`.
/// # C: O(1)
pub fn check_magic(magic1: u32, magic2: u32) -> bool {
    magic1 == LINUX_REBOOT_MAGIC1
        && (magic2 == LINUX_REBOOT_MAGIC2
            || magic2 == LINUX_REBOOT_MAGIC2A
            || magic2 == LINUX_REBOOT_MAGIC2B
            || magic2 == LINUX_REBOOT_MAGIC2C)
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
/// x86_64: triple fault via `lidt` of a zero IDTR + int3.
/// aarch64: PSCI SYSTEM_RESET (`hvc #0` with x0=0x84000009).
/// # SAFETY: clobbers IDT (x86) / traps to EL2 (arm); irreversible.
/// # C: O(1)
pub unsafe fn restart() -> ! {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        // Zero IDTR + int3 → CPU triple-faults → reset.
        // SAFETY: lidt with limit=0 makes any interrupt fault; the int3 then takes a #DB→#GP→#DF→reset chain. Irreversible on purpose.
        unsafe {
            core::arch::asm!(
                "sub rsp, 16",
                "mov word ptr [rsp], 0",
                "mov qword ptr [rsp+2], 0",
                "lidt [rsp]",
                "int3",
                options(noreturn, nostack)
            );
        }
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
/// PM1A_CNT and write SLP_TYP=_S5 SLP_EN; that rides v2.x. arm64
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

/// Dispatcher for sys_reboot(2). `arg` is currently ignored (used
/// only by RESTART2 for the boot string).
/// # SAFETY: caller has validated CAP_SYS_BOOT and the magic args.
/// # C: O(1)
pub unsafe fn cmd(c: u32) -> KResult<()> {
    match c {
        // SAFETY: each branch is a terminal-state primitive; caller validated CAP_SYS_BOOT + magic per `man 2 reboot`; irreversible by design.
        LINUX_REBOOT_CMD_RESTART | LINUX_REBOOT_CMD_RESTART2 => unsafe { restart() },
        // SAFETY: caller validated CAP_SYS_BOOT + magic; power_off is irreversible per Linux reboot(2) RESTART2/POWER_OFF contract.
        LINUX_REBOOT_CMD_POWER_OFF                            => unsafe { power_off() },
        // SAFETY: caller validated CAP_SYS_BOOT + magic; halt parks every CPU; the kernel never resumes from this primitive.
        LINUX_REBOOT_CMD_HALT                                 => unsafe { halt() },
        LINUX_REBOOT_CMD_CAD_ON | LINUX_REBOOT_CMD_CAD_OFF    => Ok(()),
        LINUX_REBOOT_CMD_KEXEC | LINUX_REBOOT_CMD_SW_SUSPEND  => Err(Error::Inval),
        _ => Err(Error::Inval),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // SAFETY: hosted-test path; init has no preconditions and the host build is a no-op Ok(()).
    #[test] fn init_ok() { unsafe { assert!(init().is_ok()); } }
    #[test] fn magic_validates() {
        assert!(check_magic(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2));
        assert!(check_magic(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2C));
        assert!(!check_magic(0, 0));
        assert!(!check_magic(LINUX_REBOOT_MAGIC1, 0));
    }
    #[test] fn unknown_cmd_inval() {
        // SAFETY: hosted-test path — host build of cmd() never reaches the asm blocks; the unknown branch returns Err immediately.
        let r = unsafe { cmd(0xDEADBEEF) };
        assert_eq!(r, Err(Error::Inval));
    }
}
