#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
use super::SvcFrame;

// ---------------------------------------------------------------------------
// EL0 trapped-MRS/MSR (`ESR_EL1.EC == 0x18`) ISS decode.
//
// Every item below feeds `oxide_arm_sysreg_trap_handler`, which exists only on
// the kernel target. The decode half is additionally reachable from the host
// unit tests at the bottom of this file, so it carries `test` in its gate; the
// write-back half (`write_saved_rt` and the constants only it uses) is not
// covered by a test and is kernel-target-only.
// ---------------------------------------------------------------------------

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const AARCH64_INSN_BYTES: u64 = 4;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const ESR_EC_SHIFT: u64 = 26;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const ESR_EC_MASK: u64 = 0x3f;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const ESR_EC_SYSREG_TRAP: u64 = 0x18;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_ISS_DIR_READ: u64 = 1;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_ISS_DIR_SHIFT: u64 = 0;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_ISS_RT_SHIFT: u64 = 5;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_ISS_RT_MASK: u64 = 0x1f;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_ISS_CRN_SHIFT: u64 = 10;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_ISS_CRM_SHIFT: u64 = 1;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_ISS_OP1_SHIFT: u64 = 14;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_ISS_OP2_SHIFT: u64 = 17;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_ISS_OP0_SHIFT: u64 = 20;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_OP0_MASK: u64 = 0x3;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_OP_MASK: u64 = 0x7;
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_CR_MASK: u64 = 0xf;
/// XZR encoding in the ISS `Rt` field: a read into it discards the value.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const SYSREG_XZR_RT: u64 = 31;

#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
#[derive(Clone, Copy, Eq, PartialEq)]
struct SysReg {
    op0: u64,
    op1: u64,
    crn: u64,
    crm: u64,
    op2: u64,
}

// Only the handler reads CNTFRQ_EL0; the test below decodes CNTVCT_EL0.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
const SYSREG_CNTFRQ_EL0: SysReg = SysReg { op0: 3, op1: 3, crn: 14, crm: 0, op2: 0 };
/// `CTR_EL0`, the cache-type register Linux exposes through its trap hook.
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_CTR_EL0: SysReg = SysReg { op0: 3, op1: 3, crn: 0, crm: 0, op2: 1 };
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_CNTVCT_EL0: SysReg = SysReg { op0: 3, op1: 3, crn: 14, crm: 0, op2: 2 };

// Also emulated for EL0: `CNTPCT_EL0`. Denying counter access clears BOTH
// EL0PCTEN and EL0VCTEN, so a task under `prctl(PR_TSC_SIGSEGV)` traps here on
// the physical counter too; emulating that one while refusing the virtual one
// would leave the trap trivially side-steppable.
#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
const SYSREG_CNTPCT_EL0: SysReg = SysReg { op0: 3, op1: 3, crn: 14, crm: 0, op2: 1 };

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_arm_undef_handler(frame_ptr: *mut u8) -> u64;
    /// Non-zero when the current task ran `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)`.
    /// The task-state owner lives above this crate, so the counter-read
    /// emulator asks by upcall rather than reaching into the scheduler.
    fn oxide_arm_counter_read_denied() -> u64;
    /// Deliver SIGSEGV to the current task for a denied counter read
    /// (Linux `cntvct_read_handler`'s `force_sig(SIGSEGV)` arm). Returns the
    /// saved user x0, like the undef handler.
    fn oxide_arm_counter_read_sigsegv(frame_ptr: *mut u8) -> u64;
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
fn sysreg_ec(esr: u64) -> u64 {
    (esr >> ESR_EC_SHIFT) & ESR_EC_MASK
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
fn sysreg_iss_reg(esr: u64) -> SysReg {
    SysReg {
        op0: (esr >> SYSREG_ISS_OP0_SHIFT) & SYSREG_OP0_MASK,
        op1: (esr >> SYSREG_ISS_OP1_SHIFT) & SYSREG_OP_MASK,
        crn: (esr >> SYSREG_ISS_CRN_SHIFT) & SYSREG_CR_MASK,
        crm: (esr >> SYSREG_ISS_CRM_SHIFT) & SYSREG_CR_MASK,
        op2: (esr >> SYSREG_ISS_OP2_SHIFT) & SYSREG_OP_MASK,
    }
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
fn sysreg_iss_rt(esr: u64) -> u64 {
    (esr >> SYSREG_ISS_RT_SHIFT) & SYSREG_ISS_RT_MASK
}

#[cfg(any(test, all(target_arch = "aarch64", target_os = "oxide-kernel")))]
fn sysreg_iss_is_read(esr: u64) -> bool {
    ((esr >> SYSREG_ISS_DIR_SHIFT) & SYSREG_ISS_DIR_READ) == SYSREG_ISS_DIR_READ
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn write_saved_rt(frame: &mut SvcFrame, rt: u64, value: u64) {
    match rt {
        0..=17 => frame.gp[rt as usize] = value,
        18 => frame.x18_x29[0] = value,
        19..=28 => frame.x19_x28[(rt - 19) as usize] = value,
        29 => frame.x18_x29[1] = value,
        30 => frame.x30 = value,
        SYSREG_XZR_RT => {}
        _ => {}
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn read_cntfrq_el0() -> u64 {
    let v: u64;
    // SAFETY: `mrs CNTFRQ_EL0` reads the architected counter frequency and has no memory side effects.
    unsafe { core::arch::asm!("mrs {v}, cntfrq_el0", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
    v
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn read_cntpct_el0() -> u64 {
    let v: u64;
    // SAFETY: `mrs CNTPCT_EL0` reads the architected physical counter and has no memory side effects.
    unsafe { core::arch::asm!("mrs {v}, cntpct_el0", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
    v
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn read_cntvct_el0() -> u64 {
    let v: u64;
    // SAFETY: `mrs CNTVCT_EL0` reads the architected virtual counter and has no memory side effects.
    unsafe { core::arch::asm!("mrs {v}, cntvct_el0", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
    v
}

/// Handle EL0 trapped MRS/MSR instructions. Linux exposes the architected
/// counter registers to userspace; unsupported trapped sysregs stay SIGILL.
/// # SAFETY: `frame` is the live 288 B lower-EL sync frame owned by this CPU.
/// # C: O(1)
/// # Ctx: synchronous exception, IRQs masked
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[no_mangle]
pub unsafe extern "C" fn oxide_arm_sysreg_trap_handler(frame: *mut SvcFrame, esr: u64) -> u64 {
    // SAFETY: caller passed the live lower-EL sync frame for this exception.
    let f = unsafe { &mut *frame };
    if sysreg_ec(esr) != ESR_EC_SYSREG_TRAP || !sysreg_iss_is_read(esr) {
        // SAFETY: the frame is byte-identical to the undef frame expected by the SIGILL delivery path.
        return unsafe { oxide_arm_undef_handler(frame.cast::<u8>()) };
    }
    let reg = sysreg_iss_reg(esr);
    if reg == SYSREG_CTR_EL0 {
        let saved_x0 = f.gp[0];
        let value = crate::cpuid::ctr_el0();
        let rt = sysreg_iss_rt(esr);
        write_saved_rt(f, rt, value);
        f.elr_el1 = f.elr_el1.wrapping_add(AARCH64_INSN_BYTES);
        return if rt == 0 { value } else { saved_x0 };
    }
    // Linux `cntvct_read_handler` / `cntfrq_read_handler`: a task that armed
    // `PR_TSC_SIGSEGV` gets the signal INSTEAD of the emulated value. Without
    // this arm the trap still fires (the enable bits are cleared) but the
    // emulator hands the counter back anyway, so `PR_TSC_SIGSEGV` would report
    // success while `mrs CNTVCT_EL0` kept working — the exact lie the option
    // exists to prevent.
    if matches!(reg, SYSREG_CNTVCT_EL0 | SYSREG_CNTPCT_EL0 | SYSREG_CNTFRQ_EL0) {
        // SAFETY: upcall into the task-state owner; reads one per-task flag and takes no locks.
        if unsafe { oxide_arm_counter_read_denied() } != 0 {
            // SAFETY: the frame is the live 288 B lower-EL sync frame this handler was given.
            return unsafe { oxide_arm_counter_read_sigsegv(frame.cast::<u8>()) };
        }
    }
    let value = if reg == SYSREG_CNTVCT_EL0 {
        read_cntvct_el0()
    } else if reg == SYSREG_CNTPCT_EL0 {
        read_cntpct_el0()
    } else if reg == SYSREG_CNTFRQ_EL0 {
        read_cntfrq_el0()
    } else {
        // SAFETY: the frame is byte-identical to the undef frame expected by the SIGILL delivery path.
        return unsafe { oxide_arm_undef_handler(frame.cast::<u8>()) };
    };
    let rt = sysreg_iss_rt(esr);
    let saved_x0 = f.gp[0];
    write_saved_rt(f, rt, value);
    f.elr_el1 = f.elr_el1.wrapping_add(AARCH64_INSN_BYTES);
    if rt == 0 { value } else { saved_x0 }
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn sysreg_iss_decodes_cntvct_el0() {
        let esr = (ESR_EC_SYSREG_TRAP << ESR_EC_SHIFT) | 0x34f841;
        assert_eq!(sysreg_ec(esr), ESR_EC_SYSREG_TRAP);
        assert!(sysreg_iss_is_read(esr));
        assert_eq!(sysreg_iss_rt(esr), 2);
        assert!(sysreg_iss_reg(esr) == SYSREG_CNTVCT_EL0);
    }
}
