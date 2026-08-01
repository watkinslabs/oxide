// Trap/abort -> (signal, si_code) classification for both architectures.
//
// A synchronous CPU exception that userspace cannot be resumed from becomes a
// signal, and the signal's `si_code` is what tells a handler WHY: SEGV_MAPERR
// vs SEGV_ACCERR, BUS_ADRALN vs BUS_ADRERR, ILL_ILLOPN, FPE_INTDIV. Every
// crash reporter, JIT guard-page trick and `mmap`-probe idiom in userspace
// keys on that field, so getting it from the hardware status register is not
// optional detail.
//
// Pure decode, no kernel state, so both arches' tables are `cargo test -p hal`
// provable rather than only observable at QEMU boot. The fault vectors in
// `mm-pmm` consume the result and hand it to `force_sig_fault`.
//
// Module manifest:
//   `x86_64`  — IDT vector + `#PF` error code decode.
//   `aarch64` — ESR_EL1 exception class + data/instruction-abort DFSC decode.

use crate::siginfo::code;

/// One classified fault: the signal to force and its `si_code`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FaultSignal {
    /// Linux signo (1..=31).
    pub signo: u8,
    /// `si_code` from `siginfo::code`, or `SI_KERNEL` for the unclassifiable
    /// hardware conditions Linux reports without a `_sigfault` classification.
    pub code: i32,
}

/// `SI_KERNEL` — the `si_code` Linux uses for a fault it cannot classify
/// (`#GP`, an unknown abort). Duplicated from the signal-source codes rather
/// than imported so `hal` keeps no dependency on `sched`.
pub const SI_KERNEL: i32 = 0x80;

/// SIGILL.
const SIGILL: u8 = 4;
/// SIGTRAP.
const SIGTRAP: u8 = 5;
/// SIGBUS.
const SIGBUS: u8 = 7;
/// SIGFPE.
const SIGFPE: u8 = 8;
/// SIGSEGV.
const SIGSEGV: u8 = 11;

pub mod x86_64 {
    use super::*;

    /// `#PF` error-code bit 0 (`X86_PF_PROT`): the fault was a protection
    /// violation on a PRESENT page, not an absent mapping.
    pub const PF_PROT: u64 = 1 << 0;
    /// Bit 1 (`X86_PF_WRITE`): the access was a write.
    pub const PF_WRITE: u64 = 1 << 1;
    /// Bit 2 (`X86_PF_USER`): the access was issued at CPL=3.
    pub const PF_USER: u64 = 1 << 2;
    /// Bit 3 (`X86_PF_RSVD`): a reserved page-table bit was set — a kernel
    /// page-table bug, never a user-resolvable fault.
    pub const PF_RSVD: u64 = 1 << 3;
    /// Bit 4 (`X86_PF_INSTR`): an instruction fetch.
    pub const PF_INSTR: u64 = 1 << 4;
    /// Bit 5 (`X86_PF_PK`): the page's protection key denied the access.
    ///
    /// The hardware has already consulted PKRU against the PTE's key, so this
    /// bit is AUTHORITATIVE — unlike the aarch64 Overlay hint, no re-check is
    /// needed to know a key caused the fault. It cannot be resolved by any
    /// amount of paging work: the mapping is present and permitted by the page
    /// tables, and only a `WRPKRU` or `pkey_mprotect` can change the answer.
    pub const PF_PK: u64 = 1 << 5;
    /// Bit 6 (`X86_PF_SHSTK`): a shadow-stack access.
    pub const PF_SHSTK: u64 = 1 << 6;
    /// Bit 15 (`X86_PF_SGX`): an SGX-specific access-control violation.
    pub const PF_SGX: u64 = 1 << 15;

    /// IDT vector numbers this classifier names (Intel SDM Vol. 3 §6.15).
    pub const TRAP_DE: u64 = 0;
    pub const TRAP_DB: u64 = 1;
    pub const TRAP_BP: u64 = 3;
    pub const TRAP_OF: u64 = 4;
    pub const TRAP_BR: u64 = 5;
    pub const TRAP_UD: u64 = 6;
    pub const TRAP_NM: u64 = 7;
    pub const TRAP_TS: u64 = 10;
    pub const TRAP_NP: u64 = 11;
    pub const TRAP_SS: u64 = 12;
    pub const TRAP_GP: u64 = 13;
    pub const TRAP_PF: u64 = 14;
    pub const TRAP_MF: u64 = 16;
    pub const TRAP_AC: u64 = 17;
    pub const TRAP_XF: u64 = 19;
    pub const TRAP_CP: u64 = 21;

    /// `#PF` classification: a protection-key denial is SEGV_PKUERR, an absent
    /// mapping is SEGV_MAPERR, and a present page the access was not entitled
    /// to is SEGV_ACCERR.
    ///
    /// The key check comes FIRST because a key denial always arrives with
    /// `PF_PROT` set as well — the page IS present and the page tables DO
    /// permit the access; it was the key that refused. Testing `PF_PROT` first
    /// would report every key violation as a plain access error and hide the
    /// one piece of information a handler needs to fix it.
    /// # C: O(1)
    pub fn page_fault(err: u64) -> FaultSignal {
        if err & PF_PK != 0 { return FaultSignal { signo: SIGSEGV, code: code::SEGV_PKUERR }; }
        let code = if err & PF_PROT != 0 { code::SEGV_ACCERR } else { code::SEGV_MAPERR };
        FaultSignal { signo: SIGSEGV, code }
    }

    /// Every non-`#PF` synchronous trap taken from user mode.
    ///
    /// The signal choice is the architecture's, not ours: `#UD` is SIGILL with
    /// ILL_ILLOPN, `#DE` is SIGFPE/FPE_INTDIV, `#AC` is SIGBUS/BUS_ADRALN, and
    /// the segment traps (`#TS`, `#SS`) are SIGBUS/SIGSEGV with no `si_code`
    /// classification at all.
    /// # C: O(1)
    pub fn trap(vec: u64) -> FaultSignal {
        match vec {
            TRAP_DE => FaultSignal { signo: SIGFPE,  code: code::FPE_INTDIV },
            TRAP_DB => FaultSignal { signo: SIGTRAP, code: code::TRAP_TRACE },
            TRAP_BP => FaultSignal { signo: SIGTRAP, code: code::TRAP_BRKPT },
            TRAP_OF => FaultSignal { signo: SIGSEGV, code: SI_KERNEL },
            TRAP_BR => FaultSignal { signo: SIGSEGV, code: code::SEGV_BNDERR },
            TRAP_UD => FaultSignal { signo: SIGILL,  code: code::ILL_ILLOPN },
            TRAP_NM => FaultSignal { signo: SIGFPE,  code: SI_KERNEL },
            TRAP_TS => FaultSignal { signo: SIGSEGV, code: SI_KERNEL },
            TRAP_NP => FaultSignal { signo: SIGBUS,  code: SI_KERNEL },
            TRAP_SS => FaultSignal { signo: SIGBUS,  code: SI_KERNEL },
            TRAP_GP => FaultSignal { signo: SIGSEGV, code: SI_KERNEL },
            TRAP_MF => FaultSignal { signo: SIGFPE,  code: code::FPE_FLTUNK },
            TRAP_AC => FaultSignal { signo: SIGBUS,  code: code::BUS_ADRALN },
            TRAP_XF => FaultSignal { signo: SIGFPE,  code: code::FPE_FLTUNK },
            TRAP_CP => FaultSignal { signo: SIGSEGV, code: code::SEGV_CPERR },
            _       => FaultSignal { signo: SIGSEGV, code: SI_KERNEL },
        }
    }

    /// The address a trap's `si_addr` reports. Only the faults that name a
    /// memory operand carry one; the rest report the faulting instruction, and
    /// the segment/`#GP` traps report nothing at all.
    /// # C: O(1)
    pub fn trap_addr(vec: u64, pc: u64) -> u64 {
        match vec {
            TRAP_DE | TRAP_UD | TRAP_MF | TRAP_XF | TRAP_BP | TRAP_DB | TRAP_BR => pc,
            _ => 0,
        }
    }
}

pub mod aarch64 {
    use super::*;

    /// ESR_EL1 exception class field, bits 26..31.
    pub const fn ec(esr: u64) -> u64 { (esr >> 26) & 0x3f }
    /// Data/instruction abort fault status code, bits 0..5 of ESR_EL1.ISS.
    pub const fn dfsc(esr: u64) -> u64 { esr & 0x3f }

    /// `ESR_ELx.ISS2.Overlay` — the permission overlay contributed to this
    /// abort.
    ///
    /// A HINT, not a verdict, and deliberately not used to choose a `si_code`.
    /// A permission-overlay fault arrives as an ORDINARY permission fault
    /// (`dfsc` 0x0c..0x0f) — there is no distinct fault-status code for it —
    /// and this bit can be set spuriously (the rights register is updated
    /// without an `isb` on context switch) as well as CLEAR on an access that
    /// should still be reported as a key violation (no page mapped yet, but
    /// the rights register already forbids the access). The verdict therefore
    /// has to come from comparing the live rights register against the VMA's
    /// key, exactly as the arch-neutral access check does.
    pub const ISS2_OVERLAY: u64 = 1 << 6;

    /// EC values this classifier names (Arm ARM D17.2.37).
    pub const EC_UNKNOWN: u64 = 0x00;
    /// Trapped WF*.
    pub const EC_ILLEGAL_STATE: u64 = 0x0e;
    /// SVE/SIMD/FP access trapped.
    pub const EC_FP_ACCESS: u64 = 0x07;
    /// Instruction abort from a lower EL.
    pub const EC_IABT_LOW: u64 = 0x20;
    /// PC alignment fault.
    pub const EC_PC_ALIGN: u64 = 0x22;
    /// Data abort from a lower EL.
    pub const EC_DABT_LOW: u64 = 0x24;
    /// SP alignment fault.
    pub const EC_SP_ALIGN: u64 = 0x26;
    /// Trapped AArch64 floating-point exception.
    pub const EC_FP_EXC: u64 = 0x2c;
    /// Breakpoint from a lower EL.
    pub const EC_BREAKPT_LOW: u64 = 0x30;
    /// Software step from a lower EL.
    pub const EC_SOFTSTEP_LOW: u64 = 0x32;
    /// Watchpoint from a lower EL.
    pub const EC_WATCHPT_LOW: u64 = 0x34;
    /// AArch64 BRK instruction.
    pub const EC_BRK: u64 = 0x3c;

    /// Data/instruction-abort DFSC decode. Address-size and translation faults
    /// are an absent mapping (SEGV_MAPERR); access-flag and permission faults
    /// are a present page the access was not entitled to (SEGV_ACCERR); an
    /// external abort is BUS_OBJERR; an alignment fault is BUS_ADRALN.
    /// # C: O(1)
    pub fn abort(esr: u64) -> FaultSignal {
        match dfsc(esr) {
            // 0b0000LL address size fault, 0b0001LL translation fault, and the
            // level -1 translation fault at 0b101011.
            0x00..=0x07 | 0x2b => FaultSignal { signo: SIGSEGV, code: code::SEGV_MAPERR },
            // 0b0010LL access flag fault, 0b0011LL permission fault.
            0x08..=0x0f        => FaultSignal { signo: SIGSEGV, code: code::SEGV_ACCERR },
            // 0b010000 synchronous external abort, 0b011000 parity/ECC error.
            0x10 | 0x18        => FaultSignal { signo: SIGBUS,  code: code::BUS_OBJERR },
            // 0b100001 alignment fault.
            0x21               => FaultSignal { signo: SIGBUS,  code: code::BUS_ADRALN },
            _                  => FaultSignal { signo: SIGSEGV, code: SI_KERNEL },
        }
    }

    /// Every synchronous EL0 exception, keyed on ESR_EL1.EC.
    /// # C: O(1)
    pub fn sync(esr: u64) -> FaultSignal {
        match ec(esr) {
            EC_IABT_LOW | EC_DABT_LOW => abort(esr),
            EC_UNKNOWN | EC_ILLEGAL_STATE => FaultSignal { signo: SIGILL, code: code::ILL_ILLOPC },
            EC_FP_ACCESS => FaultSignal { signo: SIGILL, code: code::ILL_ILLOPC },
            EC_PC_ALIGN | EC_SP_ALIGN => FaultSignal { signo: SIGBUS, code: code::BUS_ADRALN },
            EC_FP_EXC => FaultSignal { signo: SIGFPE, code: code::FPE_FLTUNK },
            EC_BRK => FaultSignal { signo: SIGTRAP, code: code::TRAP_BRKPT },
            EC_BREAKPT_LOW => FaultSignal { signo: SIGTRAP, code: code::TRAP_BRKPT },
            EC_SOFTSTEP_LOW => FaultSignal { signo: SIGTRAP, code: code::TRAP_TRACE },
            EC_WATCHPT_LOW => FaultSignal { signo: SIGTRAP, code: code::TRAP_HWBKPT },
            _ => FaultSignal { signo: SIGSEGV, code: SI_KERNEL },
        }
    }

    /// Whether the exception came from EL0 (Linux `user_mode(regs)`'s
    /// equivalent for the abort classes).
    /// # C: O(1)
    pub fn from_el0(esr: u64) -> bool { matches!(ec(esr), EC_IABT_LOW | EC_DABT_LOW) }
}

#[cfg(test)]
mod tests;
