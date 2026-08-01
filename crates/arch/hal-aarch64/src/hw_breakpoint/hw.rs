// Privileged DBGBVR/DBGBCR/DBGWVR/DBGWCR + MDSCR_EL1 access, and the
// context-switch fast path.
//
// Gated to the kernel target exactly as the rest of this crate's EL1
// system-register asm is; every caller above this file works on the
// `HwBreakpointState` value type instead. The debug value/control registers
// have no register-indirect form, so each slot index needs its own
// instruction — the accessor macro below emits one arm per architectural slot.

use core::arch::asm;

use super::ctrl::CTRL_E;
use super::idreg::{ARM_MAX_BRP, ARM_MAX_WRP};
use super::state::HwBreakpointState;

/// `MDSCR_EL1.SS` — software-step enable, bit 0.
pub const MDSCR_SS: u64 = 1 << 0;
/// `MDSCR_EL1.KDE` — local (EL1) debug enable, bit 13.
pub const MDSCR_KDE: u64 = 1 << 13;
/// `MDSCR_EL1.MDE` — monitor debug enable, bit 15. Breakpoint and watchpoint
/// exceptions are only generated while this is set.
pub const MDSCR_MDE: u64 = 1 << 15;

macro_rules! wb_accessor {
    ($write:ident, $read:ident, $reg:literal, $($n:literal),+ $(,)?) => {
        /// Write one indexed debug register. Out-of-range indices are ignored.
        /// # SAFETY: caller must be at EL1 and own this CPU's debug registers.
        unsafe fn $write(n: usize, val: u64) {
            match n {
                $(
                    $n => {
                        // SAFETY: `msr dbg{b,w}{v,c}r<n>_el1` writes an EL1
                        // debug value/control register; privileged, no memory
                        // effects. Caller owns this CPU's debug registers per
                        // the enclosing fn contract.
                        unsafe {
                            asm!(concat!("msr ", $reg, stringify!($n), "_el1, {v}"),
                                 v = in(reg) val,
                                 options(nomem, nostack, preserves_flags));
                        }
                    }
                )+
                _ => {}
            }
        }

        /// Read one indexed debug register. Out-of-range indices read zero.
        /// # SAFETY: caller must be at EL1 and own this CPU's debug registers.
        unsafe fn $read(n: usize) -> u64 {
            let mut val: u64 = 0;
            match n {
                $(
                    $n => {
                        // SAFETY: `mrs` of an EL1 debug value/control
                        // register; privileged, no memory effects. Caller owns
                        // this CPU's debug registers per the fn contract.
                        unsafe {
                            asm!(concat!("mrs {v}, ", $reg, stringify!($n), "_el1"),
                                 v = out(reg) val,
                                 options(nomem, nostack, preserves_flags));
                        }
                    }
                )+
                _ => {}
            }
            val
        }
    };
}

wb_accessor!(write_bvr, read_bvr, "dbgbvr", 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
wb_accessor!(write_bcr, read_bcr, "dbgbcr", 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
wb_accessor!(write_wvr, read_wvr, "dbgwvr", 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
wb_accessor!(write_wcr, read_wcr, "dbgwcr", 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);

/// Instruction-synchronisation barrier — debug-register writes take effect
/// only after one.
/// # SAFETY: `isb` has no memory effects and is legal at any exception level.
unsafe fn isb() {
    // SAFETY: `isb` flushes the pipeline so the debug-register writes issued
    // above are in effect before the next instruction; no memory effects.
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
}

/// Read `MDSCR_EL1`.
/// # SAFETY: caller must be at EL1 and own this CPU's debug configuration.
/// # C: O(1)
pub unsafe fn read_mdscr() -> u64 {
    let v: u64;
    // SAFETY: `mrs MDSCR_EL1` reads the monitor debug system control register;
    // privileged, no memory effects. Caller owns this CPU's debug state.
    unsafe {
        asm!("mrs {v}, mdscr_el1", v = out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

/// Write `MDSCR_EL1`.
/// # SAFETY: caller must be at EL1, own this CPU's debug configuration, and
/// hold interrupts masked so a nested handler cannot observe a torn value.
/// # C: O(1)
pub unsafe fn write_mdscr(val: u64) {
    // SAFETY: `msr MDSCR_EL1` writes the monitor debug system control
    // register; privileged, no memory effects. Caller masks interrupts and
    // owns this CPU's debug state per the fn contract.
    unsafe {
        asm!("msr mdscr_el1, {v}", v = in(reg) val, options(nomem, nostack, preserves_flags));
        isb();
    }
}

/// Set or clear `MDSCR_EL1.MDE`, leaving every other bit — notably the
/// software-step enable the ptrace step path owns — untouched.
/// # SAFETY: caller must be at EL1 with interrupts masked and own this CPU's
/// debug configuration.
/// # C: O(1)
pub unsafe fn set_monitor_enable(on: bool) {
    // SAFETY: read-modify-write of MDSCR_EL1 through this module's own
    // accessors, whose EL1 / caller-owns-debug-state contract this fn repeats.
    unsafe {
        let cur = read_mdscr();
        let new = if on { cur | MDSCR_MDE } else { cur & !MDSCR_MDE };
        if new != cur { write_mdscr(new); }
    }
}

/// Install a task's register files. Each slot is disarmed before its value
/// register is written, so no slot is ever enabled against a stale address.
/// `MDSCR_EL1.MDE` follows whether anything ended up armed.
/// # SAFETY: caller must be at EL1 with interrupts masked, and own this CPU's
/// debug registers for the duration (no concurrent diagnostic arming).
/// # C: O(n_brps + n_wrps)
/// # Ctx: context switch, IRQ-off
pub unsafe fn load(st: &HwBreakpointState, n_brps: u8, n_wrps: u8) {
    let nb = (n_brps as usize).min(ARM_MAX_BRP);
    let nw = (n_wrps as usize).min(ARM_MAX_WRP);
    // SAFETY: every accessor below carries the same EL1 /
    // caller-owns-the-debug-registers contract this fn states; the control
    // word is cleared first so an enabled slot never sees a stale DBGxVR.
    unsafe {
        for i in 0..nb {
            write_bcr(i, 0);
            write_bvr(i, st.brk[i].addr);
            write_bcr(i, st.brk[i].ctrl as u64);
        }
        for i in 0..nw {
            write_wcr(i, 0);
            write_wvr(i, st.wp[i].addr);
            write_wcr(i, st.wp[i].ctrl as u64);
        }
        isb();
        set_monitor_enable(st.is_armed());
    }
}

/// Clear every slot's enable bit and drop `MDSCR_EL1.MDE`.
/// # SAFETY: caller must be at EL1 with interrupts masked and own this CPU's
/// debug registers.
/// # C: O(n_brps + n_wrps)
pub unsafe fn disarm_all(n_brps: u8, n_wrps: u8) {
    let nb = (n_brps as usize).min(ARM_MAX_BRP);
    let nw = (n_wrps as usize).min(ARM_MAX_WRP);
    // SAFETY: writes zero to each implemented control register through this
    // module's accessors; same EL1 / caller-owns-debug-registers contract.
    unsafe {
        for i in 0..nb { write_bcr(i, 0); }
        for i in 0..nw { write_wcr(i, 0); }
        isb();
        set_monitor_enable(false);
    }
}

/// Context-switch hook. Costs nothing when neither the outgoing nor the
/// incoming task has a slot armed, which is the common case.
/// # SAFETY: caller must be at EL1 on the switching CPU with interrupts masked
/// and that CPU's debug registers owned by the scheduler for the duration.
/// # C: O(n_brps + n_wrps)
/// # Ctx: context switch, IRQ-off
pub unsafe fn switch(prev: &HwBreakpointState, next: &HwBreakpointState, n_brps: u8, n_wrps: u8) {
    if !prev.is_armed() && !next.is_armed() { return; }
    // SAFETY: reached only when one side is armed; `load` carries the same
    // EL1 / caller-owns-the-debug-registers contract as this fn.
    unsafe { load(next, n_brps, n_wrps); }
}

/// Read back one breakpoint slot as `(DBGBVR, DBGBCR)` — the boot self-check
/// that the register file took what `load` wrote.
/// # SAFETY: caller must be at EL1 and own this CPU's debug registers.
/// # C: O(1)
pub unsafe fn read_brk(n: usize) -> (u64, u32) {
    // SAFETY: reads through this module's accessors, whose EL1 /
    // caller-owns-the-debug-registers contract this fn repeats.
    unsafe { (read_bvr(n), (read_bcr(n) & u32::MAX as u64) as u32) }
}

/// Read back one watchpoint slot as `(DBGWVR, DBGWCR)`.
/// # SAFETY: caller must be at EL1 and own this CPU's debug registers.
/// # C: O(1)
pub unsafe fn read_wp(n: usize) -> (u64, u32) {
    // SAFETY: reads through this module's accessors, whose EL1 /
    // caller-owns-the-debug-registers contract this fn repeats.
    unsafe { (read_wvr(n), (read_wcr(n) & u32::MAX as u64) as u32) }
}

/// Toggle only the enable bit of every EL0 slot in one register file, as the
/// step-over-a-hit path does: after a breakpoint or watchpoint fires the slot
/// must be silenced for exactly one instruction, then restored.
/// # SAFETY: caller must be at EL1 with interrupts masked and own this CPU's
/// debug registers.
/// # C: O(n)
pub unsafe fn toggle_enables(brk: bool, n: u8, on: bool) {
    let max = if brk { ARM_MAX_BRP } else { ARM_MAX_WRP };
    let n = (n as usize).min(max);
    // SAFETY: read-modify-write of the enable bit through this module's
    // accessors; same EL1 / caller-owns-the-debug-registers contract.
    unsafe {
        for i in 0..n {
            let cur = if brk { read_bcr(i) } else { read_wcr(i) };
            let new = if on { cur | CTRL_E as u64 } else { cur & !(CTRL_E as u64) };
            if brk { write_bcr(i, new); } else { write_wcr(i, new); }
        }
        isb();
    }
}
