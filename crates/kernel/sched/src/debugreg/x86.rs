// HAL bridge for the per-task debug-register shadow: convert between
// `Task::debugregs` and the HAL's `DebugRegs` value, validate a ptrace DR7 or
// address write through the architecture's ladder, and install the incoming
// task's state on a context switch.
//
// x86_64 only. aarch64 exposes hardware breakpoints through the
// `NT_ARM_HW_BREAK` / `NT_ARM_HW_WATCH` regsets instead of a `struct user`
// debug-register window, so it has no counterpart here.

use core::sync::atomic::Ordering;

use hal_x86_64::debugreg::{dr6, dr7, DebugRegs, Dr7Error};

use crate::Task;
use super::{CONTROL, NR_ADDR, STATUS};

/// Snapshot a task's shadow as the HAL value type. # C: O(1)
pub fn snapshot(t: &Task) -> DebugRegs {
    DebugRegs {
        addr: super::addrs(t),
        dr6:  t.debugregs[STATUS].load(Ordering::Acquire),
        dr7:  t.debugregs[CONTROL].load(Ordering::Acquire),
    }
}

/// `ptrace_set_debugreg(n, data)` for a breakpoint address slot.
///
/// The address is validated before it is stored, not when DR7 later arms it: a
/// slot holding a kernel address is a kernel breakpoint the moment any DR7
/// write enables it, and Linux refuses the address at the point it is offered.
/// # C: O(1)
pub fn set_addr(t: &Task, slot: usize, addr: u64) -> Result<(), Dr7Error> {
    if slot >= NR_ADDR { return Err(Dr7Error::KernelAddress { slot }); }
    let mut regs = snapshot(t);
    regs.set_addr(slot, addr)?;
    t.debugregs[slot].store(addr, Ordering::Release);
    Ok(())
}

/// `ptrace_set_debugreg(7, data)` — the full DR7 ladder against the addresses
/// the task currently holds. Nothing is stored unless every armed slot passes.
/// # C: O(NR_ADDR)
pub fn set_control(t: &Task, dr7: u64) -> Result<(), Dr7Error> {
    let mut regs = snapshot(t);
    regs.set_dr7(dr7)?;
    t.debugregs[CONTROL].store(regs.dr7, Ordering::Release);
    Ok(())
}

/// `ptrace_set_debugreg(6, data)`. The status a tracer writes is a VIRTUAL
/// DR6 kept per task and never loaded into hardware, so the write always
/// succeeds and round-trips verbatim: the value is stored in positive polarity
/// (`raw ^ reserved-ones`) and flipped back on read. Masking it to the cause
/// bits — which is what this used to do — silently dropped part of a value a
/// tracer is entitled to read back unchanged.
/// # C: O(1)
pub fn set_status(t: &Task, dr6: u64) {
    t.debugregs[STATUS].store(dr6::normalize(dr6), Ordering::Release);
}

/// `ptrace_get_debugreg(6)` — the virtual DR6 flipped back to architectural
/// polarity, which is the form userspace expects.
/// # C: O(1)
pub fn status(t: &Task) -> u64 { dr6::normalize(t.debugregs[STATUS].load(Ordering::Acquire)) }

/// Install `t`'s breakpoints on this CPU. Skips every privileged write when
/// neither the outgoing nor the incoming task has a slot armed, which is every
/// switch on a machine with no debugger attached.
/// # SAFETY: caller is the context switch at CPL=0 with this CPU's debug
/// registers owned by the scheduler for the duration.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn switch_to(prev: &Task, next: &Task) {
    if !super::armed(prev) && !super::armed(next) { return; }
    let (p, n) = (snapshot(prev), snapshot(next));
    // SAFETY: forwarded contract — context switch, CPL=0, this CPU's debug
    // registers are the scheduler's for the duration of the switch.
    unsafe { hal_x86_64::debugreg::hw::switch(&p, &n); }
}

/// Read and clear the hardware DR6 after a #DB, fold its cause bits into the
/// task's shadow, and report the `si_code` the SIGTRAP must carry —
/// `TRAP_TRACE` for a single-step, `TRAP_HWBKPT` for a breakpoint hit.
/// # SAFETY: caller is the #DB fault path at CPL=0 with interrupts masked, so
/// this CPU is the sole debug-register reader.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn take_trap(t: &Task) -> i32 {
    // SAFETY: forwarded contract — #DB dispatch, CPL=0, IRQs masked, sole
    // reader of this CPU's DR6.
    let raw = unsafe { hal_x86_64::debugreg::hw::store_dr6() };
    let cause = dr6::normalize(raw) & dr6::DR6_CAUSE_MASK;
    super::record_status(t, cause);
    dr6::si_code_for(cause)
}

/// The DR7 value a task with no breakpoints holds. Exposed so the shadow's
/// "unarmed" encoding is the architecture's reset value rather than a bare
/// zero invented here.
/// # C: O(1)
pub const fn empty_control() -> u64 { dr7::DR7_EMPTY }
