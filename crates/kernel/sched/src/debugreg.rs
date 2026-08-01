// Per-task hardware debug-register shadow — the storage half.
//
// The BIT contract (DR7 encodings, address alignment, the #DB cause
// classifier) belongs to the architecture and lives in the HAL; this file owns
// only where a task keeps its copy, how a `struct user.u_debugreg` index maps
// onto it, and when it is installed into hardware. Keeping the storage
// arch-neutral is what lets `Task` carry it on both arches without an
// x86-shaped field leaking into the aarch64 build.
//
// Module manifest — this file owns:
//   * the slot layout of `Task::debugregs` and the `u_debugreg` index map.
//   * `armed` / `clear` — the arch-neutral predicates callers outside x86 use.
//   * `x86` — the HAL bridge: snapshot/install/context-switch, x86_64 only.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::Task;

pub mod slab;

/// The x86 shadow behind the lazy slot: DR0-DR3, then DR6 and DR7.
#[derive(Default)]
pub struct Shadow { pub regs: [AtomicU64; SLOTS] }

/// Number of hardware breakpoint slots — DR0..DR3.
pub const NR_ADDR: usize = 4;
/// Index of the status shadow (DR6) inside `Task::debugregs`.
pub const STATUS: usize = 4;
/// Index of the control shadow (DR7) inside `Task::debugregs`.
pub const CONTROL: usize = 5;
/// Length of `Task::debugregs`.
pub const SLOTS: usize = 6;

/// DR7's four local+global enable bits. A task with none set is unarmed, which
/// is the context-switch fast path and the only thing this file needs to know
/// about DR7's layout.
pub const DR7_ENABLE_MASK: u64 = 0xff;

/// Map a `struct user.u_debugreg[idx]` index onto a storage slot.
///
/// There are NO DR4/DR5 registers: indices 4 and 5 are not aliases of 6 and 7,
/// they simply do not exist. A READ of them yields zero and succeeds, a WRITE
/// of them is EIO — the asymmetry is real and observable, so the two
/// directions are answered separately (`writable_slot`).
/// # C: O(1)
pub const fn slot_of_u_debugreg(idx: usize) -> Option<usize> {
    match idx {
        0..=3 => Some(idx),
        6     => Some(STATUS),
        7     => Some(CONTROL),
        _     => None,
    }
}

/// Whether `idx` names the control register, whose write must be validated
/// before it can reach hardware. # C: O(1)
pub const fn is_control(idx: usize) -> bool { idx == CONTROL_IDX }

/// Whether `idx` names the status register. # C: O(1)
pub const fn is_status(idx: usize) -> bool { idx == STATUS_IDX }

/// `u_debugreg` index of the status register (DR6).
pub const STATUS_IDX: usize = 6;
/// `u_debugreg` index of the control register (DR7).
pub const CONTROL_IDX: usize = 7;
/// Highest `u_debugreg` index `struct user` exposes.
pub const MAX_IDX: usize = 7;

/// Read one `u_debugreg` slot of `t`. A nonexistent index (DR4/DR5, or past
/// the end) reads as zero rather than failing — the read side has no error
/// path at all. A task that never armed a breakpoint answers from the
/// architectural reset value without touching an allocation.
/// # C: O(1)
pub fn get(t: &Task, idx: usize) -> u64 {
    let (Some(slot), Some(sh)) = (slot_of_u_debugreg(idx), t.debugregs.get()) else { return 0 };
    sh.regs[slot].load(Ordering::Acquire)
}

/// Store one slot verbatim, allocating the shadow on first use. Validation is
/// the caller's — a DR7 write must have been through the HAL ladder first.
/// # C: O(1)
pub fn put(t: &Task, slot: usize, v: u64) {
    if slot >= SLOTS { return; }
    if let Some(sh) = t.debugregs.get_or_init() { sh.regs[slot].store(v, Ordering::Release); }
}

/// The four breakpoint addresses. # C: O(1)
pub fn addrs(t: &Task) -> [u64; NR_ADDR] {
    let mut a = [0u64; NR_ADDR];
    let Some(sh) = t.debugregs.get() else { return a };
    let mut i = 0;
    while i < NR_ADDR { a[i] = sh.regs[i].load(Ordering::Acquire); i += 1; }
    a
}

/// At least one breakpoint slot is enabled. The context-switch gate, so the
/// no-shadow answer must be reachable without an allocation.
/// # C: O(1)
pub fn armed(t: &Task) -> bool {
    match t.debugregs.get() {
        Some(sh) => sh.regs[CONTROL].load(Ordering::Acquire) & DR7_ENABLE_MASK != 0,
        None     => false,
    }
}

/// Drop every breakpoint. `execve` does this (Linux `flush_ptrace_hw_breakpoint`
/// on exec) and so does a fresh task — a breakpoint set against the old program
/// image names an address that no longer belongs to anything.
/// # C: O(1)
pub fn clear(t: &Task) {
    let Some(sh) = t.debugregs.get() else { return };
    let mut i = 0;
    while i < SLOTS { sh.regs[i].store(0, Ordering::Release); i += 1; }
}

/// Accumulate the cause bits of a #DB into the task's DR6 shadow, so its
/// tracer can read WHY the trap fired after the fact. # C: O(1)
pub fn record_status(t: &Task, cause: u64) {
    if let Some(sh) = t.debugregs.get_or_init() { sh.regs[STATUS].fetch_or(cause, Ordering::AcqRel); }
}

#[cfg(target_arch = "x86_64")]
#[path = "debugreg/x86.rs"] pub mod x86;

/// aarch64 exposes hardware breakpoints through the `NT_ARM_HW_BREAK` /
/// `NT_ARM_HW_WATCH` regsets rather than a `struct user` debug window, so its
/// storage is a separate register file with nothing in common beyond being
/// per-task.
#[cfg(target_arch = "aarch64")]
#[path = "debugreg/arm.rs"] pub mod arm;

#[cfg(test)]
#[path = "debugreg/tests.rs"] mod tests;
