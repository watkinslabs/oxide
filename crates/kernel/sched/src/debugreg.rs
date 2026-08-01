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

use core::sync::atomic::Ordering;

use crate::Task;

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
/// Indices 4 and 5 alias 6 and 7, as they do in hardware — a write to DR4/DR5
/// is a write to DR6/DR7 unless CR4.DE is set, and Linux exposes the aliased
/// pair through `ptrace_get_debugreg`/`ptrace_set_debugreg` unchanged.
/// # C: O(1)
pub const fn slot_of_u_debugreg(idx: usize) -> Option<usize> {
    match idx {
        0..=3 => Some(idx),
        4 | 6 => Some(STATUS),
        5 | 7 => Some(CONTROL),
        _     => None,
    }
}

/// Whether `idx` names the control register, which is the only slot whose
/// write must be validated before it can reach hardware. # C: O(1)
pub const fn is_control(idx: usize) -> bool { matches!(idx, 5 | 7) }

/// Whether `idx` names the status register, which a tracer may only clear.
/// # C: O(1)
pub const fn is_status(idx: usize) -> bool { matches!(idx, 4 | 6) }

/// Read one `u_debugreg` slot of `t`. # C: O(1)
pub fn get(t: &Task, idx: usize) -> Option<u64> {
    slot_of_u_debugreg(idx).map(|s| t.debugregs[s].load(Ordering::Acquire))
}

/// Store one slot verbatim. Validation is the caller's — a DR7 write must have
/// been through the HAL ladder first. # C: O(1)
pub fn put(t: &Task, slot: usize, v: u64) {
    if slot < SLOTS { t.debugregs[slot].store(v, Ordering::Release); }
}

/// The four breakpoint addresses. # C: O(1)
pub fn addrs(t: &Task) -> [u64; NR_ADDR] {
    let mut a = [0u64; NR_ADDR];
    let mut i = 0;
    while i < NR_ADDR { a[i] = t.debugregs[i].load(Ordering::Acquire); i += 1; }
    a
}

/// At least one breakpoint slot is enabled. # C: O(1)
pub fn armed(t: &Task) -> bool {
    t.debugregs[CONTROL].load(Ordering::Acquire) & DR7_ENABLE_MASK != 0
}

/// Drop every breakpoint. `execve` does this (Linux `flush_ptrace_hw_breakpoint`
/// on exec) and so does a fresh task — a breakpoint set against the old program
/// image names an address that no longer belongs to anything.
/// # C: O(1)
pub fn clear(t: &Task) {
    let mut i = 0;
    while i < SLOTS { t.debugregs[i].store(0, Ordering::Release); i += 1; }
}

/// Accumulate the cause bits of a #DB into the task's DR6 shadow, so its
/// tracer can read WHY the trap fired after the fact. # C: O(1)
pub fn record_status(t: &Task, cause: u64) {
    t.debugregs[STATUS].fetch_or(cause, Ordering::AcqRel);
}

#[cfg(target_arch = "x86_64")]
#[path = "debugreg/x86.rs"] pub mod x86;

#[cfg(test)]
#[path = "debugreg/tests.rs"] mod tests;
