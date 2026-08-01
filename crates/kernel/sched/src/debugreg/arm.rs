// Per-task aarch64 hardware breakpoint / watchpoint state — the storage half.
//
// The register contract (DBGBCR/DBGWCR fields, the validation ladder, the
// regset byte layout, the debug-exception classifier) belongs to the
// architecture and lives in the HAL. This file owns only where a task keeps
// its copy and when that copy reaches hardware.
//
// The x86 counterpart is `debugreg::x86`. The two are deliberately NOT
// unified: x86 exposes its debug registers through `struct user`'s
// `u_debugreg` window, aarch64 through the `NT_ARM_HW_BREAK` /
// `NT_ARM_HW_WATCH` regsets, and the register files have nothing in common
// beyond both being per-task.

use core::cell::UnsafeCell;

use hal_aarch64::hw_breakpoint::{self as hbp, HwBpError, HwBreakpointState, RegFile};

use crate::Task;

/// The register file behind the task's lazy slot.
pub struct Shadow(UnsafeCell<HwBreakpointState>);

impl Default for Shadow {
    fn default() -> Self { Self(UnsafeCell::new(HwBreakpointState::empty())) }
}

// SAFETY: the contents follow the same single-mutator rule as `fpu_state` per `13§5` — the owning task on its own CPU, or a tracer while the tracee is ptrace-stopped and so cannot be picked — so sharing the handle across threads is sound.
unsafe impl Sync for Shadow {}
// SAFETY: `HwBreakpointState` is plain `Copy` data with no interior pointers or thread affinity.
unsafe impl Send for Shadow {}

/// Snapshot a task's state. A task that never armed anything answers from the
/// reset value without touching an allocation.
/// # C: O(1)
pub fn snapshot(t: &Task) -> HwBreakpointState {
    let Some(sh) = t.hw_break.get() else { return HwBreakpointState::empty() };
    // SAFETY: single-mutator rule per `13§5` as documented on `Shadow` — the owning task on its own CPU, or a tracer while the tracee is ptrace-stopped.
    unsafe { *sh.0.get() }
}

/// Replace a task's state wholesale, allocating the register file on first
/// use. `SETREGSET` validates the entire buffer before calling this, so a
/// partially-accepted write is never installed.
/// # C: O(1)
pub fn store(t: &Task, st: &HwBreakpointState) {
    let Some(sh) = t.hw_break.get_or_init() else { return };
    // SAFETY: same single-mutator rule as `snapshot`; `HwBreakpointState` is plain `Copy` data with no interior pointers or handles.
    unsafe { *sh.0.get() = *st; }
}

/// At least one slot enabled — the context-switch gate. # C: O(N_slots)
pub fn armed(t: &Task) -> bool { snapshot(t).is_armed() }

/// Drop every breakpoint and watchpoint. `execve` does this: a breakpoint set
/// against the old program image names an address that now belongs to
/// different code.
/// # C: O(1)
pub fn clear(t: &Task) {
    // Nothing to clear if nothing was ever armed — and no reason to allocate.
    if t.hw_break.get().is_some() { store(t, &HwBreakpointState::empty()); }
}

/// Install one slot, through the architecture's validation ladder. Nothing is
/// stored unless it passes, so a refused write leaves the slot as it was.
/// # C: O(1)
pub fn set_slot(t: &Task, file: RegFile, idx: usize, addr: u64, ctrl: u32)
    -> Result<(), HwBpError>
{
    let mut st = snapshot(t);
    st.set_addr(file, idx, addr)?;
    st.set_ctrl(file, idx, ctrl)?;
    store(t, &st);
    Ok(())
}

/// Slots this machine implements for `file`, read from the CPU's own ID
/// register at boot — never a hard-coded count. It varies by implementation,
/// and a tracer is told the real number through `dbg_info`.
/// # C: O(1)
pub fn slots(file: RegFile) -> u8 {
    match file { RegFile::Break => hbp::num_brps(), RegFile::Watch => hbp::num_wrps() }
}

/// The `dbg_info` word `GETREGSET` reports in the regset header: the debug
/// architecture version and this machine's slot count for `file`.
/// # C: O(1)
pub fn dbg_info(file: RegFile) -> u32 {
    match file { RegFile::Break => hbp::idreg::break_dbg_info(), RegFile::Watch => hbp::idreg::watch_dbg_info() }
}

/// Install `t`'s debug registers on this CPU. Writes nothing when neither the
/// outgoing nor the incoming task has a slot armed, which is every switch on a
/// machine with no debugger attached.
/// # SAFETY: caller is the context switch at EL1 with this CPU's debug
/// registers owned by the scheduler for the duration.
/// # C: O(N_slots)
#[cfg(target_os = "oxide-kernel")]
#[inline(never)]
pub unsafe fn switch_to(prev: &Task, next: &Task) {
    // The register file is hundreds of bytes, so it is BORROWED in place and
    // never copied onto the caller's frame: this runs inside `schedule`, which
    // sits on the deepest syscall chain the stack gate measures. `#[inline(never)]`
    // keeps even the borrow bookkeeping out of that frame, since the common
    // case returns without touching either state.
    let (Some(p), Some(n)) = (prev.hw_break.get(), next.hw_break.get()) else {
        // At most one side is armed; a null slot IS the reset state, so a
        // half-armed switch only has to install the side that exists.
        // SAFETY: forwarded contract — the context switch owns both tasks, so
        // neither runs concurrently and this CPU's debug registers are the
        // scheduler's for the duration.
        return unsafe { switch_one(prev, next) };
    };
    // SAFETY: single-mutator rule per `13§5` as documented on `Shadow`; the context switch owns both tasks here and neither can run concurrently.
    let (pr, nr) = unsafe { (&*p.0.get(), &*n.0.get()) };
    if !pr.is_armed() && !nr.is_armed() { return; }
    // SAFETY: forwarded contract — context switch at EL1, this CPU's debug registers are the scheduler's for the duration of the switch.
    unsafe { hbp::hw::switch(pr, nr, hbp::num_brps(), hbp::num_wrps()); }
}

/// The at-most-one-side-allocated case, kept out of `switch_to` so the common
/// both-null switch costs one branch and no stack.
/// # SAFETY: same contract as `switch_to`.
/// # C: O(N_slots)
#[cfg(target_os = "oxide-kernel")]
#[inline(never)]
unsafe fn switch_one(prev: &Task, next: &Task) {
    let armed_prev = prev.hw_break.get().is_some_and(|s| {
        // SAFETY: single-mutator rule per `13§5`; the context switch owns this task.
        unsafe { (*s.0.get()).is_armed() }
    });
    match next.hw_break.get() {
        // SAFETY: context switch at EL1 owns this CPU's debug registers; `s` is the incoming task's live register file.
        Some(s) => unsafe {
            let n = &*s.0.get();
            if n.is_armed() || armed_prev { hbp::hw::load(n, hbp::num_brps(), hbp::num_wrps()); }
        },
        // SAFETY: context switch at EL1 owns this CPU's debug registers; disarming is the reset state the incoming task has.
        None => if armed_prev { unsafe { hbp::hw::disarm_all(hbp::num_brps(), hbp::num_wrps()); } },
    }
}

/// Classify a debug exception against `t`'s armed slots. `None` means the
/// exception was not one this task armed.
/// # C: O(N_slots)
pub fn classify(t: &Task, esr: u64, far: u64, pc: u64) -> Option<hbp::DebugEvent> {
    let st = snapshot(t);
    hbp::classify(esr, far, pc, &st, hbp::num_brps(), hbp::num_wrps())
}

/// Read this CPU's debug feature register and cache the implemented slot
/// counts. Runs once during boot, before any task can arm a breakpoint.
/// # SAFETY: caller is early boot at EL1; the debug feature register is
/// read-only with no side effects.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn init_slot_counts() {
    // SAFETY: forwarded contract — early boot at EL1, read-only feature register.
    unsafe { hbp::idreg::init(); }
}
