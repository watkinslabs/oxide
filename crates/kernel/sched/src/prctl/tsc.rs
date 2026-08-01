// `prctl(PR_SET_TSC / PR_GET_TSC)` — per-task counter-read trapping.
//
// The mode is task state (`Task::tsc_sigsegv`); the trap itself is a CPU
// register that only holds while that task is on the CPU, so it is re-asserted
// on every context switch whose two tasks disagree — the same shape as Linux
// carrying `TIF_NOTSC` / `TIF_TSC_SIGSEGV` through `__switch_to`.
//
//   x86_64  `CR4.TSD`. A trapped `rdtsc`/`rdtscp` at CPL=3 raises `#GP(0)`,
//           which the user-fault classifier already turns into SIGSEGV
//           (`SI_KERNEL`) — the same signal Linux's `#GP` path delivers.
//   aarch64 `CNTKCTL_EL1.EL0{P,V}CTEN`. A trapped `mrs CNTVCT_EL0` raises a
//           sysreg trap (ESR EC 0x18), which the sysreg handler normally
//           EMULATES; the emulator asks `tsc_denied` first and raises SIGSEGV
//           instead when the mode is armed. Emulating it regardless would make
//           `PR_TSC_SIGSEGV` a lie on the arch where the counter is a sysreg.
//
// Decision logic is pure and ungated so `cargo test` reaches it; the two
// privileged writes live behind `hw`, selected at the module boundary.

use syscall::errno::Errno;

use super::uapi::{PR_TSC_ENABLE, PR_TSC_SIGSEGV};
use crate::task::Task;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[path = "tsc/hw_x86.rs"] mod hw;
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[path = "tsc/hw_arm.rs"] mod hw;
#[cfg(not(all(any(target_arch = "x86_64", target_arch = "aarch64"), target_os = "oxide-kernel")))]
#[path = "tsc/hw_host.rs"] mod hw;

/// `set_tsc_mode(val)`: `PR_TSC_SIGSEGV` arms the trap, `PR_TSC_ENABLE`
/// disarms it, anything else is EINVAL. `classify` has already rejected the
/// third case, so this is total over what reaches it — but it is the one
/// place that owns the value→flag mapping, and it is tested directly.
/// # C: O(1)
pub fn mode_to_flag(val: u32) -> Result<bool, Errno> {
    match val {
        PR_TSC_SIGSEGV => Ok(true),
        PR_TSC_ENABLE => Ok(false),
        _ => Err(Errno::Einval),
    }
}

/// `get_tsc_mode`: the `unsigned int` written through the user pointer.
/// # C: O(1)
pub fn flag_to_mode(armed: bool) -> u32 {
    if armed { PR_TSC_SIGSEGV } else { PR_TSC_ENABLE }
}

/// Store the mode on `cur` and make it true of the CPU `cur` is running on.
///
/// Linux runs both under `preempt_disable()` so the flag and the register
/// cannot be observed disagreeing; the caller here is the syscall path, which
/// is already the single mutator of its own task's state, and the register
/// write is a no-op when the bit already matches.
/// # C: O(1)
pub fn apply(cur: &Task, armed: bool) {
    cur.tsc_sigsegv.store(armed, core::sync::atomic::Ordering::Release);
    // SAFETY: per-CPU control register write, legal at the kernel's privilege
    // level; `cur` is the task running on this CPU so the register and the
    // flag describe the same thread.
    unsafe { hw::set_trapped(armed) };
}

/// Re-assert the incoming task's mode across a context switch.
///
/// Called with `prev`'s mode and `next`'s, so an unchanged mode costs one
/// compare — Linux's `if ((tifp ^ tifn) & _TIF_NOTSC)`. Skipping the compare
/// would put a serialising control-register write on every switch.
/// # C: O(1)
/// # Ctx: schedule(); preempt-off
pub fn switch_to(prev_armed: bool, next_armed: bool) {
    if prev_armed == next_armed { return; }
    // SAFETY: runs inside `schedule()`'s preempt-off scope, where this CPU is
    // the sole writer of its own counter-trap control register, and `next` is
    // the task about to run here.
    unsafe { hw::set_trapped(next_armed) };
}

/// True when `cur` may not read the counter — the predicate the aarch64
/// sysreg-trap emulator consults before it hands back a counter value.
/// # C: O(1)
pub fn denied(cur: &Task) -> bool {
    cur.tsc_sigsegv.load(core::sync::atomic::Ordering::Acquire)
}

// The HAL's EL0 counter-read trap emulator upcalls into this policy; the
// symbols only exist on the target that has the trap.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[path = "tsc/upcall.rs"] mod upcall;

#[cfg(test)]
#[path = "tsc/tests.rs"]
mod tests;
