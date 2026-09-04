// `schedule()` - the ONE task-switch primitive per `13§8`.
// the timer/IPI IRQ path only sets `need_resched`; the actual switch
// happens through `schedule()` at the return-to-user slow path
// (`oxide_irq_exit_to_user` -> the return-to-user work loop), at `preempt_enable`
// drop-to-zero, and at voluntary yields (`tick_yield`, kthread exit).
//
// Preempt/IRQ handoff (Linux `context_switch`/`finish_task_switch`):
//   - `schedule()` entry: `preempt_disable` (+1) then `irq_disable`,
//     so the pick + ctx-switch is atomic vs timer/IPI and the rq lock
//     is never held with IRQs on (the UP-only assumption smp-arch.md
//     flags as fatal under SMP).
//   - the INCOMING task runs `finish_task_switch` after the switch:
//     `irq_enable` (Linux `finish_lock_switch` = `raw_spin_unlock_irq`)
//     + `preempt_enable_no_check` (-1). Net 0 per switch; the +1/IRQ
//     state of a frozen switcher is paid by whoever it switched to.
//   - first-run tasks pay the same handoff through the architecture scaffold.
//
// `pick_next_task` + the `if next.mm != prev.mm: switch_address_space`
// AS-swap hook (`13§8`) are unchanged. With v1's single global user AS
// + kthreads (`mm=None`), the AS-swap branch fires only on a
// kthread->user pair; wired via `MmuOps::activate(next.mm.root_pa)`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use hal::{Context, MmuOps};
use crate::{RunqueueInner, SchedClass, Task, TaskState};
use crate::live::runqueue::{global, Runqueue};

use super::active_mm::{active_mm_defer_drop, active_mm_finish_drop, active_mm_grab, sched_current_cpu};
use super::hooks::{fire_sched_switch, sched_switch_hook_installed};
use super::lifecycle::VOLUNTARY;
use super::ownership::report_ownership_conflict;

#[cfg(target_arch = "x86_64")]
type ArchCtx = hal_x86_64::ContextX86_64;
#[cfg(target_arch = "aarch64")]
type ArchCtx = hal_aarch64::ContextAArch64;

#[cfg(target_arch = "x86_64")]
type ActiveMmu = hal_x86_64::mmu_ops::X86Mmu;
#[cfg(target_arch = "aarch64")]
type ActiveMmu = hal_aarch64::mmu_ops::ArmMmu;

mod handoff;
mod round;
mod yield_api;
#[cfg(test)]
mod tests;

pub(super) use round::schedule_once;
pub use handoff::oxide_finish_task_switch;
pub use yield_api::{park_yield, sched_yield, schedule, tick_yield};

/// Settle the elapsed execution interval before a scheduler parameter change
/// rewrites the task's class or weight. Linux does this through
/// `update_rq_clock()` plus `put_prev_task()` inside `sched_change_begin()`.
/// Oxide's running task is outside the class tree, so only the accounting half
/// is needed here; the transaction requests a reschedule after the mutation.
pub(crate) fn settle_running_for_change(task: &Task, inner: &RunqueueInner, now: u64) {
    handoff::update_curr(task, inner, now);
}

/// Restart the accounting clock after a running task's scheduler class or
/// parameters change. Linux's generic `set_next_task()` dispatches to the new
/// class here: Deadline owns a separate CBS clock, while Fair and RT share the
/// scheduler-entity execution stamp.
pub(crate) fn restart_running_after_change(task: &Task, now: u64) {
    if matches!(task.sched_class(), crate::SchedClass::Deadline) {
        crate::deadline::live::set_next_task_dl(task, now);
    } else {
        task.sched.se.exec_start.store(now, core::sync::atomic::Ordering::Release);
    }
}

pub(crate) fn change_clock_now() -> u64 { handoff::now_ns() }
