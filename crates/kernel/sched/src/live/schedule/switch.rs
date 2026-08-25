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

/// Largest CPU-time delta charged in one `update_curr` - the scheduler
/// tick period (10ms @ 100Hz). Caps a single charge against clock skew /
/// a long IRQ-off window per `13§3`.
const MAX_TICK_NS: u64 = 10_000_000;

mod handoff;
mod round;
mod yield_api;
#[cfg(test)]
mod tests;

pub(super) use round::schedule_once;
pub use handoff::oxide_finish_task_switch;
pub use yield_api::{park_yield, sched_yield, schedule, tick_yield};
