// Module manifest:
// - `active_mm` owns per-CPU lazy-TLB `active_mm` tracking + parked-mm handoff.
// - `atomic` owns atomic-schedule diagnosis and preempt-count recovery.
// - `hooks` owns sched_switch tracing and teardown stats surface.
// - `irq` owns switch-time IRQ state preservation and bounded idle waits.
// - `lifecycle` owns runqueue install/current-task helpers and teardown glue.
// - `migrate` owns switch-time affinity eviction of the outgoing task.
// - `switch` owns the context-switch engine, finish-task-switch tail, and yield path.
// - `ownership` owns the post-mortem for the `on_cpu` ownership assertion.
// - `ctxprobe` (aarch64, debug-armctx) owns the fatal-fault register-corruption
//   post-mortem: the context save/restore ring + the hal fault-dump hook.
// - `entry_frame` owns task-local x86 fault-frame handoff across task switches.

mod active_mm;
mod atomic;
mod cond;
mod entry_frame;
#[cfg(all(target_arch = "aarch64", feature = "debug-armctx"))]
pub mod ctxprobe;
mod hooks;
mod irq;
mod lifecycle;
pub mod migrate;
mod ownership;
mod provenance;
mod switch;

pub use active_mm::park_active_mm;
pub use cond::cond_resched;
pub(crate) use active_mm::sched_current_cpu;
pub use hooks::{install_sched_switch_hook, RunStats, SchedSwitchFn};
pub use lifecycle::{
    current, current_chroot_root, current_mount_ns, install_default_runqueue,
    mark_done, preempt_schedule_irq, runqueue_active, uninstall_global_with_stats,
};
pub use migrate::{pin_current_to_cpu, unpin_current_cpu};
pub use switch::{oxide_finish_task_switch, park_yield, sched_yield, schedule, tick_yield};
