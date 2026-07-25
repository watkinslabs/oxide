// Module manifest:
// - `active_mm` owns per-CPU lazy-TLB `active_mm` tracking + parked-mm handoff.
// - `hooks` owns sched_switch tracing and teardown stats surface.
// - `lifecycle` owns runqueue install/current-task helpers and teardown glue.
// - `switch` owns the context-switch engine, finish-task-switch tail, and yield path.
// - `ctxprobe` (aarch64, debug-armctx) owns the fatal-fault register-corruption
//   post-mortem: the context save/restore ring + the hal fault-dump hook.

mod active_mm;
#[cfg(all(target_arch = "aarch64", feature = "debug-armctx"))]
pub mod ctxprobe;
mod hooks;
mod lifecycle;
mod switch;

pub use active_mm::park_active_mm;
pub use hooks::{install_sched_switch_hook, RunStats, SchedSwitchFn};
pub use lifecycle::{
    current, current_chroot_root, current_mount_ns, install_default_runqueue,
    mark_done, runqueue_active, uninstall_global_with_stats,
};
pub use switch::{oxide_finish_task_switch, park_yield, sched_yield, schedule, tick_yield};
