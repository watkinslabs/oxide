// Liveness diagnostics: on-demand task-state dump (serial sysrq) +
// a no-progress liveness watchdog. Per `05` pre-mortem fix
// ("liveness watchdog (no-progress-N-sec)") and `27`'s `kernel.sysrq`
// surface.

use crate::Task;

pub mod emit;
pub mod format;
pub mod nmi;
pub mod percpu;
pub mod ring;
pub mod watchdog;

#[cfg(target_os = "oxide-kernel")]
pub(super) fn current_task() -> Option<&'static Task> {
    crate::live::current()
}

#[cfg(not(target_os = "oxide-kernel"))]
pub(super) fn current_task() -> Option<&'static Task> {
    None
}

pub use emit::{dump_tasks, note_init_exit, sysrq_rx};
pub use format::{copy_into, fmt_dec, syscall_name};
pub use ring::{dump_exit_recent, note_switch, record_broker_write, record_syscall, switches};
#[cfg(test)]
pub(crate) use watchdog::TEST_STALL_NS as STALL_NS;
pub use watchdog::{Beat, WatchdogState, watchdog_tick};

#[cfg(test)]
mod tests;
