// Liveness diagnostics: on-demand task-state dump (serial sysrq) +
// a no-progress liveness watchdog. Per `05` pre-mortem fix
// ("liveness watchdog (no-progress-N-sec)") and `27`'s `kernel.sysrq`
// surface.

use crate::Task;

pub mod emit;
pub mod format;
#[cfg(feature = "debug-getdents")]
pub mod getdents;
#[cfg(feature = "debug-syscall-return")]
pub mod syscall_return;
pub mod nmi;
pub mod percpu;
pub mod ring;
mod syscall_names;
pub mod sysrq;
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
pub use sysrq::{set_mask as set_sysrq_mask, set_always_enabled as set_sysrq_always_enabled,
                trigger as sysrq_trigger};
pub use format::{copy_into, fmt_dec, syscall_name};
#[cfg(feature = "debug-getdents")]
pub use getdents::{getdents_begin, getdents_clear, getdents_progress, getdents_stage};
#[cfg(feature = "debug-syscall-return")]
pub use syscall_return::{syscall_return_clear, syscall_return_stage,
                         SYSCALL_RETURN_STAGE_AFTER_DIAG, SYSCALL_RETURN_STAGE_AFTER_DISPATCH,
                         SYSCALL_RETURN_STAGE_AFTER_PTRACE, SYSCALL_RETURN_STAGE_AFTER_RSEQ,
                         SYSCALL_RETURN_STAGE_IN_EXIT_TO_USER,
                         SYSCALL_RETURN_STAGE_AFTER_TIMERS};
pub use ring::{dump_exit_recent, note_switch, switches};
#[cfg(any(feature = "debug-taskdump", feature = "debug-polktrace"))]
pub use ring::record_syscall;
#[cfg(test)]
pub(crate) use watchdog::TEST_STALL_NS as STALL_NS;
pub use watchdog::{Beat, WatchdogState, note_interrupted_kernel_pc, watchdog_tick};

#[cfg(test)]
mod tests;
