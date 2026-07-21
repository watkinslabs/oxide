use core::sync::atomic::{AtomicU8, Ordering};

use crate::Task;

const SYSCALL_RETURN_STAGE_NONE: u8 = 0;
pub const SYSCALL_RETURN_STAGE_AFTER_DISPATCH: u8 = 1;
pub const SYSCALL_RETURN_STAGE_AFTER_DIAG: u8 = 2;
pub const SYSCALL_RETURN_STAGE_AFTER_TIMERS: u8 = 3;
pub const SYSCALL_RETURN_STAGE_AFTER_RSEQ: u8 = 4;
pub const SYSCALL_RETURN_STAGE_AFTER_PTRACE: u8 = 5;

/// Task-owned syscall-return tail stage, read only by watchdog/task dumps. # C: O(1)
pub(crate) struct SyscallReturnState { stage: AtomicU8 }

impl SyscallReturnState {
    pub(crate) const fn new() -> Self { Self { stage: AtomicU8::new(SYSCALL_RETURN_STAGE_NONE) } }
}

/// Publish the current syscall-return tail checkpoint without serial I/O. # C: O(1)
pub fn syscall_return_stage(task: &Task, stage: u8) {
    task.syscall_return.stage.store(stage, Ordering::Release);
}

/// Clear the completed syscall-return tail checkpoint before user return. # C: O(1)
pub fn syscall_return_clear(task: &Task) {
    task.syscall_return.stage.store(SYSCALL_RETURN_STAGE_NONE, Ordering::Release);
}

/// Emit an active syscall-return checkpoint from watchdog/task-dump context. # C: O(1)
pub(crate) fn emit_syscall_return(task: &Task) {
    let stage = task.syscall_return.stage.load(Ordering::Acquire);
    if stage == SYSCALL_RETURN_STAGE_NONE { return; }
    klog::write_raw(b" return-tail=");
    klog::write_raw(stage_name(stage));
}

fn stage_name(stage: u8) -> &'static [u8] {
    match stage {
        SYSCALL_RETURN_STAGE_AFTER_DISPATCH => b"after-dispatch",
        SYSCALL_RETURN_STAGE_AFTER_DIAG => b"after-diag",
        SYSCALL_RETURN_STAGE_AFTER_TIMERS => b"after-timers",
        SYSCALL_RETURN_STAGE_AFTER_RSEQ => b"after-rseq",
        SYSCALL_RETURN_STAGE_AFTER_PTRACE => b"after-ptrace",
        _ => b"unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_stages_and_clear_are_stable() {
        let state = SyscallReturnState::new();
        assert_eq!(state.stage.load(Ordering::Acquire), SYSCALL_RETURN_STAGE_NONE);
        state.stage.store(SYSCALL_RETURN_STAGE_AFTER_TIMERS, Ordering::Release);
        assert_eq!(stage_name(state.stage.load(Ordering::Acquire)), b"after-timers");
        state.stage.store(SYSCALL_RETURN_STAGE_NONE, Ordering::Release);
        assert_eq!(state.stage.load(Ordering::Acquire), SYSCALL_RETURN_STAGE_NONE);
    }
}
