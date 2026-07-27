// `Task`-typed adapters over the pure predicates. Kept out of the pure
// submodules so those stay provable from plain values.

use core::sync::atomic::Ordering;

use crate::Task;

/// Linux `wait_task_zombie`: `status = (p->signal->flags & SIGNAL_GROUP_EXIT)
/// ? p->signal->group_exit_code : p->exit_code`.
///
/// The group latch wins so a reaper sees the code `exit_group(2)` asked for,
/// even when this particular task was cut down by the SIGKILL that
/// `zap_other_threads` posted on its behalf.
/// # C: O(1)
pub fn wait_status(task: &Task) -> i32 {
    task.thread_group
        .group_exit_status()
        .unwrap_or_else(|| task.exit_status.load(Ordering::Acquire))
}
