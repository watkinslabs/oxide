// POSIX job-control access to a controlling tty — Linux `__tty_check_change`
// (`drivers/tty/tty_jobctrl.c:33-66`) reached from n_tty's `job_control`
// (`drivers/tty/n_tty.c:2090-2101`) on read and `tty_check_change` on write
// (`28§6`).
//
// Module manifest:
// - `decide`: pure Access/Decision rule + its `VfsError` mapping (host-tested).
// - `live`:   the ONE live gate every tty driver calls — gathers the calling
//             task's context (pgrp, ctty match, stop-signal disposition, orphan
//             status), signals the pgrp on a Stop, returns the decision's error.
//             Kernel-gated: it reads `sched::live`.
// - `tests`:  hosted tests for the rule and for the full decision chain the
//             `userspace/wait_diff` jobctl probe exercises.

mod decide;
pub use decide::{decide, Access, Decision};

#[cfg(target_os = "oxide-kernel")]
mod live;
#[cfg(target_os = "oxide-kernel")]
pub use live::check;

#[cfg(test)]
mod tests;
