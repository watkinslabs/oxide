// Linux `kernel/exit.c` decision logic, free of runqueue / arch state so
// `cargo test -p sched` proves it without a QEMU boot.
//
// Module manifest:
//   status  — wait-status encode/decode (`SYSCALL_DEFINE1(exit)`, `wait_task_zombie`)
//   group   — `do_group_exit` effective-code choice
//   notify  — `exit_notify` + `do_notify_parent` autoreap decision
//   reaper  — `find_new_reaper` / `find_child_reaper` target choice
//   orphan  — `will_become_orphaned_pgrp` / `kill_orphaned_pgrp` predicate
//   init    — global-init / pid-ns-init exit consequence
//   task    — `Task`-typed adapters over the pure predicates above

pub mod status;
pub mod group;
pub mod notify;
pub mod reaper;
pub mod orphan;
pub mod init;
mod task;

pub use task::wait_status;

#[cfg(test)]
mod tests;
