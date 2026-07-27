// Hosted proof of the `kernel/exit.c` decision logic.
//
// Module manifest:
//   status  — exit-code truncation, WIFEXITED/WIFSIGNALED/WCOREDUMP encoding
//   group   — do_group_exit latch, incl. exit_group from a non-leader thread
//   notify  — exit_notify autoreap under SIG_IGN / SA_NOCLDWAIT
//   reaper  — find_new_reaper sibling / subreaper / namespace-init order
//   orphan  — orphaned-process-group SIGHUP+SIGCONT predicate
//   init    — global-init panic vs pid-ns teardown
//   thread_group — the same latch driven through the real `ThreadGroup`

mod status;
mod group;
mod notify;
mod reaper;
mod orphan;
mod init;
mod thread_group;
