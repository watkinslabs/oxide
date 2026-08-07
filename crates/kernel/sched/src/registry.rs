// Module manifest: global tid → Weak<Task> registry per `13§5` / `19§4`.
// Populated at task spawn; entries decay naturally via `Weak::upgrade` once
// the runqueue + zombies drop their last `Arc<Task>`.
//
// Used by procfs to enumerate `/proc/<pid>/` and synthesise per-pid
// `status`/`cmdline`/`stat`/`maps`. Lock order: leaf — callers hold no other
// sched locks.
//
// B1429: the registry was a flat `Vec<(u32, Weak<Task>)>` — every point
// lookup (tid or vpid) scanned it O(N) under the IRQs-off `REG` lock, which
// stalled the whole CPU for the scan's duration on every fork/exec/wait4/
// kill/tgkill/procfs read. `core.rs` now keys the registry by tid in a
// `BTreeMap` (O(log N)) with a self-validating vpid accelerator hint; see
// `core::Registry` for why that hint can never become a second source of
// truth.
//
// - core: `Registry` storage (by_tid + vpid_hint), `REG` lock, shared
//   mechanics (`hint_upsert`, `prune_dead_locked`, `clear_locked`).
// - tid: insert, tid point lookup, SIGCONT stop/cont flip, test reset.
// - vpid: vpid(vtgid)-keyed resolution + the vpid/vtid/parent-vpid display
//   helpers procfs renders.
// - wait: wait4/waitid candidate matching + stop/cont event scan.
// - snapshot: full-registry O(N) walks (procfs readdir, /proc/stat,
//   diagnostics) plus the hard-IRQ-safe `next_live_tid_after`.
// - pidfd: exact pidfd identity acquisition + `release_task`-equivalent reap.

mod core;
mod mm;
mod pidfd;
mod snapshot;
mod tid;
mod vpid;
mod wait;

pub use pidfd::{
    acquire_pidfd_in_namespace, mark_reaped, pidfd_exit_ready, publish_pidfd_exit,
    PidfdAcquireError, PidfdKind,
};
pub use snapshot::{
    kernel_stack_bytes_snapshot, live_counts, live_tids, next_live_tid_after, tasks_traced_by,
    thread_entries, thread_group, try_snapshot,
};
pub use mm::{mm_sharers, thread_group_members};
pub(crate) use mm::{track_mm_before_replace, track_task_before_publish, untrack_mm_after_replace};
pub(crate) use snapshot::set_syscall_tracepoint_work_all;
#[cfg(any(test, feature = "hosted"))]
pub use tid::clear_for_tests;
pub use tid::{insert, lookup, try_wake_stopped, LOOKUPS};
#[cfg(target_os = "oxide-kernel")]
pub use vpid::caller_pid_ns;
pub use vpid::{
    display_vpid, display_vtid, group_chain, lookup_by_vpid, lookup_in_namespace, live_vpids,
    leader_tgid_nr_in, nr_chain_in, parent_vpid, reader_pid_ns, resolve_user_pid, tgid_nr_in, tgid_nr_seen_by,
    vnr_in,
};
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub(crate) use wait::wait_candidate_matches;
pub use wait::{
    child_stop_event, has_children, has_wait_children, task_rusage_both, task_rusage_self, task_rusage_thread,
    tasks_in_pgrp, WaitChildSnapshot,
};
