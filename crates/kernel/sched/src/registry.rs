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
    kernel_stack_bytes_snapshot, live_counts, live_tids, next_live_tid_after, thread_entries,
    try_snapshot,
};
#[cfg(any(test, feature = "hosted"))]
pub use tid::clear_for_tests;
pub use tid::{insert, lookup, try_wake_stopped, LOOKUPS};
pub use vpid::{
    display_vpid, display_vtid, lookup_by_vpid, lookup_in_namespace, live_vpids, parent_vpid,
    resolve_user_pid,
};
pub(crate) use wait::wait_candidate_matches;
pub use wait::{
    has_children, has_wait_children, peek_child_stop_event, take_child_stop_event,
    tasks_in_pgrp, WaitChildSnapshot,
};
