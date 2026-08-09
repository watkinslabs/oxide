// Fork/exit propagation of `attr.inherit` events — Linux `inherit_task_group`
// (creation side, `perf_event_init_task`) and `sync_child_event` /
// `perf_event_exit_task` (fold-back). Pure over the registry + `PerfEvent`
// API, no target gate, so the propagation and fold-back algebra are
// hosted-testable (`docs/53` — decision logic never lives in a gated shim).
//
// Only TASK-scoped events (`tid` came back `Some` from admission) are ever
// inheritable. A CPU-wide event (`pid == -1`) has no task to follow and is
// invisible to a fork, exactly as `perf_event_init_context` only walks
// `current->perf_event_ctxp` — a per-TASK context, never the per-CPU one.
// Both kinds live in `registry`, which is the single table the sample path
// walks too.

use super::event::PerfEvent;
use super::registry::{live_task_events, retire_task};
use super::uapi::attr_bit;

/// Linux `perf_event_init_task` → `perf_event_init_context` →
/// `inherit_task_group` → `inherit_event`, restricted to the software-only
/// surface oxide implements: every event open against the forking parent
/// with `attr.inherit` set gets a clone that targets the child and starts
/// counting from the fork instant. An event with `attr.inherit` clear is
/// skipped, matching `inherit_task_group`'s `!event->attr.inherit` early
/// return — this is the row-298 gap: before this call a child born after an
/// inheriting event was open got no event at all, so a `waitpid`-time read
/// of the parent silently undercounted.
///
/// `clone_thread` is `flags & CLONE_THREAD`. `inherit_task_group` also skips
/// an event when `(event->attr.inherit_thread && !(clone_flags &
/// CLONE_THREAD))` fails to hold — i.e. by default (`inherit_thread == 0`) an
/// event follows a `fork()`-born PROCESS child but not a `pthread_create()`-
/// born thread, unless the event opted into `PERF_ATTR_INHERIT_THREAD`.
///
/// Returns the number of events inherited, for callers/tests that want to
/// confirm propagation happened.
/// # C: O(N_parent_task_events)
pub fn on_fork(parent_tid: u32, child_tid: u32, clone_thread: bool) -> usize {
    let mut n = 0;
    for ev in live_task_events(parent_tid) {
        if !ev.attr.bit(attr_bit::INHERIT) { continue; }
        if clone_thread && !ev.attr.bit(attr_bit::INHERIT_THREAD) { continue; }
        // `PerfEvent::new_inherited` registers the child itself (every
        // task-scoped event self-registers on construction, which is also
        // where the registry takes its owning keep-alive since an inherited
        // child has no fd of its own), so this loop only decides WHICH
        // parent events qualify.
        let _child = PerfEvent::new_inherited(&ev, child_tid);
        n += 1;
    }
    n
}

/// Linux `perf_event_exit_task` → `perf_event_exit_event` → `sync_child_event`:
/// fold every inherited event this exiting task held back into its parent's
/// `child_count`, then retire the task's registry entry outright — taking
/// back the registry's own keep-alive on each inherited child so it is
/// actually freed here, not merely orphaned. A non-inherited event (this
/// task's own, never anyone's child) folds into nothing — `fold_into_parent`
/// is a no-op without a live `parent` — so it is simply dropped.
/// # C: O(N_tid_events)
pub fn on_task_exit(tid: u32) {
    for ev in retire_task(tid) { ev.fold_into_parent(); }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU32, Ordering};

    use alloc::sync::{Arc, Weak};

    use super::*;
    use crate::perf::attr::PerfAttr;
    use crate::perf::counter::SwSource;

    /// Every test claims a disjoint tid range from this counter so the
    /// process-global event registry cannot let two tests observe
    /// each other's events under `cargo test`'s default parallel threads.
    static NEXT_TID: AtomicU32 = AtomicU32::new(900_000);
    fn fresh_tid() -> u32 { NEXT_TID.fetch_add(1, Ordering::Relaxed) }

    fn attr(inherit: bool) -> PerfAttr {
        let mut a = PerfAttr::default();
        if inherit { a.bits |= 1 << attr_bit::INHERIT; }
        a
    }

    /// Positive control target: set this event's count to `n` by driving its
    /// `SwSource::Zero` accumulator directly (pure state, no real task/clock
    /// dependency needed).
    fn set_count(ev: &Arc<PerfEvent>, n: u64) { ev.state.lock().counter.acc = n; }

    #[test]
    fn inheriting_event_propagates_to_child() {
        let parent_tid = fresh_tid();
        let child_tid = fresh_tid();
        let ev = PerfEvent::new(attr(true), SwSource::Zero, Some(parent_tid), -1, None);
        let n = on_fork(parent_tid, child_tid, false);
        assert_eq!(n, 1);
        let child_events = live_task_events(child_tid);
        assert_eq!(child_events.len(), 1);
        assert!(child_events[0].parent.as_ref().and_then(Weak::upgrade).is_some());
        let _ = ev; // keep parent alive for the duration of the assertions
    }

    #[test]
    fn non_inheriting_event_does_not_propagate() {
        let parent_tid = fresh_tid();
        let child_tid = fresh_tid();
        let ev = PerfEvent::new(attr(false), SwSource::Zero, Some(parent_tid), -1, None);
        let n = on_fork(parent_tid, child_tid, false);
        assert_eq!(n, 0);
        assert!(live_task_events(child_tid).is_empty());
        let _ = ev;
    }

    #[test]
    fn cpu_scoped_event_is_not_inherited() {
        // `tid == None` == a CPU-wide event (`pid == -1` at open): it is
        // never registered against any tid, so a fork of ANY task — even the
        // opening one — must not clone it.
        let parent_tid = fresh_tid();
        let child_tid = fresh_tid();
        let ev = PerfEvent::new(attr(true), SwSource::Zero, None, 0, None);
        let n = on_fork(parent_tid, child_tid, false);
        assert_eq!(n, 0);
        assert!(live_task_events(child_tid).is_empty());
        let _ = ev;
    }

    /// `clone_thread=true` (a `pthread_create`) does not inherit a plain
    /// `attr.inherit` event unless it also set `attr.inherit_thread` —
    /// `inherit_task_group`'s `event->attr.inherit_thread && !(clone_flags &
    /// CLONE_THREAD)` gate.
    #[test]
    fn clone_thread_does_not_inherit_without_inherit_thread() {
        let parent_tid = fresh_tid();
        let child_tid = fresh_tid();
        let ev = PerfEvent::new(attr(true), SwSource::Zero, Some(parent_tid), -1, None);
        let n = on_fork(parent_tid, child_tid, true);
        assert_eq!(n, 0);
        let _ = ev;
    }

    /// The core row-298 contract: a child's count, accumulated after fork,
    /// folds into the PARENT's total once the child exits — a later read on
    /// the parent (`read_value`) must see the sum, not just what the parent
    /// itself counted.
    #[test]
    fn child_exit_folds_count_into_parent() {
        let parent_tid = fresh_tid();
        let child_tid = fresh_tid();
        let parent = PerfEvent::new(attr(true), SwSource::Zero, Some(parent_tid), -1, None);
        set_count(&parent, 10);
        let n = on_fork(parent_tid, child_tid, false);
        assert_eq!(n, 1);
        let child = live_task_events(child_tid).into_iter().next().unwrap();
        set_count(&child, 7);

        let (before, _, _) = parent.read_value();
        assert_eq!(before, 10, "parent read must not see the child's count before exit");

        on_task_exit(child_tid);

        let (after, _, _) = parent.read_value();
        assert_eq!(after, 17, "parent read must fold in the exited child's count");
        // The registry drops the tid slot once its last live event is gone.
        assert!(live_task_events(child_tid).is_empty());
    }

    /// Positive control: without the fold-back call, the child's count is
    /// silently lost — proves the test above can actually fail.
    #[test]
    fn positive_control_without_exit_fold_parent_stays_stale() {
        let parent_tid = fresh_tid();
        let child_tid = fresh_tid();
        let parent = PerfEvent::new(attr(true), SwSource::Zero, Some(parent_tid), -1, None);
        set_count(&parent, 10);
        on_fork(parent_tid, child_tid, false);
        let child = live_task_events(child_tid).into_iter().next().unwrap();
        set_count(&child, 7);
        // Deliberately skip on_task_exit(child_tid) here.
        let (still, _, _) = parent.read_value();
        assert_eq!(still, 10, "without the fold call the parent must NOT see the child's count");
    }

    #[test]
    fn multiple_children_each_fold_into_the_same_parent() {
        let parent_tid = fresh_tid();
        let c1 = fresh_tid();
        let c2 = fresh_tid();
        let parent = PerfEvent::new(attr(true), SwSource::Zero, Some(parent_tid), -1, None);
        on_fork(parent_tid, c1, false);
        set_count(&live_task_events(c1).into_iter().next().unwrap(), 3);
        on_task_exit(c1);
        on_fork(parent_tid, c2, false);
        set_count(&live_task_events(c2).into_iter().next().unwrap(), 4);
        on_task_exit(c2);
        let (total, _, _) = parent.read_value();
        assert_eq!(total, 7);
    }
}
