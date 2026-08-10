// Fork/exit propagation tests: what crosses a fork, what a group keeps in
// its shape, what an exit folds back, and the clone lineage a full
// inherit stamps on the child's context.

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
let _perf = crate::perf::hrtimer::tests::wheel();
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
let _perf = crate::perf::hrtimer::tests::wheel();
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
let _perf = crate::perf::hrtimer::tests::wheel();
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
/// thread-follow gate.
#[test]
fn clone_thread_does_not_inherit_without_inherit_thread() {
let _perf = crate::perf::hrtimer::tests::wheel();
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
let _perf = crate::perf::hrtimer::tests::wheel();
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
let _perf = crate::perf::hrtimer::tests::wheel();
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

/// A GROUP survives the fork as a group: the child gets one leader with
/// the same number of siblings, every member points at the child leader,
/// and a grouped read on the child reports the whole group.
///
/// POSITIVE CONTROL: pass `None` for the sibling's leader in `on_fork` and
/// the `group_members` count drops to 1 for each child event, failing the
/// last two assertions.
#[test]
fn a_group_is_inherited_as_a_group() {
let _perf = crate::perf::hrtimer::tests::wheel();
    let parent_tid = fresh_tid();
    let child_tid = fresh_tid();
    let leader = PerfEvent::new(attr(true), SwSource::Zero, Some(parent_tid), -1, None);
    let mut sibs = alloc::vec::Vec::new();
    for _ in 0..2 {
        let s = PerfEvent::new(attr(true), SwSource::Zero, Some(parent_tid), -1,
                               Some(Arc::downgrade(&leader)));
        leader.state.lock().siblings.push(Arc::downgrade(&s));
        sibs.push(s);
    }
    assert_eq!(on_fork(parent_tid, child_tid, false), 3, "leader plus two siblings");

    let kids = live_task_events(child_tid);
    assert_eq!(kids.len(), 3);
    let leaders: alloc::vec::Vec<_> = kids.iter().filter(|k| k.leader.is_none()).collect();
    assert_eq!(leaders.len(), 1, "exactly one child-side leader");
    assert_eq!(leaders[0].siblings().len(), 2, "both siblings joined it");
    for k in kids.iter() {
        assert_eq!(k.group_members().len(), 3,
                   "every member sees the whole inherited group");
    }
    let _ = (leader, sibs);
}

/// A sibling reached on its own is not cloned a second time — the group is
/// inherited exactly once, through its leader.
#[test]
fn a_sibling_is_not_inherited_twice() {
let _perf = crate::perf::hrtimer::tests::wheel();
    let parent_tid = fresh_tid();
    let child_tid = fresh_tid();
    let leader = PerfEvent::new(attr(true), SwSource::Zero, Some(parent_tid), -1, None);
    let sib = PerfEvent::new(attr(true), SwSource::Zero, Some(parent_tid), -1,
                             Some(Arc::downgrade(&leader)));
    leader.state.lock().siblings.push(Arc::downgrade(&sib));
    assert_eq!(on_fork(parent_tid, child_tid, false), 2);
    assert_eq!(live_task_events(child_tid).len(), 2);
    let _ = (leader, sib);
}

/// A group whose LEADER does not inherit is not inherited at all, however
/// its siblings are configured: the leader's setting decides for the group.
#[test]
fn a_non_inheriting_leader_takes_its_whole_group_with_it() {
let _perf = crate::perf::hrtimer::tests::wheel();
    let parent_tid = fresh_tid();
    let child_tid = fresh_tid();
    let leader = PerfEvent::new(attr(false), SwSource::Zero, Some(parent_tid), -1, None);
    let sib = PerfEvent::new(attr(true), SwSource::Zero, Some(parent_tid), -1,
                             Some(Arc::downgrade(&leader)));
    leader.state.lock().siblings.push(Arc::downgrade(&sib));
    assert_eq!(on_fork(parent_tid, child_tid, false), 0);
    assert!(live_task_events(child_tid).is_empty());
    let _ = (leader, sib);
}

/// `inherit_stat` publishes the dying child's own final values as a record,
/// so a consumer sees the per-child breakdown and not only the parent's
/// folded total.
///
/// POSITIVE CONTROL: the same test without the flag (below) must find no
/// such record, which proves this one is measuring the flag.
#[test]
fn inherit_stat_publishes_the_childs_final_read_at_exit() {
let _perf = crate::perf::hrtimer::tests::wheel();
    use crate::perf::ring::PerfBuffer;
    use crate::perf::uapi::record as rec;
    let parent_tid = fresh_tid();
    let child_tid = fresh_tid();
    let mut a = attr(true);
    a.bits |= 1 << attr_bit::INHERIT_STAT;
    let parent = PerfEvent::new(a, SwSource::Zero, Some(parent_tid), -1, None);
    let rb = PerfBuffer::hosted(4, 0, false);
    parent.state.lock().buffer = Some(Arc::clone(&rb));
    on_fork(parent_tid, child_tid, false);
    let child = live_task_events(child_tid).into_iter().next().unwrap();
    set_count(&child, 11);

    let before = rb.unread();
    on_task_exit(child_tid);
    assert!(rb.unread() > before, "the child's exit published a record");
    let rec_ty = u32::from_le_bytes(rb.peek_data(before, 4).try_into().unwrap());
    assert_eq!(rec_ty, rec::READ);
    // `{pid, tid}` then the counter value in the default read format.
    let body = rb.peek_data(before + 8, 16);
    assert_eq!(u32::from_le_bytes(body[4..8].try_into().unwrap()), child_tid);
    assert_eq!(u64::from_le_bytes(body[8..16].try_into().unwrap()), 11);
    // The fold still happens: both halves of the contract, not one.
    assert_eq!(parent.read_value().0, 11);
}

#[test]
fn positive_control_without_inherit_stat_no_record_is_published() {
let _perf = crate::perf::hrtimer::tests::wheel();
    use crate::perf::ring::PerfBuffer;
    let parent_tid = fresh_tid();
    let child_tid = fresh_tid();
    let parent = PerfEvent::new(attr(true), SwSource::Zero, Some(parent_tid), -1, None);
    let rb = PerfBuffer::hosted(4, 0, false);
    parent.state.lock().buffer = Some(Arc::clone(&rb));
    on_fork(parent_tid, child_tid, false);
    set_count(&live_task_events(child_tid).into_iter().next().unwrap(), 11);
    let before = rb.unread();
    on_task_exit(child_tid);
    assert_eq!(rb.unread(), before, "no flag, no record");
    assert_eq!(parent.read_value().0, 11, "the fold is unconditional");
}

/// A grandchild links back to the ROOT event — the one with the fd — and
/// not to the thread in the middle. A fork/exec/exit pipeline routinely
/// outlives its middle thread, and a chained link would take the
/// grandchild's whole count with it when that thread went.
///
/// POSITIVE CONTROL: linking the grandchild to its immediate parent
/// instead leaves the root reading 3 here rather than 12.
#[test]
fn a_grandchilds_count_survives_the_middle_thread_exiting_first() {
    let _perf = crate::perf::hrtimer::tests::wheel();
    let (root_tid, mid_tid, leaf_tid) = (fresh_tid(), fresh_tid(), fresh_tid());
    let root = PerfEvent::new(attr(true), SwSource::Zero, Some(root_tid), -1, None);
    set_count(&root, 3);
    assert_eq!(on_fork(root_tid, mid_tid, false), 1);
    assert_eq!(on_fork(mid_tid, leaf_tid, false), 1);
    let leaf = live_task_events(leaf_tid).into_iter().next().unwrap();
    assert!(Arc::ptr_eq(&leaf.parent.as_ref().and_then(Weak::upgrade).unwrap(), &root),
            "the grandchild links to the root, not to the thread in the middle");
    set_count(&leaf, 9);
    // The middle thread exits FIRST, taking its own event with it.
    on_task_exit(mid_tid);
    on_task_exit(leaf_tid);
    assert_eq!(root.read_value().0, 12, "the grandchild's count reached the root");
}

/// An inherited child follows the state its parent event is actually IN, not
/// the `attr.disabled` bit it was opened with: an event opened disabled and
/// then enabled through its fd must have its children counting.
#[test]
fn an_inherited_child_follows_the_parents_live_state_not_its_attr() {
    let _perf = crate::perf::hrtimer::tests::wheel();
    let mut a = attr(true);
    a.bits |= 1 << attr_bit::DISABLED;
    let (p, c) = (fresh_tid(), fresh_tid());
    let parent = PerfEvent::new(a, SwSource::Zero, Some(p), -1, None);
    assert!(!parent.state.lock().counter.enabled, "opened disabled");
    parent.state.lock().counter.enable(0, now_ns());
    on_fork(p, c, false);
    let child = live_task_events(c).into_iter().next().unwrap();
    assert!(child.state.lock().counter.enabled,
            "a child of an enabled event counts, whatever the attr said");
    let _ = parent;
}

/// And the converse: a parent disabled through its fd hands its children a
/// stopped counter even though `attr.disabled` is clear.
#[test]
fn a_disabled_parent_hands_its_child_a_stopped_counter() {
    let _perf = crate::perf::hrtimer::tests::wheel();
    let (p, c) = (fresh_tid(), fresh_tid());
    let parent = PerfEvent::new(attr(true), SwSource::Zero, Some(p), -1, None);
    parent.state.lock().counter.disable(0, now_ns());
    on_fork(p, c, false);
    let child = live_task_events(c).into_iter().next().unwrap();
    assert!(!child.state.lock().counter.enabled);
    let _ = parent;
}

/// A partial inherit does not claim a clone: the child still gets the events
/// that qualified, but its context records no lineage, so nothing later pairs
/// two lists that do not line up.
#[test]
fn a_partial_inherit_leaves_the_child_unstamped() {
    let _perf = crate::perf::hrtimer::tests::wheel();
    let (p, c) = (fresh_tid(), fresh_tid());
    let yes = PerfEvent::new(attr(true), SwSource::Zero, Some(p), -1, None);
    let no  = PerfEvent::new(attr(false), SwSource::Zero, Some(p), -1, None);
    assert_eq!(on_fork(p, c, false), 1, "only the inheriting event crossed");
    assert_eq!(with_context(c, |x| x.parent_ctx), Some(None), "no lineage claimed");
    let _ = (yes, no);
}

/// A full inherit does claim one, at the parent's current version.
#[test]
fn a_full_inherit_stamps_the_child_as_a_clone() {
    let _perf = crate::perf::hrtimer::tests::wheel();
    let (p, c) = (fresh_tid(), fresh_tid());
    let ev = PerfEvent::new(attr(true), SwSource::Zero, Some(p), -1, None);
    on_fork(p, c, false);
    let (id, generation) = with_context(p, |x| (x.id, x.generation)).unwrap();
    assert_eq!(with_context(c, |x| (x.parent_ctx, x.parent_gen)),
               Some((Some(id), generation)));
    let _ = ev;
}

#[test]
fn multiple_children_each_fold_into_the_same_parent() {
let _perf = crate::perf::hrtimer::tests::wheel();
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
