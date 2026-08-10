// The per-task event context: one object per thread that owns that thread's
// event list, its clone lineage, and the modification generation the
// equivalence test reads.
//
// A task-scoped event never stands alone. It belongs to the context of the
// thread it counts, and that context is what a fork clones, what a switch
// compares, and what an exit retires. Before this module the per-tid event
// list was the whole of it, which is enough to find events and not enough to
// answer the two questions a clone lineage answers: is the context this task
// is carrying the same one, at the same version, that the task it is switching
// with carries; and which event is the ROOT of an inherited tree once the
// thread in the middle is gone.
//
// Pure over its own state — no target gate — so equivalence, generation
// accounting, clone stamping and the pairwise mid-life synchronisation are all
// hosted-testable (`docs/53`).

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::event::PerfEvent;
use super::uapi::attr_bit;

/// Context identity allocator. An id, not an address: lineage outlives the
/// context it names (a root context can be retired while a grandchild still
/// records it as its parent), and a raw pointer that outlives its object is
/// exactly the comparison that can accidentally match a later allocation.
static NEXT_CTX_ID: AtomicU64 = AtomicU64::new(1);

/// One registration inside a context. `weak` is the uniform handle used for
/// lookup and for orphan detection (a closed fd drops the event's only OTHER
/// owner, so `weak` dies and the entry prunes itself). `owner` is the
/// context's OWN keep-alive, populated only for a fork-inherited child: unlike
/// a `perf_event_open`-ed event, which its fd's inode keeps alive, an
/// inherited child has no fd at all, so its context must be its strong owner
/// until the task exits.
pub struct Entry {
    pub weak:  Weak<PerfEvent>,
    pub owner: Option<Arc<PerfEvent>>,
}

/// One thread's event context.
pub struct PerfContext {
    /// Stable identity, referenced by descendants' `parent_ctx`.
    pub id:         u64,
    /// The thread this context is attached to.
    pub task:       u32,
    /// Bumped on every list modification, so a lineage recorded at one instant
    /// can be detected as stale at a later one.
    pub generation: u64,
    /// The context this one was cloned from at fork, FLATTENED to the root of
    /// the tree: a grandchild records the root, never the thread in the middle,
    /// so the lineage survives the middle thread exiting first.
    pub parent_ctx: Option<u64>,
    /// The parent's `generation` at the instant of the clone.
    pub parent_gen: u64,
    /// Events in this context that asked for per-task counts
    /// (`attr.inherit_stat`) — the mid-life synchronisation is skipped
    /// outright when this is zero.
    pub nr_stat:    usize,
    /// The event list, in registration order. Order is what pairs a parent's
    /// events with a clone's during synchronisation, and it holds because a
    /// clone is only ever stamped when EVERY event was inherited.
    pub events:     Vec<Entry>,
}

impl PerfContext {
    /// A fresh, unclonedcontext for `task`. # C: O(1)
    pub fn new(task: u32) -> Self {
        PerfContext {
            id: NEXT_CTX_ID.fetch_add(1, Ordering::Relaxed),
            task, generation: 0, parent_ctx: None, parent_gen: 0,
            nr_stat: 0, events: Vec::new(),
        }
    }

    /// `list_add_event` — register `ev` here and bump the generation.
    /// # C: O(live events)
    pub fn add(&mut self, ev: &Arc<PerfEvent>) {
        self.prune();
        if ev.attr.bit(attr_bit::INHERIT_STAT) { self.nr_stat += 1; }
        let owner = if ev.parent.is_some() { Some(Arc::clone(ev)) } else { None };
        self.events.push(Entry { weak: Arc::downgrade(ev), owner });
        self.generation = self.generation.wrapping_add(1);
    }

    /// `list_del_event` for every entry whose event is gone: a closed fd is a
    /// removal, and it must move the generation exactly as an explicit one
    /// does or a stale lineage keeps testing equivalent. # C: O(live events)
    pub fn prune(&mut self) {
        let before = self.events.len();
        self.events.retain(|e| e.weak.strong_count() > 0);
        let removed = before - self.events.len();
        if removed == 0 { return; }
        // A freed event can no longer be asked whether it wanted per-task
        // counts, so the count is retaken from the survivors rather than
        // decremented — exact, over a list this short.
        self.nr_stat = self.events.iter()
            .filter_map(|e| e.weak.upgrade())
            .filter(|ev| ev.attr.bit(attr_bit::INHERIT_STAT))
            .count();
        self.generation = self.generation.wrapping_add(removed as u64);
    }

    /// Live events here, pruning as it goes. # C: O(events)
    pub fn snapshot(&mut self) -> Vec<Arc<PerfEvent>> {
        self.prune();
        self.events.iter().filter_map(|e| e.weak.upgrade()).collect()
    }

    /// The lineage a fork of this context hands its child: this context at its
    /// current version, or — when this one is ITSELF a clone — the root it was
    /// cloned from, which is what keeps an inheriting tree two levels deep
    /// instead of arbitrarily deep. # C: O(1)
    pub fn clone_stamp(&self) -> CloneStamp {
        match self.parent_ctx {
            Some(root) => CloneStamp { ctx: root,    gen: self.parent_gen },
            None       => CloneStamp { ctx: self.id, gen: self.generation },
        }
    }

    /// Record this context as a clone. # C: O(1)
    pub fn stamp_clone(&mut self, s: CloneStamp) {
        self.parent_ctx = Some(s.ctx);
        self.parent_gen = s.gen;
    }
}

/// A context's identity and version, as recorded by the contexts cloned from
/// it. Copied out of the parent rather than borrowed, so the table is held
/// still for one read and not for the whole fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CloneStamp { pub ctx: u64, pub gen: u64 }

/// Whether two contexts are the same context at the same version — both cloned
/// from one version of one context, so their event lists pair up positionally.
///
/// Three ways that holds: one is the other's parent, the other way round, or
/// both were cloned from the same version of the same third context.
/// # C: O(1)
pub fn context_equiv(a: &PerfContext, b: &PerfContext) -> bool {
    if b.parent_ctx == Some(a.id) && b.parent_gen == a.generation { return true; }
    if a.parent_ctx == Some(b.id) && a.parent_gen == b.generation { return true; }
    a.parent_ctx.is_some() && a.parent_ctx == b.parent_ctx && a.parent_gen == b.parent_gen
}

/// The pairs two equivalent contexts synchronise, positionally, up to the
/// shorter list. Split out from the walk so the pairing rule itself is
/// testable without any live event. # C: O(min(len))
pub fn stat_pairs(a: &mut PerfContext, b: &mut PerfContext)
    -> Vec<(Arc<PerfEvent>, Arc<PerfEvent>)>
{
    if a.nr_stat == 0 { return Vec::new(); }
    let (ea, eb) = (a.snapshot(), b.snapshot());
    ea.into_iter().zip(eb).collect()
}

/// `perf_event_task_sched_out`'s context half: when the two threads either
/// side of a context switch carry equivalent contexts, bring every
/// `attr.inherit_stat` pair up to date, so a consumer reading either side
/// MID-LIFE — through a `read(2)` or, with no syscall at all, through the
/// mapped control page — sees that thread's own count rather than the value
/// frozen at the last time something happened to touch the event.
///
/// Attachment: a context stays with the thread it counts for its whole life.
/// The pairwise value exchange the reference performs at this point repairs an
/// attribution its own fast path has just broken by handing each thread the
/// OTHER's context object; with the contexts left in place there is nothing to
/// repair, and exchanging the values here would be the defect rather than the
/// fix. Pinned by `each_side_keeps_its_own_tasks_count`.
///
/// Runs from the deferred bottom half that already carries the switch's two
/// identities, never from the switch path itself: it allocates, and the
/// context-switch path may not.
/// # C: O(1) when either thread has no context or no `inherit_stat` event
pub fn sched_out(prev_tid: u32, next_tid: u32) {
    if prev_tid == next_tid { return; }
    let pairs = super::registry::with_context_pair(prev_tid, next_tid, |a, b| {
        if !context_equiv(a, b) { return Vec::new(); }
        stat_pairs(a, b)
    });
    for (x, y) in pairs { sync_stat(&x); sync_stat(&y); }
}

/// One event's half of the synchronisation: fold everything it has counted so
/// far into its stored value and republish the control page from it. Silent
/// for an event that did not ask for per-task counts. # C: O(1)
pub fn sync_stat(ev: &Arc<PerfEvent>) {
    if !ev.attr.bit(attr_bit::INHERIT_STAT) { return; }
    ev.sync_now();
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;

    use super::*;
    use crate::perf::attr::PerfAttr;
    use crate::perf::counter::SwSource;
    use crate::perf::inherit::on_fork;
    use crate::perf::registry::live_task_events;
    use crate::perf::ring::PerfBuffer;

    fn ctx(task: u32) -> PerfContext { PerfContext::new(task) }

    /// Disjoint tid ranges per test: the event table is process-global and
    /// `cargo test` runs these in parallel.
    static NEXT_TID: AtomicU32 = AtomicU32::new(700_000);
    fn fresh_tid() -> u32 { NEXT_TID.fetch_add(1, Ordering::Relaxed) }

    fn attr(stat: bool) -> PerfAttr {
        let mut a = PerfAttr::default();
        a.bits |= 1 << attr_bit::INHERIT;
        if stat { a.bits |= 1 << attr_bit::INHERIT_STAT; }
        a
    }

    fn set_count(ev: &Arc<PerfEvent>, n: u64) { ev.state.lock().counter.acc = n; }

    /// A parent with a mapped ring, one inheriting child, and the counts each
    /// has run up so far.
    struct Tree {
        parent:  Arc<PerfEvent>,
        child:   Arc<PerfEvent>,
        rb:      Arc<PerfBuffer>,
        p_tid:   u32,
        c_tid:   u32,
    }

    fn tree(stat: bool, p_count: u64, c_count: u64) -> Tree {
        let (p_tid, c_tid) = (fresh_tid(), fresh_tid());
        let parent = PerfEvent::new(attr(stat), SwSource::Zero, Some(p_tid), -1, None);
        let rb = PerfBuffer::hosted(4, 0, false);
        parent.state.lock().buffer = Some(Arc::clone(&rb));
        assert_eq!(on_fork(p_tid, c_tid, false), 1);
        let child = live_task_events(c_tid).into_iter().next().expect("child event");
        set_count(&parent, p_count);
        set_count(&child, c_count);
        Tree { parent, child, rb, p_tid, c_tid }
    }

    /// THE row-298 clause: a parent and a RUNNING child. Every context switch
    /// between the two republishes each side's own count, so a consumer sees
    /// the parent's running total mid-life — without a syscall, and without
    /// waiting for the child to exit.
    ///
    /// POSITIVE CONTROL: `without_per_task_counts_a_switch_publishes_nothing`
    /// is this test with the flag cleared, and finds the page untouched.
    #[test]
    fn a_switch_publishes_the_running_counts_of_both_sides() {
        let _perf = crate::perf::hrtimer::tests::wheel();
        let t = tree(true, 5, 7);
        assert_eq!(t.rb.peek_userpage().0, 0, "nothing published before the switch");
        sched_out(t.p_tid, t.c_tid);
        assert_eq!(t.rb.peek_userpage().0, 5, "the parent's own running count");
        let _ = (&t.parent, &t.child);
    }

    /// Positive control for the test above: same tree, no `inherit_stat`, and
    /// the switch publishes nothing.
    #[test]
    fn without_per_task_counts_a_switch_publishes_nothing() {
        let _perf = crate::perf::hrtimer::tests::wheel();
        let t = tree(false, 5, 7);
        sched_out(t.p_tid, t.c_tid);
        assert_eq!(t.rb.peek_userpage().0, 0, "no flag, no per-task publication");
        let _ = (&t.parent, &t.child);
    }

    /// The synchronisation keeps each side's value with the THREAD that ran it
    /// up — it does not trade the two. A parent that has counted 5 while its
    /// child counted 7 still reads 5 afterwards, and the child still reads 7.
    #[test]
    fn each_side_keeps_its_own_tasks_count() {
        let _perf = crate::perf::hrtimer::tests::wheel();
        let t = tree(true, 5, 7);
        sched_out(t.p_tid, t.c_tid);
        assert_eq!(t.parent.read_value().0, 5, "the parent's count stayed the parent's");
        assert_eq!(t.child.read_value().0, 7, "and the child's stayed the child's");
    }

    /// A context modified after the fork is no longer the version the child
    /// was cloned from, so the pairing stops and nothing is synchronised —
    /// positional pairing against a list that has changed shape would put each
    /// pair against the wrong partner.
    #[test]
    fn a_context_modified_after_the_fork_stops_pairing() {
        let _perf = crate::perf::hrtimer::tests::wheel();
        let t = tree(true, 5, 7);
        // A second `perf_event_open` against the parent thread.
        let extra = PerfEvent::new(attr(true), SwSource::Zero, Some(t.p_tid), -1, None);
        sched_out(t.p_tid, t.c_tid);
        assert_eq!(t.rb.peek_userpage().0, 0, "unpaired contexts synchronise nothing");
        let _ = (&t.parent, &t.child, extra);
    }

    /// Two unrelated threads that both have events share no lineage, so a
    /// switch between them is a pair of map lookups and nothing more.
    #[test]
    fn a_switch_between_unrelated_threads_synchronises_nothing() {
        let _perf = crate::perf::hrtimer::tests::wheel();
        let (a_tid, b_tid) = (fresh_tid(), fresh_tid());
        let a = PerfEvent::new(attr(true), SwSource::Zero, Some(a_tid), -1, None);
        let b = PerfEvent::new(attr(true), SwSource::Zero, Some(b_tid), -1, None);
        let rb = PerfBuffer::hosted(4, 0, false);
        a.state.lock().buffer = Some(Arc::clone(&rb));
        set_count(&a, 5);
        sched_out(a_tid, b_tid);
        assert_eq!(rb.peek_userpage().0, 0);
        let _ = (a, b);
    }

    /// A child that exits while the switch is being processed takes its whole
    /// context with it. The surviving side must come through unharmed: still
    /// registered, still holding its events, still readable.
    #[test]
    fn a_child_exiting_first_leaves_the_parents_context_intact() {
        let _perf = crate::perf::hrtimer::tests::wheel();
        let t = tree(true, 5, 7);
        crate::perf::inherit::on_task_exit(t.c_tid);
        sched_out(t.p_tid, t.c_tid);
        assert_eq!(live_task_events(t.p_tid).len(), 1, "the parent kept its event");
        assert_eq!(t.parent.read_value().0, 12, "and folded in the child that exited");
    }

    /// The reverse order: the PARENT is gone and the child is still running.
    #[test]
    fn a_parent_exiting_first_leaves_the_childs_context_intact() {
        let _perf = crate::perf::hrtimer::tests::wheel();
        let t = tree(true, 5, 7);
        crate::perf::inherit::on_task_exit(t.p_tid);
        sched_out(t.p_tid, t.c_tid);
        assert_eq!(live_task_events(t.c_tid).len(), 1, "the child kept its event");
        assert_eq!(t.child.read_value().0, 7);
    }

    #[test]
    fn a_fresh_context_is_a_clone_of_nothing() {
        let (a, b) = (ctx(1), ctx(2));
        assert!(!context_equiv(&a, &b), "two unrelated contexts never pair");
        assert!(a.id != b.id, "identities are distinct");
    }

    #[test]
    fn a_clone_is_equivalent_to_its_parent_in_both_directions() {
        let a = ctx(1);
        let mut b = ctx(2);
        b.stamp_clone(a.clone_stamp());
        assert!(context_equiv(&a, &b));
        assert!(context_equiv(&b, &a));
    }

    /// The generation is the whole point of the test: a context modified after
    /// the clone is no longer the version that was cloned, and the pairing has
    /// to stop.
    #[test]
    fn modifying_the_parent_after_the_clone_breaks_equivalence() {
        let mut a = ctx(1);
        let mut b = ctx(2);
        b.stamp_clone(a.clone_stamp());
        assert!(context_equiv(&a, &b));
        a.generation = a.generation.wrapping_add(1);
        assert!(!context_equiv(&a, &b), "a later modification unpairs them");
    }

    /// Two siblings cloned from the same version of one context pair with each
    /// other, without either being the other's parent.
    #[test]
    fn two_clones_of_one_context_pair_with_each_other() {
        let a = ctx(1);
        let (mut b, mut c) = (ctx(2), ctx(3));
        b.stamp_clone(a.clone_stamp());
        c.stamp_clone(a.clone_stamp());
        assert!(context_equiv(&b, &c));
    }

    /// Clones of DIFFERENT versions of the same context do not pair: their
    /// event lists need not line up.
    #[test]
    fn clones_of_different_versions_do_not_pair() {
        let mut a = ctx(1);
        let (mut b, mut c) = (ctx(2), ctx(3));
        b.stamp_clone(a.clone_stamp());
        a.generation += 1;
        c.stamp_clone(a.clone_stamp());
        assert!(!context_equiv(&b, &c));
    }

    /// Flattening: a grandchild records the ROOT context, not the thread in
    /// the middle — so it still pairs with the root's own context, and with
    /// its uncles, after the middle context is gone.
    #[test]
    fn a_grandchild_records_the_root_context_not_the_middle_one() {
        let a = ctx(1);
        let mut b = ctx(2);
        b.stamp_clone(a.clone_stamp());
        let mut c = ctx(3);
        c.stamp_clone(b.clone_stamp());
        assert_eq!(c.parent_ctx, Some(a.id), "flattened to the root");
        assert_eq!(c.parent_ctx, b.parent_ctx, "grandchild and child are siblings in lineage");
        assert!(context_equiv(&a, &c), "still pairs with the root");
        drop(b);
        assert!(context_equiv(&a, &c), "and after the middle context is gone");
    }
}
