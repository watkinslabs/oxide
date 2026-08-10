// The one table of live events: a per-task context per thread that owns one
// (`super::context`), plus the per-CPU list a `pid == -1` event lands in.
//
// ONE object, one lock: fork/exit propagation (`inherit`), sample emission
// (`emit`) and the mid-life synchronisation (`context::sched_out`) all need
// "which events does this context own", and a second table for the second
// caller is exactly the split source of truth that lets the two disagree about
// whether an event is still live.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicUsize, Ordering};

use sync::{PerfTaskEvents, Spinlock};

use super::context::{Entry, PerfContext};
use super::event::PerfEvent;

#[derive(Default)]
struct Registry {
    /// tid -> that thread's event context.
    task: BTreeMap<u32, PerfContext>,
    /// cpu -> CPU-wide events (`pid == -1` at open). A CPU context follows no
    /// task, is never cloned by a fork, and so needs none of the lineage a
    /// task context carries.
    cpu:  BTreeMap<i32, Vec<Entry>>,
}

static EVENTS: Spinlock<Registry, PerfTaskEvents> =
    Spinlock::new(Registry { task: BTreeMap::new(), cpu: BTreeMap::new() });

/// Registered-context count, maintained alongside `EVENTS` purely so the
/// counter sites can answer "is perf in use at all" without touching the lock.
/// A user page fault consults this on EVERY fault, and taking a spinlock there
/// would tax the hottest path in the kernel for a facility almost no boot uses.
/// It may lag the table by one registration, which only ever costs one missed
/// sample on the first event a context registers; the table itself stays the
/// single source of truth for WHICH events exist.
static NR_CONTEXTS: AtomicUsize = AtomicUsize::new(0);

fn push_cpu(list: &mut Vec<Entry>, ev: &Arc<PerfEvent>) {
    list.retain(|e| e.weak.strong_count() > 0);
    let owner = if ev.parent.is_some() { Some(Arc::clone(ev)) } else { None };
    list.push(Entry { weak: Arc::downgrade(ev), owner });
}

/// Register a newly created event under the context it targets. Called once
/// from `PerfEvent::new_inner`. A task-scoped event joins that thread's
/// context, creating it if this is its first event (only those can be
/// inherited across a fork); a CPU-wide one goes in the per-CPU table, where
/// only the sample path finds it. # C: O(1) amortized
pub(super) fn register(ev: &Arc<PerfEvent>) {
    let mut g = EVENTS.lock();
    match ev.tid {
        Some(tid) => g.task.entry(tid).or_insert_with(|| PerfContext::new(tid)).add(ev),
        None      => push_cpu(g.cpu.entry(ev.cpu).or_default(), ev),
    }
    refresh_count(&g);
}

fn refresh_count(g: &Registry) {
    NR_CONTEXTS.store(g.task.len() + g.cpu.len(), Ordering::Release);
}

fn snapshot(list: &mut Vec<Entry>) -> Vec<Arc<PerfEvent>> {
    list.retain(|e| e.weak.strong_count() > 0);
    list.iter().filter_map(|e| e.weak.upgrade()).collect()
}

/// Every still-live event registered for `tid`, pruning dead entries and
/// dropping the context once empty. Snapshotting to owned `Arc`s and releasing
/// the registry lock BEFORE touching any event's own state keeps
/// `PerfTaskEvents` a strict leaf over `PerfEvent::state`. # C: O(N)
pub(super) fn live_task_events(tid: u32) -> Vec<Arc<PerfEvent>> {
    let mut g = EVENTS.lock();
    let Some(ctx) = g.task.get_mut(&tid) else { return Vec::new() };
    let out = ctx.snapshot();
    if ctx.events.is_empty() { g.task.remove(&tid); }
    refresh_count(&g);
    out
}

/// Read `tid`'s context under the registry lock. The context itself is never
/// handed out: its lineage and generation are only meaningful while the table
/// that owns it is held still. # C: O(1) plus `f`
pub(super) fn with_context<R>(tid: u32, f: impl FnOnce(&mut PerfContext) -> R) -> Option<R> {
    let mut g = EVENTS.lock();
    g.task.get_mut(&tid).map(f)
}

/// Both sides of a context switch at once, so the equivalence test sees one
/// consistent version of each. Yields `R::default()` when either thread has no
/// context — the overwhelmingly common case, and the reason this returns
/// before doing any work rather than after. # C: O(1) plus `f`
pub(super) fn with_context_pair<R: Default>(
    a: u32, b: u32, f: impl FnOnce(&mut PerfContext, &mut PerfContext) -> R) -> R
{
    let mut g = EVENTS.lock();
    if !g.task.contains_key(&a) || !g.task.contains_key(&b) { return R::default(); }
    // Two disjoint keys of one map: taken out and put back so both are held
    // mutably at once without a second lock or an unsafe alias.
    let Some(mut ca) = g.task.remove(&a) else { return R::default() };
    let Some(mut cb) = g.task.remove(&b) else { g.task.insert(a, ca); return R::default() };
    let out = f(&mut ca, &mut cb);
    g.task.insert(a, ca);
    g.task.insert(b, cb);
    out
}

/// Every still-live CPU-wide event bound to `cpu`. # C: O(N)
pub(super) fn live_cpu_events(cpu: i32) -> Vec<Arc<PerfEvent>> {
    let mut g = EVENTS.lock();
    let Some(list) = g.cpu.get_mut(&cpu) else { return Vec::new() };
    let out = snapshot(list);
    if list.is_empty() { g.cpu.remove(&cpu); }
    refresh_count(&g);
    out
}

/// Retire `tid`'s context outright and hand back everything it held, including
/// its own keep-alive on each inherited child so the caller's fold-back is the
/// last thing that touches it. # C: O(N)
pub(super) fn retire_task(tid: u32) -> Vec<Arc<PerfEvent>> {
    let ctx = { let mut g = EVENTS.lock(); let c = g.task.remove(&tid); refresh_count(&g); c };
    ctx.into_iter().flat_map(|c| c.events)
        .filter_map(|e| e.owner.or_else(|| e.weak.upgrade()))
        .collect()
}

/// Every live event in every context — the walk the sampling tick makes over
/// the contexts on a CPU, over oxide's one registry. Task-scoped events come
/// first; the caller's work is per-event and order-independent.
/// # C: O(N)
pub(super) fn all_events() -> Vec<Arc<PerfEvent>> {
    let mut g = EVENTS.lock();
    let mut out = Vec::new();
    for ctx in g.task.values_mut()  { out.extend(ctx.snapshot()); }
    for list in g.cpu.values_mut()  { out.extend(snapshot(list)); }
    g.task.retain(|_, c| !c.events.is_empty());
    g.cpu.retain(|_, l| !l.is_empty());
    refresh_count(&g);
    out
}

/// True when any registered event might want a sample. LOCK-FREE: a user page
/// fault asks this on every fault, so it reads the atomic rather than the
/// table. # C: O(1)
pub(super) fn any_registered() -> bool { NR_CONTEXTS.load(Ordering::Acquire) != 0 }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perf::attr::PerfAttr;
    use crate::perf::counter::SwSource;

    static NEXT_TID: AtomicUsize = AtomicUsize::new(800_000);

    /// The lock-free fast path must agree with the table it stands in for:
    /// registering makes it true, and retiring the last context makes it false
    /// again. A stuck-true value only costs a wasted walk; a stuck-false one
    /// silently drops every sample, which is why this is pinned.
    #[test]
    fn the_lock_free_gate_tracks_the_table() {
    let _perf = crate::perf::hrtimer::tests::wheel();
        let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed) as u32;
        let ev = PerfEvent::new(PerfAttr::default(), SwSource::Zero, Some(tid), -1, None);
        assert!(any_registered());
        assert_eq!(live_task_events(tid).len(), 1);
        drop(ev);
        // The dead entry is pruned by the next walk, which also refreshes the
        // count — the table remains the source of truth for WHICH events exist.
        assert!(live_task_events(tid).is_empty());
        let _ = retire_task(tid);
    }

    #[test]
    fn a_cpu_wide_event_registers_under_its_cpu_not_a_tid() {
    let _perf = crate::perf::hrtimer::tests::wheel();
        let ev = PerfEvent::new(PerfAttr::default(), SwSource::Zero, None, 7, None);
        assert_eq!(live_cpu_events(7).len(), 1);
        assert!(live_cpu_events(6).is_empty());
        assert!(live_task_events(0).is_empty());
        drop(ev);
        assert!(live_cpu_events(7).is_empty());
    }

    /// A thread's first event creates its context; registering a second one
    /// moves the generation, which is what a clone lineage is tested against.
    #[test]
    fn registering_an_event_creates_a_context_and_moves_its_generation() {
    let _perf = crate::perf::hrtimer::tests::wheel();
        let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed) as u32;
        assert!(with_context(tid, |c| c.generation).is_none(), "no events, no context");
        let a = PerfEvent::new(PerfAttr::default(), SwSource::Zero, Some(tid), -1, None);
        let g1 = with_context(tid, |c| c.generation).expect("context exists");
        let b = PerfEvent::new(PerfAttr::default(), SwSource::Zero, Some(tid), -1, None);
        let g2 = with_context(tid, |c| c.generation).expect("context exists");
        assert!(g2 > g1, "a second registration is a modification");
        drop((a, b));
        let _ = retire_task(tid);
    }

    /// The pair accessor puts BOTH contexts back, whether or not the closure
    /// did anything — losing one would silently unregister a live thread's
    /// events on the first context switch it took part in.
    #[test]
    fn the_pair_accessor_returns_both_contexts_to_the_table() {
    let _perf = crate::perf::hrtimer::tests::wheel();
        let t1 = NEXT_TID.fetch_add(1, Ordering::Relaxed) as u32;
        let t2 = NEXT_TID.fetch_add(1, Ordering::Relaxed) as u32;
        let a = PerfEvent::new(PerfAttr::default(), SwSource::Zero, Some(t1), -1, None);
        let b = PerfEvent::new(PerfAttr::default(), SwSource::Zero, Some(t2), -1, None);
        let seen: usize = with_context_pair(t1, t2, |x, y| x.events.len() + y.events.len());
        assert_eq!(seen, 2);
        assert_eq!(live_task_events(t1).len(), 1);
        assert_eq!(live_task_events(t2).len(), 1);
        // A thread with no context at all yields the default without touching
        // the other side.
        let miss: usize = with_context_pair(t1, 0xdead_beef, |_, _| 99);
        assert_eq!(miss, 0);
        assert_eq!(live_task_events(t1).len(), 1);
        drop((a, b));
        let _ = (retire_task(t1), retire_task(t2));
    }
}
