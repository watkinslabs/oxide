// The one registry of live events, keyed by the context an event is attached
// to — Linux's per-task `perf_event_context::event_list` plus the per-CPU
// `swevent_hlist` that `perf_sw_event()` walks.
//
// ONE object, one lock: fork/exit propagation (`inherit`) and sample emission
// (`emit`) both need "which events does this context own", and a second table
// for the second caller is exactly the split source of truth that lets the two
// disagree about whether an event is still live.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::{AtomicUsize, Ordering};

use sync::{PerfTaskEvents, Spinlock};

use super::event::PerfEvent;

/// One registration. `weak` is the uniform handle used for lookup and for
/// orphan detection (a closed fd drops the event's only OTHER owner, so `weak`
/// dies and the entry prunes itself — Linux `is_orphaned_event()` silently
/// excluding a closed event). `owner` is the registry's OWN keep-alive,
/// populated only for a fork-inherited child: unlike an `perf_event_open`-ed
/// event, which its fd's inode keeps alive, an inherited child has no fd at
/// all, so the registry must be its strong owner until its task exits.
struct Entry {
    weak:  Weak<PerfEvent>,
    owner: Option<Arc<PerfEvent>>,
}

#[derive(Default)]
struct Registry {
    /// tid -> task-scoped events targeting that thread.
    task: BTreeMap<u32, Vec<Entry>>,
    /// cpu -> CPU-wide events (`pid == -1` at open).
    cpu:  BTreeMap<i32, Vec<Entry>>,
}

static EVENTS: Spinlock<Registry, PerfTaskEvents> =
    Spinlock::new(Registry { task: BTreeMap::new(), cpu: BTreeMap::new() });

/// Registered-context count, maintained alongside `EVENTS` purely so the
/// counter sites can answer "is perf in use at all" without touching the lock.
/// A user page fault consults this on EVERY fault, and taking a spinlock there
/// would tax the hottest path in the kernel for a facility almost no boot uses
/// — the same job Linux gives `static_key_false(&perf_swevent_enabled[id])`.
/// It may lag the table by one registration, which only ever costs one missed
/// sample on the first event a context registers; the table itself stays the
/// single source of truth for WHICH events exist.
static NR_CONTEXTS: AtomicUsize = AtomicUsize::new(0);

fn push(list: &mut Vec<Entry>, ev: &Arc<PerfEvent>) {
    list.retain(|e| e.weak.strong_count() > 0);
    let owner = if ev.parent.is_some() { Some(Arc::clone(ev)) } else { None };
    list.push(Entry { weak: Arc::downgrade(ev), owner });
}

/// Register a newly created event under the context it targets. Called once
/// from `PerfEvent::new_inner`. A task-scoped event goes in the per-tid table
/// (only those can be inherited across a fork — `perf_event_init_context`
/// walks a per-TASK context); a CPU-wide one goes in the per-CPU table, where
/// only the sample path finds it. # C: O(1) amortized
pub(super) fn register(ev: &Arc<PerfEvent>) {
    let mut g = EVENTS.lock();
    match ev.tid {
        Some(tid) => push(g.task.entry(tid).or_default(), ev),
        None      => push(g.cpu.entry(ev.cpu).or_default(), ev),
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
/// dropping the map slot once empty. Snapshotting to owned `Arc`s and
/// releasing the registry lock BEFORE touching any event's own state keeps
/// `PerfTaskEvents` a strict leaf over `PerfEvent::state`. # C: O(N)
pub(super) fn live_task_events(tid: u32) -> Vec<Arc<PerfEvent>> {
    let mut g = EVENTS.lock();
    let Some(list) = g.task.get_mut(&tid) else { return Vec::new() };
    let out = snapshot(list);
    if list.is_empty() { g.task.remove(&tid); }
    refresh_count(&g);
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

/// Retire `tid`'s registration outright and hand back everything it held,
/// including the registry's own keep-alive on each inherited child so the
/// caller's fold-back is the last thing that touches it. # C: O(N)
pub(super) fn retire_task(tid: u32) -> Vec<Arc<PerfEvent>> {
    let entries = { let mut g = EVENTS.lock(); let e = g.task.remove(&tid); refresh_count(&g); e };
    entries.into_iter().flatten()
        .filter_map(|e| e.owner.or_else(|| e.weak.upgrade()))
        .collect()
}

/// Every live event in every context — the walk `perf_event_task_tick` makes
/// over the contexts on a CPU, over oxide's one registry. Task-scoped events
/// come first so a group leader registered against a task precedes nothing in
/// particular; the caller's work is per-event and order-independent.
/// # C: O(N)
pub(super) fn all_events() -> Vec<Arc<PerfEvent>> {
    let mut g = EVENTS.lock();
    let mut out = Vec::new();
    for list in g.task.values_mut() { out.extend(snapshot(list)); }
    for list in g.cpu.values_mut()  { out.extend(snapshot(list)); }
    g.task.retain(|_, l| !l.is_empty());
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
}
