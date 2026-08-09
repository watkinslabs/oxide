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
    out
}

/// Every still-live CPU-wide event bound to `cpu`. # C: O(N)
pub(super) fn live_cpu_events(cpu: i32) -> Vec<Arc<PerfEvent>> {
    let mut g = EVENTS.lock();
    let Some(list) = g.cpu.get_mut(&cpu) else { return Vec::new() };
    let out = snapshot(list);
    if list.is_empty() { g.cpu.remove(&cpu); }
    out
}

/// Retire `tid`'s registration outright and hand back everything it held,
/// including the registry's own keep-alive on each inherited child so the
/// caller's fold-back is the last thing that touches it. # C: O(N)
pub(super) fn retire_task(tid: u32) -> Vec<Arc<PerfEvent>> {
    let entries = EVENTS.lock().task.remove(&tid);
    entries.into_iter().flatten()
        .filter_map(|e| e.owner.or_else(|| e.weak.upgrade()))
        .collect()
}

/// True when any registered event might want a sample. Lets the hot software
/// counter sites skip the registry walk entirely when perf is not in use —
/// Linux's `static_key_false(&perf_swevent_enabled[event_id])`. # C: O(1)
pub(super) fn any_registered() -> bool {
    let g = EVENTS.lock();
    !g.task.is_empty() || !g.cpu.is_empty()
}
