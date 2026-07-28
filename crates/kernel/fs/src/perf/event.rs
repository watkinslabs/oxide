// Live `struct perf_event` state and its counter sources.
// Linux `kernel/events/core.c` (`perf_event_alloc`, `cpu_clock_event_update`,
// `task_clock_event_update`) + `kernel/events/core.c` software counters.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sched::perf_sw::{self, CpuSw};
use sync::{Spinlock, TaskList as PerfLockClass};

use super::attr::PerfAttr;
use super::counter::{SwCounter, SwSource, TaskCount};

/// `perf_event::id` allocator (`primary_event_id`).
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Monotonic ns; the clock every perf time field is expressed in.
pub fn now_ns() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    // Hosted builds have no timer HAL; a strictly increasing tick keeps the
    // enable/disable algebra observable in unit tests.
    #[cfg(not(target_os = "oxide-kernel"))]
    { static T: AtomicU64 = AtomicU64::new(0); T.fetch_add(1, Ordering::Relaxed) }
}

/// Mutable half of a live event.
pub struct EventState {
    pub counter: SwCounter,
    /// `PERF_EVENT_IOC_REFRESH` remaining-overflow budget. Software counters in
    /// oxide never overflow (no sampling interrupt), so this only ever gates
    /// `_perf_event_refresh`'s `-EINVAL` on a non-sampling event.
    pub refresh: i64,
    /// `PERF_EVENT_IOC_SET_FILTER` payload; only tracepoint/kprobe/uprobe PMUs
    /// accept one, so this stays empty and the ioctl reports the PMU's error.
    pub period: u64,
    /// Group members, leader-first, when this event is a group leader.
    pub siblings: Vec<Weak<PerfEvent>>,
}

/// A live perf event — one open file description.
pub struct PerfEvent {
    /// Self-reference: `f_op` sees only `&Inode`, so an event must be able to
    /// hand out its own `Arc` when it is its group's leader.
    me:         Weak<PerfEvent>,
    pub attr:   PerfAttr,
    pub id:     u64,
    pub source: SwSource,
    /// Target thread id; `None` for a CPU-context event (`pid == -1`).
    pub tid:    Option<u32>,
    /// Target CPU; `-1` for a task-context event that follows the task.
    pub cpu:    i32,
    /// Group leader, when this event joined a group. `None` == own leader.
    pub leader: Option<Weak<PerfEvent>>,
    pub state:  Spinlock<EventState, PerfLockClass>,
}

impl PerfEvent {
    /// # C: O(1)
    pub fn new(attr: PerfAttr, source: SwSource, tid: Option<u32>, cpu: i32,
               leader: Option<Weak<PerfEvent>>) -> Arc<PerfEvent>
    {
        let enabled = !attr.bit(super::uapi::attr_bit::DISABLED);
        let now = now_ns();
        let ev = Arc::new_cyclic(|me| PerfEvent {
            me: me.clone(), attr, source, tid, cpu, leader,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            state: Spinlock::new(EventState {
                counter: SwCounter::new(0, now, enabled),
                refresh: 0, period: attr.sample_period, siblings: Vec::new(),
            }),
        });
        // Sample the source once the event exists so the first read reports the
        // delta since open, not since boot.
        let src = ev.sample();
        ev.state.lock().counter.base = src;
        ev
    }

    /// Current raw value of this event's counter source. # C: O(1) task lookup
    pub fn sample(&self) -> u64 {
        match self.source {
            SwSource::Zero      => 0,
            SwSource::CpuClock  => now_ns(),
            SwSource::TaskClock => match self.tid {
                Some(tid) => sched::registry::lookup(tid)
                    .map(|t| t.sum_exec_runtime_ns.load(Ordering::Relaxed)).unwrap_or(0),
                None => perf_sw::read(CpuSw::ExecNs, self.cpu.max(0) as usize),
            },
            SwSource::TaskCount(k) => match self.tid {
                Some(tid) => sched::registry::lookup(tid).map(|t| task_count(&t, k)).unwrap_or(0),
                None => cpu_count(k, self.cpu.max(0) as usize),
            },
        }
    }

    /// `__perf_event_read_value` + `perf_event_count`. # C: O(1)
    pub fn read_value(&self) -> (u64, u64, u64) {
        let src = self.sample();
        let now = now_ns();
        let g = self.state.lock();
        let t = g.counter.time_enabled(now);
        (g.counter.count(src), t, t)
    }

    /// Group members leader-first; a solo event yields just itself.
    /// # C: O(siblings)
    pub fn group_members(&self) -> Vec<Arc<PerfEvent>> {
        let leader = match self.leader.as_ref().and_then(Weak::upgrade) {
            Some(l) => l,
            None    => match self.me.upgrade() { Some(m) => m, None => return Vec::new() },
        };
        let mut out = Vec::new();
        out.push(leader.clone());
        for w in leader.state.lock().siblings.iter() {
            if let Some(s) = w.upgrade() { out.push(s); }
        }
        out
    }

    /// Number of siblings for `__perf_event_read_size`. # C: O(1)
    pub fn nr_siblings(&self) -> usize {
        match self.leader.as_ref().and_then(Weak::upgrade) {
            Some(l) => l.state.lock().siblings.len(),
            None    => self.state.lock().siblings.len(),
        }
    }

    /// Own `Arc`, for the paths that must hold a reference. # C: O(1)
    pub fn arc(&self) -> Option<Arc<PerfEvent>> { self.me.upgrade() }
}

fn task_count(t: &sched::Task, k: TaskCount) -> u64 {
    match k {
        TaskCount::PageFaultsMin   => t.min_flt.load(Ordering::Relaxed),
        TaskCount::PageFaultsMaj   => t.maj_flt.load(Ordering::Relaxed),
        TaskCount::PageFaultsAll   => t.min_flt.load(Ordering::Relaxed)
                                        .wrapping_add(t.maj_flt.load(Ordering::Relaxed)),
        TaskCount::ContextSwitches => t.nvcsw.load(Ordering::Relaxed)
                                        .wrapping_add(t.nivcsw.load(Ordering::Relaxed)),
        TaskCount::CpuMigrations   => t.nr_migrations.load(Ordering::Relaxed),
    }
}

fn cpu_count(k: TaskCount, cpu: usize) -> u64 {
    match k {
        TaskCount::PageFaultsMin   => perf_sw::read(CpuSw::MinFlt, cpu),
        TaskCount::PageFaultsMaj   => perf_sw::read(CpuSw::MajFlt, cpu),
        TaskCount::PageFaultsAll   => perf_sw::read(CpuSw::MinFlt, cpu)
                                        .wrapping_add(perf_sw::read(CpuSw::MajFlt, cpu)),
        TaskCount::ContextSwitches => perf_sw::read(CpuSw::ContextSwitch, cpu),
        TaskCount::CpuMigrations   => perf_sw::read(CpuSw::Migration, cpu),
    }
}
