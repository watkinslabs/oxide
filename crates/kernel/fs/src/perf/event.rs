// Live `struct perf_event` state and its counter sources: allocation,
// CPU-clock and task-clock update, and the software-counter set.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use sched::perf_sw::{self, CpuSw};
use sync::{Spinlock, TaskList as PerfLockClass};

use super::attr::PerfAttr;
use super::counter::{SwCounter, SwSource, TaskCount};
use super::overflow::HwPeriod;
use super::ring::PerfBuffer;

/// `EPOLLIN | EPOLLRDNORM` — the readiness `perf_output_wakeup` publishes, and
/// the key the wake carries so an `EPOLLOUT`-only waiter is not disturbed.
const WAKEUP_MASK: u32 = vfs::POLL_IN | vfs::POLL_RDNORM;

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
    /// Folded-in totals from every inherited child that has exited —
    /// Linux `child_count`/`child_total_time_enabled`/`child_total_time_running`.
    /// Added into `read_value()` unconditionally (`perf_event_count`),
    /// independent of `attr.inherit_stat` (`24` inherit propagation).
    pub child_count:        u64,
    pub child_time_enabled: u64,
    pub child_time_running: u64,
    /// Sampling-period budget (`hw_perf_event`'s `sample_period`/`period_left`).
    pub hw: HwPeriod,
    /// `hw_perf_event`'s `interrupts`/`interrupts_seq` — the per-tick sampling
    /// budget `super::throttle` enforces.
    pub interrupts: super::throttle::Interrupts,
    /// The `mmap`ed ring this event's samples go to — Linux `event->rb`.
    /// `None` until userspace maps the fd, which is why a counting-only
    /// `perf_event_open` allocates nothing.
    pub buffer: Option<Arc<PerfBuffer>>,
    /// `event->lost_samples` — what `PERF_FORMAT_LOST` reports.
    pub lost_samples: u64,
    /// Live mappings taken through THIS event's own fd. Distinct from the
    /// buffer's mapping count: an event that borrowed another event's ring has
    /// a buffer and no mappings of its own, and the two facts decide different
    /// things (whether the ring may be freed, versus whether this event may be
    /// redirected or re-mapped).
    pub mmap_count: u64,
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
    /// The event this one was cloned from on fork (`attr.inherit`) — Linux
    /// `perf_event::parent`. `None` for an event opened directly by
    /// `perf_event_open`.
    pub parent: Option<Weak<PerfEvent>>,
    pub state:  Spinlock<EventState, PerfLockClass>,
    /// `event->waitq` + `event->fasync`: who `perf_output_wakeup` wakes when a
    /// record crosses the watermark. It hangs off the EVENT, as in the
    /// reference, and the event fd's inode publishes this same `Arc` as its
    /// poll-subscriber list — one queue, so a `poll(2)` waiter and the record
    /// that satisfies it can never be looking at different lists.
    pub waitq:  Arc<vfs::PollSubscribers>,
    /// `hw_perf_event::hrtimer` — the armed sampling timer's wheel id for the
    /// clock PMUs, or `0` when none is armed. Owned by `super::hrtimer`.
    pub hrtimer: AtomicU64,
}

impl PerfEvent {
    /// # C: O(1)
    pub fn new(attr: PerfAttr, source: SwSource, tid: Option<u32>, cpu: i32,
               leader: Option<Weak<PerfEvent>>) -> Arc<PerfEvent>
    {
        Self::new_inner(attr, source, tid, cpu, leader, None)
    }

    /// Fork-inherited child event. Same `attr`/`source`/`cpu` as `parent`,
    /// targets `child_tid`, and opens its own counter window from this instant
    /// (the child's count starts at 0, like a freshly opened event, rather than
    /// sharing the parent's). `parent` is remembered so the child's exit can
    /// fold its final count back ([`PerfEvent::fold_into_parent`]).
    ///
    /// `leader` is the CHILD-side group leader an inherited sibling joins, so a
    /// group survives a fork as a group: a grouped read on the child's tree
    /// must return the same member list the parent's does, and members that
    /// each became their own leader would report a group of one apiece.
    /// # C: O(1)
    pub fn new_inherited(parent: &Arc<PerfEvent>, child_tid: u32,
                         leader: Option<&Arc<PerfEvent>>) -> Arc<PerfEvent>
    {
        // FLATTENED, not chained: an inherited event links back to the ROOT of
        // the tree — the one event that has an fd, and therefore the one whose
        // holder is doing the reading. Chaining a grandchild onto the thread
        // in the middle loses its whole count the moment that thread exits
        // first, which is the ordinary shape of a fork/exec/exit pipeline.
        let root = match parent.parent.as_ref().and_then(Weak::upgrade) {
            Some(r) => r,
            None    => Arc::clone(parent),
        };
        let ev = Self::new_inner(root.attr, root.source, Some(child_tid), root.cpu,
            leader.map(Arc::downgrade), Some(Arc::downgrade(&root)));
        // The child's counter follows the state the parent event is ACTUALLY
        // in, not the `attr.disabled` bit it was opened with: an event enabled
        // through its fd after being opened disabled must have its children
        // counting, and one disabled again must not.
        let live = parent.state.lock().counter.enabled;
        let (src, now) = (ev.sample(), now_ns());
        let mut g = ev.state.lock();
        if live { g.counter.enable(src, now); } else { g.counter.disable(src, now); }
        drop(g);
        if let Some(l) = leader { l.state.lock().siblings.push(Arc::downgrade(&ev)); }
        ev
    }

    /// Bring the stored counter up to date against the task this event counts,
    /// and republish the mapped control page from it — the snapshot a consumer
    /// reads without entering the kernel. Called at each context switch for an
    /// `attr.inherit_stat` event, which is what makes a per-task count visible
    /// while the task is still running instead of only once it exits.
    /// # C: O(1)
    pub fn sync_now(&self) {
        let src = self.sample();
        let now = now_ns();
        let (count, enabled, running, rb) = {
            let mut g = self.state.lock();
            g.counter.update(src, now);
            let t = g.counter.time_enabled(now);
            (g.counter.count(src).wrapping_add(g.child_count),
             t.saturating_add(g.child_time_enabled),
             t.saturating_add(g.child_time_running),
             g.buffer.clone())
        };
        if let Some(rb) = rb { rb.update_userpage(count, enabled, running); }
    }

    /// This event's group siblings, when it is a leader. # C: O(siblings)
    pub fn siblings(&self) -> Vec<Arc<PerfEvent>> {
        self.state.lock().siblings.iter().filter_map(Weak::upgrade).collect()
    }

    fn new_inner(attr: PerfAttr, source: SwSource, tid: Option<u32>, cpu: i32,
               leader: Option<Weak<PerfEvent>>, parent: Option<Weak<PerfEvent>>) -> Arc<PerfEvent>
    {
        let enabled = !attr.bit(super::uapi::attr_bit::DISABLED);
        let now = now_ns();
        let ev = Arc::new_cyclic(|me| PerfEvent {
            me: me.clone(), attr, source, tid, cpu, leader, parent,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            waitq: Arc::new(vfs::PollSubscribers::new()),
            hrtimer: AtomicU64::new(0),
            state: Spinlock::new(EventState {
                counter: SwCounter::new(0, now, enabled),
                refresh: 0, period: attr.sample_period, siblings: Vec::new(),
                child_count: 0, child_time_enabled: 0, child_time_running: 0,
                hw: HwPeriod::new(attr.sample_period),
                interrupts: super::throttle::Interrupts::default(),
                buffer: None, lost_samples: 0, mmap_count: 0,
            }),
        });
        // Sample the source once the event exists so the first read reports the
        // delta since open, not since boot.
        let src = ev.sample();
        ev.state.lock().counter.base = src;
        // Every event joins the registry under the context it targets: a
        // task-scoped one so `inherit::on_fork` can find it, a CPU-wide one so
        // the sample path can. Only the former is ever inherited (Linux
        // `perf_event_init_context` walks a per-TASK context).
        super::registry::register(&ev);
        // `perf_swevent_init_hrtimer` + the `pmu::add` that follows an event
        // opened without `PERF_FLAG_DISABLED`: a sampling clock-PMU event has
        // no counter site to overflow it, so its timer is armed here or never.
        super::hrtimer::start(&ev);
        ev
    }

    /// `sync_child_event`: fold this (about-to-die, inherited) child's final
    /// count into its parent's `child_count`, so the parent's next
    /// `read_value()` reports the total across every child that ever
    /// inherited from it. No-op when `parent` is gone or this was never an
    /// inherited event. # C: O(1)
    pub fn fold_into_parent(&self) {
        let Some(parent) = self.parent.as_ref().and_then(Weak::upgrade) else { return };
        let (count, enabled, running) = self.read_value();
        let mut g = parent.state.lock();
        g.child_count        = g.child_count.wrapping_add(count);
        g.child_time_enabled = g.child_time_enabled.saturating_add(enabled);
        g.child_time_running = g.child_time_running.saturating_add(running);
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

    /// `__perf_event_read_value` + `perf_event_count`. `perf_event_count`
    /// adds `child_count` unconditionally, so a parent's read reflects every
    /// inherited child that has since exited. # C: O(1)
    pub fn read_value(&self) -> (u64, u64, u64) {
        let src = self.sample();
        let now = now_ns();
        let g = self.state.lock();
        let t = g.counter.time_enabled(now);
        (g.counter.count(src).wrapping_add(g.child_count),
         t.saturating_add(g.child_time_enabled),
         t.saturating_add(g.child_time_running))
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

    /// `__perf_output_begin`'s redirection: an inherited event sends ALL of its
    /// output to the parent's ring, since only the parent was ever mmapped.
    /// `primary_event_id(event)` follows the same link. # C: O(1)
    pub fn output_target(&self) -> Option<Arc<PerfEvent>> {
        match self.parent.as_ref().and_then(Weak::upgrade) {
            Some(p) => Some(p),
            None    => self.me.upgrade(),
        }
    }

    /// The ring this event's samples land in, if one is mapped. # C: O(1)
    pub fn buffer(&self) -> Option<Arc<PerfBuffer>> { self.state.lock().buffer.clone() }

    /// `perf_output_wakeup`'s deferred half: wake every `poll(2)`/`epoll_wait`
    /// waiter on this event and deliver `SIGIO` to its `O_ASYNC` holders with
    /// `POLL_IN` as the reason. The reference queues an `irq_work` because it
    /// runs this from the sampling interrupt; oxide's sampling sites are all
    /// process context with no runqueue lock held (the scheduler ones drain
    /// through `perf_sw::drain_deferred`), so the wake runs inline.
    /// # C: O(subscribers)
    pub fn wakeup(&self) { self.waitq.notify_mask(WAKEUP_MASK); }
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
