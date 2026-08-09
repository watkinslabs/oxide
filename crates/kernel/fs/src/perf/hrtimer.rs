// The software-clock PMUs' sampling timer — `perf_swevent_init_hrtimer`,
// `perf_swevent_start_hrtimer`, `perf_swevent_hrtimer` and
// `perf_swevent_cancel_hrtimer`.
//
// `PERF_COUNT_SW_CPU_CLOCK` and `_TASK_CLOCK` have no counter site to charge
// them: their value is a clock read, so an overflow can only come from a timer.
// The reference arms one hrtimer per sampling event at `pmu::add` and emits one
// record per expiry; oxide arms the same shape on the software timer wheel,
// whose callbacks run in the timer kthread's process context — which is where
// the sampler needs to be anyway (it takes the registry and one ring lock).
//
// The period arithmetic is pure and hosted-tested; only `start`/`stop` touch
// the wheel.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;

use sched::perf_sw::{CpuSw, SwSite};

use super::attr::PerfAttr;
use super::counter::SwSource;
use super::emit;
use super::event::{now_ns, PerfEvent};

/// `NSEC_PER_SEC`, the numerator of the reference's static freq→period map.
const NSEC_PER_SEC: u64 = 1_000_000_000;

/// The reference's floor on a software-clock sampling period. A shorter one
/// would spend the CPU inside the timer callback.
pub const MIN_PERIOD_NS: u64 = 10_000;

/// Whether this event's counter source is one of the two clock PMUs, i.e. the
/// sources that overflow from a timer rather than from a counter site.
/// # C: O(1)
pub fn is_clock_source(src: SwSource) -> bool {
    matches!(src, SwSource::CpuClock | SwSource::TaskClock)
}

/// `perf_swevent_init_hrtimer` + `perf_swevent_start_hrtimer`'s period.
///
/// A non-sampling event arms nothing (`is_sampling_event`). A `freq`-mode event
/// gets the reference's static map — `sample_period = NSEC_PER_SEC / freq`,
/// after which `attr.freq` no longer drives period adjustment, since an hrtimer
/// already ticks at a fixed rate. Every armed period is then floored at
/// [`MIN_PERIOD_NS`].
/// # C: O(1)
pub fn period_ns(attr: &PerfAttr) -> Option<u64> {
    if !attr.is_sampling() { return None; }
    let raw = if attr.freq() {
        let freq = attr.sample_period;
        if freq == 0 { return None; }
        NSEC_PER_SEC / freq
    } else {
        attr.sample_period
    };
    Some(raw.max(MIN_PERIOD_NS))
}

/// Whether `ev` should have a timer armed right now: a sampling clock-PMU event
/// that is enabled. # C: O(1)
pub fn wants_timer(ev: &Arc<PerfEvent>) -> bool {
    is_clock_source(ev.source)
        && period_ns(&ev.attr).is_some()
        && ev.state.lock().counter.enabled
}

/// Arm the event's sampling timer, replacing any already armed. Idempotent for
/// an event that does not want one. # C: O(1)
pub fn start(ev: &Arc<PerfEvent>) {
    stop(ev);
    if !wants_timer(ev) { return; }
    let Some(period) = period_ns(&ev.attr) else { return };
    arm(ev, period);
}

/// `perf_swevent_cancel_hrtimer`. # C: O(N armed)
pub fn stop(ev: &Arc<PerfEvent>) {
    let raw = ev.hrtimer.swap(0, Ordering::AcqRel);
    if let Some(id) = timer::TimerId::from_raw(raw) { timer::unregister_oneshot(id); }
}

/// Register one expiry. The wheel holds a WEAK reference: an armed timer must
/// not keep a closed event alive, and the expiry after the last fd closes finds
/// a dead reference and stops re-arming — the reference's `event->destroy`
/// hook, reached without a destructor that would have to run under the wheel's
/// own lock.
fn arm(ev: &Arc<PerfEvent>, period: u64) {
    let w = Arc::downgrade(ev);
    let arg = Weak::into_raw(w) as usize;
    let id = timer::register_oneshot_owned(now_ns().saturating_add(period), arg, fire, release);
    ev.hrtimer.store(id.raw(), Ordering::Release);
}

/// `perf_swevent_hrtimer`: emit one record for this expiry, then
/// `hrtimer_forward_now` to the next.
fn fire(arg: usize, id: timer::TimerId) {
    // SAFETY: `arg` is the `Weak::into_raw` pointer `arm` produced for this
    // one-shot; the wheel hands it back exactly once, and `release` (the
    // owned-arg drop) reclaims it afterwards, so this borrow does not own it.
    let w = unsafe { Weak::from_raw(arg as *const PerfEvent) };
    let ev = w.upgrade();
    // Hand the reference back to the wheel's drop, which owns it.
    let _ = Weak::into_raw(w);
    let Some(ev) = ev else { return };
    // A cancel that raced this expiry, or a re-arm from elsewhere, owns the
    // slot now; this stale fire must neither emit nor re-arm.
    if ev.hrtimer.load(Ordering::Acquire) != id.raw() { return; }
    let Some(period) = period_ns(&ev.attr) else { return };
    if !ev.state.lock().counter.enabled {
        ev.hrtimer.store(0, Ordering::Release);
        return;
    }
    let cur = sched::current();
    let (pid, tid) = match cur.as_ref() {
        Some(c) => (c.tgid.load(Ordering::Relaxed), c.tid),
        None    => (0, 0),
    };
    // `PERF_SAMPLE_CPU`: a CPU-scoped event reports the CPU it was opened on, a
    // task-scoped one the CPU its target is running on.
    let cpu = if ev.cpu >= 0 { ev.cpu as usize }
              else { cur.as_ref().map_or(0, |c| c.cpu.load(Ordering::Acquire) as usize) };
    // The reference's `event->pmu->read(event)` before the sample, so the
    // control page and `PERF_SAMPLE_READ` reflect this expiry's clock.
    let (count, enabled, running) = ev.read_value();
    if let Some(rb) = ev.buffer() { rb.update_userpage(count, enabled, running); }
    // No trap frame: the wheel's callback runs in the timer kthread, not in the
    // interrupted context, so there is no `get_irq_regs()` to sample. The
    // reference emits nothing at all in that case; oxide emits the record with
    // the reference's "no instruction pointer" encoding rather than dropping
    // it, because dropping it would leave `perf record -e cpu-clock` with an
    // empty ring — the record's period, time, tid and read payload are all
    // real, only the IP is unavailable.
    emit::deliver(&ev, &SwSite { kind: CpuSw::ExecNs, cpu, nr: 1, ip: 0, addr: 0,
                                 user: false, charged: None }, pid, tid, Some(period));
    arm(&ev, period);
}

/// Reclaim the `Weak` the wheel was holding, once per registration.
fn release(arg: usize) {
    // SAFETY: `arg` is the `Weak::into_raw` pointer from `arm`; the wheel calls
    // this exactly once per registration, after any `fire`, and never again.
    drop(unsafe { Weak::from_raw(arg as *const PerfEvent) });
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;

    /// ONE timer wheel per process: `timer::run_due` fires every registration,
    /// so a test that arms one must not overlap a test that drains.
    static WHEEL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn wheel() -> std::sync::MutexGuard<'static, ()> {
        WHEEL.lock().unwrap_or_else(|e| e.into_inner())
    }
    use super::super::counter::TaskCount;
    use super::super::ring::PerfBuffer;
    use super::super::uapi::{attr_bit, record, sample};

    fn attr(period: u64, freq: bool) -> PerfAttr {
        PerfAttr { sample_period: period,
                   bits: if freq { 1 << attr_bit::FREQ } else { 0 },
                   sample_type: sample::IP | sample::PERIOD, ..PerfAttr::default() }
    }

    #[test]
    fn a_counting_only_event_arms_nothing() {
        assert_eq!(period_ns(&attr(0, false)), None);
        assert_eq!(period_ns(&attr(0, true)), None, "freq 0 is not a rate");
    }

    /// The reference's static freq→period map, and its 10 µs floor.
    #[test]
    fn freq_mode_becomes_a_fixed_period_and_every_period_has_a_floor() {
        assert_eq!(period_ns(&attr(1000, true)), Some(1_000_000));
        assert_eq!(period_ns(&attr(1, true)), Some(NSEC_PER_SEC));
        // 200 kHz is a 5 µs period, below the floor.
        assert_eq!(period_ns(&attr(200_000, true)), Some(MIN_PERIOD_NS));
        assert_eq!(period_ns(&attr(1, false)), Some(MIN_PERIOD_NS));
        assert_eq!(period_ns(&attr(MIN_PERIOD_NS + 1, false)), Some(MIN_PERIOD_NS + 1));
    }

    #[test]
    fn only_the_clock_pmus_are_timer_driven() {
        assert!(is_clock_source(SwSource::CpuClock));
        assert!(is_clock_source(SwSource::TaskClock));
        assert!(!is_clock_source(SwSource::Zero));
        assert!(!is_clock_source(SwSource::TaskCount(TaskCount::PageFaultsMin)));
    }

    /// Opening a sampling clock event arms its timer without any further
    /// ioctl. Nothing else ever overflows those two PMUs, so an event that
    /// leaves `perf_event_open` unarmed can never sample.
    #[test]
    fn opening_a_sampling_clock_event_arms_its_timer() {
        let _w = wheel();
        for src in [SwSource::CpuClock, SwSource::TaskClock] {
            let ev = PerfEvent::new(attr(MIN_PERIOD_NS, false), src, Some(1), -1, None);
            assert_ne!(ev.hrtimer.load(Ordering::Acquire), 0, "{src:?}");
            stop(&ev);
        }
        // A counter-driven source is fed by its counter site, never by a timer.
        let ev = PerfEvent::new(attr(MIN_PERIOD_NS, false),
                                SwSource::TaskCount(TaskCount::PageFaultsMin), Some(1), -1, None);
        assert_eq!(ev.hrtimer.load(Ordering::Acquire), 0);
        // A counting-only clock event has no period to arm.
        let ev = PerfEvent::new(attr(0, false), SwSource::CpuClock, Some(1), -1, None);
        assert_eq!(ev.hrtimer.load(Ordering::Acquire), 0);
    }

    /// The whole path, on the real wheel: a sampling `cpu-clock` event arms a
    /// timer, the expiry emits a `PERF_RECORD_SAMPLE` into the ring, and the
    /// timer re-arms so the next period samples again.
    #[test]
    fn an_armed_clock_event_emits_a_record_per_expiry_and_re_arms() {
        let _w = wheel();
        let ev = PerfEvent::new(attr(MIN_PERIOD_NS, false), SwSource::CpuClock,
                                None, 0, None);
        let rb = PerfBuffer::hosted(4, 0, false);
        ev.state.lock().buffer = Some(Arc::clone(&rb));
        start(&ev);
        assert_ne!(ev.hrtimer.load(Ordering::Acquire), 0, "the event armed a timer");

        // The hosted clock is a counter, so any large `now` is past the deadline.
        timer::run_due(u64::MAX / 2);
        let rec = rb.peek_data(0, 24);
        assert_eq!(u32::from_le_bytes(rec[0..4].try_into().unwrap()), record::SAMPLE);
        assert_eq!(u64::from_le_bytes(rec[16..24].try_into().unwrap()), MIN_PERIOD_NS,
                   "PERF_SAMPLE_PERIOD reports the timer's own period");
        let first = rb.unread();
        assert_ne!(ev.hrtimer.load(Ordering::Acquire), 0, "re-armed for the next period");
        timer::run_due(u64::MAX / 2);
        assert!(rb.unread() > first, "the next expiry sampled again");
        stop(&ev);
        assert_eq!(ev.hrtimer.load(Ordering::Acquire), 0);
    }

    /// A disabled event samples nothing (`perf_swevent_start_hrtimer` runs from
    /// `pmu::add`, which a disabled event never reaches).
    #[test]
    fn a_disabled_clock_event_arms_no_timer() {
        let _w = wheel();
        let a = PerfAttr { bits: 1 << attr_bit::DISABLED, ..attr(MIN_PERIOD_NS, false) };
        let ev = PerfEvent::new(a, SwSource::CpuClock, None, 0, None);
        assert!(!wants_timer(&ev));
        start(&ev);
        assert_eq!(ev.hrtimer.load(Ordering::Acquire), 0);
    }

    /// A closed event must not be kept alive by its own timer, and the expiry
    /// after the close must not re-arm.
    #[test]
    fn a_dropped_event_stops_its_timer_rather_than_being_pinned_by_it() {
        let _w = wheel();
        let ev = PerfEvent::new(attr(MIN_PERIOD_NS, false), SwSource::CpuClock,
                                None, 0, None);
        let w = Arc::downgrade(&ev);
        start(&ev);
        drop(ev);
        assert!(w.upgrade().is_none(), "the wheel held a Weak, not a strong ref");
        timer::run_due(u64::MAX / 2);
        timer::run_due(u64::MAX / 2);
    }
}
