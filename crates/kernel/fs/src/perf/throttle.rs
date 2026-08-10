// Sampling-interrupt throttling and its two markers.
//
// The point of the facility: a sampling event with a short period can generate
// records faster than any consumer drains them, and the sampling site sits in
// interrupt-like context, so an unbounded rate starves the machine. The budget
// is `max_samples_per_tick` interrupts per event per tick; crossing it parks the
// event, emits `PERF_RECORD_THROTTLE`, and the next tick releases it with
// `PERF_RECORD_UNTHROTTLE`. A consumer that sees neither record cannot tell a
// quiet workload from a throttled one, which is why the two records are part of
// the ABI and not an optimisation.
//
// The decision arithmetic is pure over `Interrupts` and hosted-tested; only the
// tick and the park/release helpers touch live events.

use core::sync::atomic::{AtomicU64, Ordering};

use cpu::MAX_CPUS;

/// The sentinel the interrupt count is parked at while throttled. It is a
/// count, not a flag, precisely so the "already throttled" test reads the same
/// field the budget does and the two cannot disagree.
pub const MAX_INTERRUPTS: u64 = u64::MAX;

/// One event's per-tick interrupt budget state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Interrupts {
    /// Interrupts taken in the current tick, or [`MAX_INTERRUPTS`] when parked.
    pub count: u64,
    /// The tick generation `count` belongs to.
    pub seq:   u64,
}

/// Fold this interrupt into the current tick's budget and report whether it
/// crossed the limit.
///
/// `throttle` is false for the FIRST record produced by one overflow
/// opportunity and true for every one after it, so a single overflow can never
/// throttle on its own. A timer-driven expiry arrives as one record with
/// `throttle` already true.
/// # C: O(1)
pub fn account(hw: &mut Interrupts, seq: u64, throttle: bool, max_per_tick: u64) -> bool {
    if hw.seq != seq {
        hw.seq = seq;
        hw.count = 1;
    } else {
        hw.count = hw.count.saturating_add(1);
    }
    throttle && hw.count >= max_per_tick
}

/// Whether the event is parked — the test that inhibits sampling outright,
/// rather than merely discarding the records. # C: O(1)
pub fn is_throttled(hw: &Interrupts) -> bool { hw.count == MAX_INTERRUPTS }

/// Park the budget. # C: O(1)
pub fn park(hw: &mut Interrupts) { hw.count = MAX_INTERRUPTS; }

/// Release the budget, so the next interrupt starts a fresh tick's count.
/// # C: O(1)
pub fn release(hw: &mut Interrupts) { hw.count = 0; }

// ---- per-CPU tick generation --------------------------------------------
//
// The generation is what makes the budget PER TICK without any timer having to
// touch each event: an event whose recorded generation is stale starts a fresh
// count on its next interrupt.

static SEQ:       [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static THROTTLED: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// This CPU's current budget generation. # C: O(1)
pub fn seq(cpu: usize) -> u64 {
    if cpu >= MAX_CPUS { return 0; }
    SEQ[cpu].load(Ordering::Relaxed)
}

/// Note one more event parked on this CPU. # C: O(1)
pub fn note_throttled(cpu: usize) {
    if cpu >= MAX_CPUS { return; }
    THROTTLED[cpu].fetch_add(1, Ordering::Relaxed);
}

/// Whether anything on `cpu` is parked, so the tick can skip the walk entirely.
/// # C: O(1)
pub fn any_throttled(cpu: usize) -> bool {
    if cpu >= MAX_CPUS { return false; }
    THROTTLED[cpu].load(Ordering::Relaxed) != 0
}

/// Open the next tick's budget on `cpu` and take the parked count, which the
/// caller uses to decide whether the release walk is needed at all. # C: O(1)
pub fn advance(cpu: usize) -> u64 {
    if cpu >= MAX_CPUS { return 0; }
    SEQ[cpu].fetch_add(1, Ordering::Relaxed);
    THROTTLED[cpu].swap(0, Ordering::Relaxed)
}

// ---- live half ----------------------------------------------------------

use alloc::sync::Arc;

use super::event::{now_ns, PerfEvent};
use super::registry;
use super::sample::SampleValues;
use super::sideband::record::throttle_record;
use super::uapi::attr_bit;

/// Park every member of `ev`'s group and emit `PERF_RECORD_THROTTLE` against
/// the leader, which is the stream a consumer tracks the group by. A
/// timer-driven event's timer is cancelled here, so a parked event stops
/// GENERATING opportunities rather than merely discarding them. # C: O(group)
pub fn park_group(ev: &Arc<PerfEvent>, cpu: usize) {
    for m in ev.group_members() {
        {
            let mut g = m.state.lock();
            if is_throttled(&g.interrupts) { continue; }
            park(&mut g.interrupts);
        }
        note_throttled(cpu);
        super::hrtimer::stop(&m);
        if m.leader.is_none() { log(&m, false); }
    }
}

/// Release one parked event: its counter budget reopens, a timer-driven event
/// re-arms, and `PERF_RECORD_UNTHROTTLE` is emitted against a leader.
/// # C: O(1)
fn release_one(ev: &Arc<PerfEvent>) {
    {
        let mut g = ev.state.lock();
        if !is_throttled(&g.interrupts) { return; }
        release(&mut g.interrupts);
    }
    super::hrtimer::start(ev);
    if ev.leader.is_none() { log(ev, true); }
}

/// One tick: open the next budget generation on every CPU and, if anything
/// parked since the last tick, release it. The "nothing parked, nothing to do"
/// shortcut keeps the common case at one atomic per CPU.
/// # C: O(CPUs) + O(events) only when something was parked
pub fn tick() {
    if !registry::any_registered() { return; }
    let mut parked = 0u64;
    for c in 0..cpu::count().max(1) as usize { parked = parked.saturating_add(advance(c)); }
    if parked == 0 { return; }
    for ev in registry::all_events() { release_one(&ev); }
}

/// Start the periodic tick that releases throttled events. Called once from
/// `emit::init`. # C: O(1)
pub fn init() { timer::register_periodic(sched::posix_clock::TICK_NSEC, |_| tick()); }

/// Emit one throttle marker into the event's output ring.
fn log(ev: &Arc<PerfEvent>, enable: bool) {
    let Some(out) = ev.output_target() else { return };
    let Some(rb) = out.buffer() else { return };
    let v = SampleValues {
        id: out.id, stream_id: ev.id, ip: 0, addr: 0, period: 0,
        pid: 0, tid: ev.tid.unwrap_or(0), time: now_ns(),
        cpu: ev.cpu.max(0) as u32,
    };
    let st = out.attr.sample_type;
    let all = out.attr.bit(attr_bit::SAMPLE_ID_ALL);
    let Some(r) = throttle_record(enable, st, all, &v) else { return };
    match rb.output(r.as_slice(),
                    |lost| super::sample::lost_record::<{ super::sideband::record::SIDEBAND_MAX }>(st, all, lost, &v)) {
        Some(w) => if w.wakeup { out.wakeup(); },
        None    => { rb.note_lost(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hw() -> Interrupts { Interrupts::default() }

    /// A burst inside one tick counts up; the first record of the burst is
    /// exempt, so a single
    /// overflow can never throttle.
    #[test]
    fn the_first_record_of_a_burst_is_never_throttled() {
        let mut h = hw();
        assert!(!account(&mut h, 1, false, 1), "throttle=0 exempts the first");
        assert_eq!(h.count, 1);
        assert!(account(&mut h, 1, true, 1), "the second crosses a budget of one");
    }

    #[test]
    fn the_budget_is_per_tick_and_a_new_seq_restarts_the_count() {
        let mut h = hw();
        for _ in 0..10 { assert!(!account(&mut h, 7, true, 100)); }
        assert_eq!(h.count, 10);
        // The tick moved on: the count restarts at one, not eleven.
        assert!(!account(&mut h, 8, true, 100));
        assert_eq!(h.count, 1);
        assert_eq!(h.seq, 8);
    }

    #[test]
    fn crossing_the_budget_reports_a_throttle_at_exactly_the_limit() {
        let mut h = hw();
        for i in 1..4 { assert!(!account(&mut h, 1, true, 4), "interrupt {i}"); }
        assert!(account(&mut h, 1, true, 4), "the fourth interrupt hits the limit");
    }

    /// Positive control for the sentinel: a parked event reports throttled and
    /// a release clears it. Replace `park` with `hw.count = 0` and the first
    /// assertion fails.
    #[test]
    fn park_and_release_move_the_sentinel() {
        let mut h = hw();
        assert!(!is_throttled(&h));
        park(&mut h);
        assert!(is_throttled(&h));
        assert_eq!(h.count, MAX_INTERRUPTS);
        release(&mut h);
        assert!(!is_throttled(&h));
        assert_eq!(h.count, 0);
        // A release must also let the next interrupt start a fresh budget.
        let sq = h.seq;
        assert!(!account(&mut h, sq, true, 2));
        assert_eq!(h.count, 1);
    }

    /// The per-CPU generation is what makes the budget per-tick without the
    /// tick touching any event.
    #[test]
    fn advancing_a_cpu_moves_only_that_cpus_generation() {
        let (a, b) = (MAX_CPUS - 1, MAX_CPUS - 2);
        let (sa, sb) = (seq(a), seq(b));
        advance(a);
        assert_eq!(seq(a), sa + 1);
        assert_eq!(seq(b), sb);
        advance(b);
        assert_eq!(seq(b), sb + 1);
    }

    #[test]
    fn the_parked_count_is_taken_by_the_tick_that_reads_it() {
        let cpu = MAX_CPUS - 3;
        advance(cpu);
        assert!(!any_throttled(cpu));
        note_throttled(cpu);
        note_throttled(cpu);
        assert!(any_throttled(cpu));
        assert_eq!(advance(cpu), 2);
        assert!(!any_throttled(cpu), "the tick consumed it");
        assert_eq!(advance(cpu), 0);
    }

    // ---- live path ------------------------------------------------------

    extern crate std;
    use crate::perf::attr::PerfAttr;
    use crate::perf::counter::{SwSource, TaskCount};
    use crate::perf::emit;
    use crate::perf::ring::PerfBuffer;
    use crate::perf::uapi::{record as rec, sample as samp};

    /// The sampling-rate cell is one global, so the tests that lower it run in
    /// turn rather than racing each other's budget.
    static RATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn with_budget_of_one() -> (std::sync::MutexGuard<'static, ()>, i32) {
        let g = RATE.lock().unwrap_or_else(|e| e.into_inner());
        let saved = sched::perf_sw::sample_rate();
        // One sample per tick at this kernel's tick rate.
        sched::perf_sw::set_sample_rate(sched::perf_sw::HZ as i32);
        (g, saved)
    }

    fn mapped(sample_type: u64) -> Arc<PerfEvent> { mapped_period(sample_type, 4) }

    fn mapped_period(sample_type: u64, sample_period: u64) -> Arc<PerfEvent> {
        let attr = PerfAttr { sample_period, sample_type, ..PerfAttr::default() };
        let ev = PerfEvent::new(attr, SwSource::TaskCount(TaskCount::PageFaultsMin),
                                None, 0, None);
        ev.state.lock().buffer = Some(PerfBuffer::hosted(8, 0, false));
        ev
    }

    /// One counter-site opportunity charging `nr` units. A single unit can
    /// never throttle: the first record produced by one opportunity is always
    /// admitted, so only a burst that covers several whole periods at once —
    /// or a timer-driven expiry — can cross the budget.
    fn burst(nr: u64) -> sched::perf_sw::SwSite {
        sched::perf_sw::SwSite { kind: sched::perf_sw::CpuSw::MinFlt, cpu: 0, nr,
                                 ip: 0x1000, addr: 0, user: false, charged: None }
    }
    fn site() -> sched::perf_sw::SwSite { burst(40) }

    /// Every record type in the ring, in order.
    fn types(rb: &Arc<PerfBuffer>) -> alloc::vec::Vec<u32> {
        let n = rb.unread() as usize;
        let all = rb.peek_data(0, n);
        let mut out = alloc::vec::Vec::new();
        let mut i = 0;
        while i + 8 <= all.len() {
            let ty = u32::from_le_bytes(all[i..i + 4].try_into().unwrap());
            let sz = u16::from_le_bytes(all[i + 6..i + 8].try_into().unwrap()) as usize;
            if sz == 0 { break; }
            out.push(ty);
            i += sz;
        }
        out
    }

    /// A burst past the per-tick budget parks the event: the throttle marker
    /// lands in the ring, one final sample follows, and every later
    /// opportunity in the same tick produces nothing at all.
    #[test]
    fn a_burst_past_the_budget_parks_the_event_and_marks_the_ring() {
        let (_g, saved) = with_budget_of_one();
        let ev = mapped(samp::IP);
        let rb = ev.buffer().unwrap();
        advance(0);
        // Ten opportunities, budget one per tick.
        // One opportunity covering ten whole periods.
        emit::deliver(&ev, &site(), 1, 1, None);
        let t = types(&rb);
        assert!(is_throttled(&ev.state.lock().interrupts), "the event parked");
        assert_eq!(t.iter().filter(|&&x| x == rec::THROTTLE).count(), 1,
                   "exactly one throttle marker: {t:?}");
        assert!(t.iter().filter(|&&x| x == rec::SAMPLE).count() < 10,
                "the burst was cut short: {t:?}");
        assert_eq!(t.last().copied(), Some(rec::SAMPLE),
                   "the marker precedes the last admitted sample: {t:?}");
        sched::perf_sw::set_sample_rate(saved);
    }

    /// The next tick releases the event, marks the ring with the unthrottle
    /// counterpart, and sampling resumes.
    #[test]
    fn the_next_tick_releases_the_event_and_marks_the_ring() {
        let (_g, saved) = with_budget_of_one();
        let ev = mapped(samp::IP);
        let rb = ev.buffer().unwrap();
        advance(0);
        emit::deliver(&ev, &site(), 1, 1, None);
        assert!(is_throttled(&ev.state.lock().interrupts));
        let before = types(&rb).len();

        tick();

        assert!(!is_throttled(&ev.state.lock().interrupts), "the tick released it");
        let t = types(&rb);
        assert_eq!(t.iter().filter(|&&x| x == rec::UNTHROTTLE).count(), 1,
                   "one unthrottle marker: {t:?}");
        assert!(t.len() > before);
        // ... and the event samples again.
        emit::deliver(&ev, &site(), 1, 1, None);
        assert!(types(&rb).len() > t.len(), "sampling resumed after the release");
        sched::perf_sw::set_sample_rate(saved);
    }

    /// POSITIVE CONTROL for the whole ladder: with the budget raised out of
    /// reach the same burst parks nothing and emits no marker, so the two tests
    /// above are measuring the budget and not some unrelated cap.
    #[test]
    fn positive_control_a_budget_out_of_reach_throttles_nothing() {
        let (_g, saved) = with_budget_of_one();
        sched::perf_sw::set_sample_rate(saved.max(100_000));
        let ev = mapped(samp::IP);
        let rb = ev.buffer().unwrap();
        advance(0);
        emit::deliver(&ev, &site(), 1, 1, None);
        let t = types(&rb);
        assert!(!is_throttled(&ev.state.lock().interrupts));
        assert_eq!(t.iter().filter(|&&x| x == rec::THROTTLE).count(), 0, "{t:?}");
        assert_eq!(t.iter().filter(|&&x| x == rec::SAMPLE).count(), 10, "{t:?}");
        sched::perf_sw::set_sample_rate(saved);
    }

    /// A parked event's records carry the same identity a sample does, so a
    /// consumer can attribute the throttle to the stream it belongs to.
    #[test]
    fn the_marker_carries_time_id_and_stream_id() {
        let (_g, saved) = with_budget_of_one();
        let ev = mapped(samp::IP);
        let rb = ev.buffer().unwrap();
        advance(0);
        emit::deliver(&ev, &site(), 1, 1, None);
        let n = rb.unread() as usize;
        let all = rb.peek_data(0, n);
        // Walk to the marker.
        let mut i = 0;
        while i + 8 <= all.len() {
            let ty = u32::from_le_bytes(all[i..i + 4].try_into().unwrap());
            let sz = u16::from_le_bytes(all[i + 6..i + 8].try_into().unwrap()) as usize;
            if ty == rec::THROTTLE {
                assert_eq!(sz, 8 + 24, "header plus time/id/stream_id");
                let id = u64::from_le_bytes(all[i + 16..i + 24].try_into().unwrap());
                let sid = u64::from_le_bytes(all[i + 24..i + 32].try_into().unwrap());
                assert_eq!(id, ev.id);
                assert_eq!(sid, ev.id);
                sched::perf_sw::set_sample_rate(saved);
                return;
            }
            if sz == 0 { break; }
            i += sz;
        }
        sched::perf_sw::set_sample_rate(saved);
        panic!("no throttle marker in the ring");
    }

    /// An out-of-range CPU is dropped rather than aliased onto slot 0, which
    /// would let one CPU's tick reset another's budget.
    #[test]
    fn an_out_of_range_cpu_is_dropped_not_aliased() {
        let s0 = seq(0);
        note_throttled(MAX_CPUS);
        assert_eq!(advance(MAX_CPUS), 0);
        assert_eq!(seq(MAX_CPUS), 0);
        assert_eq!(seq(0), s0, "slot 0 was not touched");
    }
}
