// The scheduling lifecycle, over the real event objects and the real registry.
//
// THE contract these pin: a task-scoped counter charges the intervals its
// thread was on a CPU and nothing else. Every case here has a stated positive
// control — the assertion that fails when the start/stop is taken away — and
// the control for the clause itself is
// `a_blocked_thread_is_charged_none_of_the_interval_it_waited`, which reads a
// microsecond of on-CPU time out of a second of elapsed time.

use core::sync::atomic::{AtomicU32, Ordering};

use alloc::sync::Arc;

use super::*;
use crate::perf::attr::PerfAttr;
use crate::perf::counter::{SwCounter, SwSource, TaskCount};
use crate::perf::hrtimer::{self, MIN_PERIOD_NS};
use crate::perf::ring::PerfBuffer;
use crate::perf::uapi::{attr_bit, sample};

/// Disjoint tid ranges per case: the registry is process-global and `cargo
/// test` runs these in parallel. This range belongs to this module alone —
/// sharing one with another module's cases has both handing the other's events
/// to `live_task_events`, which reads as a missing event rather than as a
/// collision.
static NEXT_TID: AtomicU32 = AtomicU32::new(1_100_000);
fn fresh_tid() -> u32 { NEXT_TID.fetch_add(1, Ordering::Relaxed) }

fn clock_event(tid: u32) -> Arc<PerfEvent> {
    PerfEvent::new(PerfAttr::default(), SwSource::CpuClock, Some(tid), -1, None)
}

/// A task-scoped clock event parked off a CPU at instant 0, so each case
/// starts from a window of known shape.
///
/// The hosted build has no scheduler to say which thread is running, so an
/// event is installed scheduled-in; parking it here reaches the same state the
/// kernel installs an event on a thread that is not the one running.
fn parked(tid: u32) -> Arc<PerfEvent> {
    let ev = clock_event(tid);
    event_sched_out(&ev, 0);
    assert_eq!(ev.read_value(), (0, 0, 0), "parked with nothing counted");
    ev
}

/// A microsecond of on-CPU time out of a second of elapsed time — the shape of
/// a thread that is blocked on I/O almost all of its life.
const SLICE_NS: u64 = 1_000;
const BLOCKED_NS: u64 = 1_000_000_000;

// ---- the counter algebra, over explicit values --------------------------

fn counter() -> SwCounter { SwCounter::new(0, 0, true) }

/// The window closes at the stop and does not reopen until the start, so the
/// interval between them is charged to nobody.
///
/// POSITIVE CONTROL: delete the `stop`/`start` pair and the count becomes the
/// full elapsed 1_000_000_100 instead of 100.
#[test]
fn a_counter_charges_only_the_intervals_between_start_and_stop() {
    let mut c = counter();
    c.stop(100, 100);
    assert_eq!(c.count(BLOCKED_NS), 100, "the first window, and only it");
    c.start(BLOCKED_NS, BLOCKED_NS);
    c.stop(BLOCKED_NS + 100, BLOCKED_NS + 100);
    assert_eq!(c.count(BLOCKED_NS + 100), 200, "100 ran, then 100 more");
}

/// A stopped counter reads a FIXED value however far the source has moved:
/// this is what a `read(2)` against a blocked thread must see.
#[test]
fn a_stopped_counter_ignores_the_source_entirely() {
    let mut c = counter();
    c.stop(50, 50);
    assert_eq!(c.count(50), 50);
    assert_eq!(c.count(u64::MAX), 50, "the source ran away; the count did not");
    assert_eq!(c.time_enabled(u64::MAX), 50);
}

/// Both clocks are measured over the counting windows, so a mostly-blocked
/// thread reports the ratio 1 rather than the fraction of its life it ran.
#[test]
fn the_enabled_and_running_clocks_freeze_with_the_count() {
    let mut c = counter();
    c.stop(SLICE_NS, SLICE_NS);
    c.start(BLOCKED_NS, BLOCKED_NS);
    assert_eq!(c.time_enabled(BLOCKED_NS + SLICE_NS), 2 * SLICE_NS,
               "the blocked interval is in neither clock");
}

/// Start and stop are each idempotent: a repeated switch-in must not reopen a
/// window that is already open (which would discard everything counted since
/// it opened), and a repeated switch-out must not fold one twice.
#[test]
fn a_repeated_start_or_stop_changes_nothing() {
    let mut c = counter();
    c.start(500, 500);
    assert_eq!(c.count(500), 500, "the already-open window was not reopened");
    c.stop(600, 600);
    c.stop(u64::MAX, u64::MAX);
    assert_eq!(c.count(u64::MAX), 600, "the second stop folded nothing");
}

/// Enable and disable are the OTHER axis, and the two compose: an event
/// disabled while its thread is off a CPU must not be charged the interval it
/// spent blocked when the disable folds.
///
/// POSITIVE CONTROL: make `disable` fold unconditionally and the count becomes
/// the full elapsed interval.
#[test]
fn disabling_a_scheduled_out_event_folds_nothing() {
    let mut c = counter();
    c.stop(SLICE_NS, SLICE_NS);
    c.disable(BLOCKED_NS, BLOCKED_NS);
    assert_eq!(c.count(BLOCKED_NS), SLICE_NS);
    assert_eq!(c.time_enabled(BLOCKED_NS), SLICE_NS);
}

/// A disabled event that is scheduled in and out counts nothing: neither
/// condition alone is enough.
#[test]
fn a_disabled_event_counts_across_a_switch_as_it_does_across_anything() {
    let mut c = SwCounter::new(0, 0, false);
    c.stop(10, 10);
    c.start(20, 20);
    c.stop(u64::MAX, u64::MAX);
    assert_eq!(c.count(u64::MAX), 0);
}

// ---- installation state -------------------------------------------------

/// Each case is a context state, not a policy choice.
#[test]
fn an_event_is_installed_in_the_state_its_context_is_in() {
    // A CPU context is never scheduled out.
    assert!(install_active(None, Some(7), false));
    assert!(install_active(None, None, false));
    // The thread it targets is the one running.
    assert!(install_active(Some(7), Some(7), false));
    // ...and some other thread, which may be blocked indefinitely, is not.
    assert!(!install_active(Some(7), Some(8), false));
    // A fork-inherited child has not run yet, whoever is running.
    assert!(!install_active(Some(7), Some(7), true));
    assert!(!install_active(None, Some(7), true));
    // No scheduler to ask: no switch will ever schedule it in, so installing
    // it scheduled-out would leave it unable to count at all.
    assert!(install_active(Some(7), None, false));
}

// ---- the lifecycle over live events -------------------------------------

/// THE row-298 clause. A thread runs for a microsecond, blocks for a second,
/// then runs for another microsecond. Its `PERF_COUNT_SW_CPU_CLOCK` event must
/// read two microseconds — its ON-CPU time — and not the second it waited.
///
/// POSITIVE CONTROL: `a_wall_clock_source_without_the_switch_charges_the_whole_
/// interval` runs the same arithmetic with the start/stop pair removed and
/// finds the full elapsed interval, a million times larger.
#[test]
fn a_blocked_thread_is_charged_none_of_the_interval_it_waited() {
    let _w = hrtimer::tests::wheel();
    let tid = fresh_tid();
    let ev = parked(tid);
    let mut t = 10_000;

    // First slice: on-CPU from `t`, off at `t + SLICE_NS`.
    event_sched_in(&ev, t);
    t += SLICE_NS;
    event_sched_out(&ev, t);
    let after_first = ev.read_value().0;

    // Blocked. Nothing about the thread advances for a whole second.
    t += BLOCKED_NS;

    // Second slice.
    event_sched_in(&ev, t);
    t += SLICE_NS;
    event_sched_out(&ev, t);

    assert_eq!(ev.read_value().0 - after_first, SLICE_NS,
               "the second slice, and none of the second spent blocked");
    assert_eq!(ev.read_value().0, 2 * SLICE_NS, "two slices, nothing else");
    crate::perf::inherit::on_task_exit(tid);
}

/// The positive control for the case above, expressed as the arithmetic the
/// counter performs when the start/stop pair is not there: a wall-clock source
/// read at two instants a second apart reports the second.
#[test]
fn a_wall_clock_source_without_the_switch_charges_the_whole_interval() {
    let mut c = counter();
    // No `stop` at the switch out, no `start` at the switch in — the window
    // opened once and stayed open.
    c.update(SLICE_NS, SLICE_NS);
    assert_eq!(c.count(SLICE_NS + BLOCKED_NS), SLICE_NS + BLOCKED_NS,
               "a still-open window charges the blocked interval in full");
}

/// `total_time_enabled` and `total_time_running` come off the same windows, so
/// a profile of the blocked thread reports the CPU time it actually got.
#[test]
fn the_reported_times_cover_the_on_cpu_intervals_only() {
    let _w = hrtimer::tests::wheel();
    let tid = fresh_tid();
    let ev = parked(tid);
    event_sched_in(&ev, 0);
    event_sched_out(&ev, SLICE_NS);
    event_sched_in(&ev, BLOCKED_NS);
    event_sched_out(&ev, BLOCKED_NS + SLICE_NS);
    let (_, enabled, running) = ev.read_value();
    assert_eq!(enabled, 2 * SLICE_NS);
    assert_eq!(running, 2 * SLICE_NS);
    crate::perf::inherit::on_task_exit(tid);
}

/// The switch's own timestamp is what stamps both windows, so the outgoing
/// thread's close and the incoming thread's open MEET: no interval is charged
/// twice and none is charged to nobody.
///
/// POSITIVE CONTROL: stamp either side with a reading taken at the drain
/// instead and the two windows overlap by the drain's delay, so the two
/// threads' counts sum to more than the elapsed time.
#[test]
fn the_two_sides_of_a_switch_meet_at_the_switchs_own_instant() {
    let _w = hrtimer::tests::wheel();
    let (a_tid, b_tid) = (fresh_tid(), fresh_tid());
    let (a, b) = (parked(a_tid), parked(b_tid));
    // A runs 0..100, B runs 100..300, A runs 300..600.
    event_sched_in(&a, 0);
    sched_switch(a_tid, b_tid, 100);
    sched_switch(b_tid, a_tid, 300);
    event_sched_out(&a, 600);
    let (ca, cb) = (a.read_value().0, b.read_value().0);
    assert_eq!(ca, 400, "A ran 0..100 and 300..600");
    assert_eq!(cb, 200, "B ran 100..300");
    assert_eq!(ca + cb, 600, "the whole interval, charged exactly once");
    crate::perf::inherit::on_task_exit(a_tid);
    crate::perf::inherit::on_task_exit(b_tid);
}

/// A switch between two threads that have no events must not take the registry
/// lock or allocate — a kernel that is not being profiled pays one atomic
/// load per switch. The observable half of that is that the call is a no-op,
/// and the structural half is the `any_registered` gate it returns through.
#[test]
fn a_switch_with_no_events_open_does_nothing() {
    let _w = hrtimer::tests::wheel();
    let (x, y) = (fresh_tid(), fresh_tid());
    sched_switch(x, y, 1_000);
    assert!(crate::perf::registry::live_task_events(x).is_empty());
    assert!(crate::perf::registry::live_task_events(y).is_empty());
    // A switch from a thread to ITSELF is not a switch.
    let tid = fresh_tid();
    let ev = parked(tid);
    event_sched_in(&ev, 0);
    sched_switch(tid, tid, BLOCKED_NS);
    event_sched_out(&ev, SLICE_NS);
    // Had the self-switch been taken for a real one it would have folded a
    // window at `BLOCKED_NS` and opened another, and the count would carry the
    // whole second.
    assert_eq!(ev.read_value().0, SLICE_NS,
               "one window, opened at 0 and closed a slice later");
    crate::perf::inherit::on_task_exit(tid);
}

/// The other side of the switch is a thread that is EXITING: its context is
/// already gone by the time the bottom half runs. The surviving side must
/// still be scheduled correctly rather than the whole switch being abandoned.
#[test]
fn a_switch_against_an_exited_thread_still_schedules_the_survivor() {
    let _w = hrtimer::tests::wheel();
    let (gone, live) = (fresh_tid(), fresh_tid());
    let dead = parked(gone);
    let ev = parked(live);
    event_sched_in(&ev, 0);
    event_sched_out(&ev, SLICE_NS);
    crate::perf::inherit::on_task_exit(gone);
    drop(dead);
    // The exited thread hands the CPU to the live one.
    sched_switch(gone, live, BLOCKED_NS);
    event_sched_out(&ev, BLOCKED_NS + SLICE_NS);
    assert_eq!(ev.read_value().0, 2 * SLICE_NS,
               "the survivor's window opened at the switch and closed a slice later");
    crate::perf::inherit::on_task_exit(live);
}

/// A per-task COUNT source — page faults, switches — is charged by sites that
/// only run while the thread is on a CPU, so the start/stop must not disturb
/// it. Pinned because the sched-out folds a delta for every source alike.
#[test]
fn a_counter_source_is_unchanged_by_the_scheduling_windows() {
    let _w = hrtimer::tests::wheel();
    let tid = fresh_tid();
    let ev = PerfEvent::new(PerfAttr::default(),
        SwSource::TaskCount(TaskCount::PageFaultsMin), Some(tid), -1, None);
    ev.state.lock().counter.acc = 42;
    event_sched_out(&ev, BLOCKED_NS);
    event_sched_in(&ev, 2 * BLOCKED_NS);
    event_sched_out(&ev, 3 * BLOCKED_NS);
    assert_eq!(ev.read_value().0, 42, "the source never moved, so neither did the count");
    crate::perf::inherit::on_task_exit(tid);
}

/// The switch out publishes the count into the mapped control page, which is
/// where a consumer that never enters the kernel reads it.
///
/// POSITIVE CONTROL: the page reads zero before the switch out, and the
/// assertion fails if the publication is removed.
#[test]
fn a_switch_out_publishes_the_count_to_the_control_page() {
    let _w = hrtimer::tests::wheel();
    let tid = fresh_tid();
    let ev = parked(tid);
    let rb = PerfBuffer::hosted(4, 0, false);
    ev.state.lock().buffer = Some(Arc::clone(&rb));
    event_sched_in(&ev, 0);
    assert_eq!(rb.peek_userpage().0, 0, "nothing published while it runs");
    event_sched_out(&ev, SLICE_NS);
    assert_eq!(rb.peek_userpage(), (SLICE_NS, SLICE_NS, SLICE_NS));
    crate::perf::inherit::on_task_exit(tid);
}

// ---- the sampling timer -------------------------------------------------

fn sampling_attr() -> PerfAttr {
    PerfAttr { sample_period: MIN_PERIOD_NS, sample_type: sample::IP | sample::PERIOD,
               ..PerfAttr::default() }
}

/// A sampling clock event on a thread that is not running must produce no
/// samples: the timer retires itself at its first expiry after the switch out,
/// and the thread's next switch-in arms it again.
///
/// POSITIVE CONTROL: the same event, left scheduled in, emits a record on the
/// very same `run_due` — asserted at the end of this case.
#[test]
fn a_scheduled_out_clock_event_stops_sampling_and_resumes_on_switch_in() {
    let _w = hrtimer::tests::wheel();
    let tid = fresh_tid();
    let ev = PerfEvent::new(sampling_attr(), SwSource::CpuClock, Some(tid), -1, None);
    let rb = PerfBuffer::hosted(4, 0, false);
    ev.state.lock().buffer = Some(Arc::clone(&rb));
    hrtimer::start(&ev);
    assert_ne!(ev.hrtimer.load(Ordering::Acquire), 0, "armed while running");

    event_sched_out(&ev, SLICE_NS);
    timer::run_due(u64::MAX / 2);
    assert_eq!(rb.unread(), 0, "a thread that is not on a CPU samples nothing");
    assert_eq!(ev.hrtimer.load(Ordering::Acquire), 0, "and the timer retired itself");

    event_sched_in(&ev, BLOCKED_NS);
    assert_ne!(ev.hrtimer.load(Ordering::Acquire), 0, "the switch-in re-armed it");
    timer::run_due(u64::MAX / 2);
    assert!(rb.unread() > 0, "and it samples again");
    hrtimer::stop(&ev);
    crate::perf::inherit::on_task_exit(tid);
}

/// The re-arm is only for an event that has none: a switch-in against a live
/// timer must leave it alone rather than cancel and re-register, which on this
/// wheel is a scan of every registration under one lock.
#[test]
fn a_switch_in_leaves_an_already_armed_timer_alone() {
    let _w = hrtimer::tests::wheel();
    let tid = fresh_tid();
    let ev = PerfEvent::new(sampling_attr(), SwSource::CpuClock, Some(tid), -1, None);
    hrtimer::start(&ev);
    let armed = ev.hrtimer.load(Ordering::Acquire);
    assert_ne!(armed, 0);
    // Not a switch-in at all — already scheduled in.
    event_sched_in(&ev, SLICE_NS);
    assert_eq!(ev.hrtimer.load(Ordering::Acquire), armed, "the same registration");
    hrtimer::stop(&ev);
    crate::perf::inherit::on_task_exit(tid);
}

// ---- the counter-site sampling gate -------------------------------------

/// An opportunity charged to a thread cannot be taken by an event that was not
/// scheduled in when it happened.
///
/// POSITIVE CONTROL: the same delivery against the same event, scheduled in,
/// produces a record — asserted first, so the case cannot pass by delivering
/// nothing at all.
#[test]
fn a_scheduled_out_event_takes_no_sampling_opportunity() {
    let _w = hrtimer::tests::wheel();
    let tid = fresh_tid();
    let a = PerfAttr { sample_period: 1, sample_type: sample::IP, ..PerfAttr::default() };
    let ev = PerfEvent::new(a, SwSource::TaskCount(TaskCount::PageFaultsMin),
                            Some(tid), -1, None);
    let rb = PerfBuffer::hosted(4, 0, false);
    ev.state.lock().buffer = Some(Arc::clone(&rb));
    let site = sched::perf_sw::SwSite {
        kind: sched::perf_sw::CpuSw::MinFlt, cpu: 0, nr: 1, ip: 0x1000, addr: 0,
        user: true, charged: None };

    crate::perf::emit::deliver(&ev, &site, 1, tid, None);
    let ran = rb.unread();
    assert!(ran > 0, "control: a scheduled-in event samples");

    event_sched_out(&ev, SLICE_NS);
    crate::perf::emit::deliver(&ev, &site, 1, tid, None);
    assert_eq!(rb.unread(), ran, "and a scheduled-out one does not");
    crate::perf::inherit::on_task_exit(tid);
}

// ---- installation, end to end -------------------------------------------

/// An event opened against a thread that is not the one running joins its
/// context scheduled OUT, so it counts nothing until that thread runs.
///
/// The hosted build has no scheduler to name a running thread, so this drives
/// the inherited case, which is scheduled out for the same reason and by the
/// same decision.
#[test]
fn a_fork_inherited_event_counts_nothing_until_the_child_runs() {
    let _w = hrtimer::tests::wheel();
    let (p_tid, c_tid) = (fresh_tid(), fresh_tid());
    let mut a = PerfAttr::default();
    a.bits |= 1 << attr_bit::INHERIT;
    let parent = PerfEvent::new(a, SwSource::CpuClock, Some(p_tid), -1, None);
    assert_eq!(crate::perf::inherit::on_fork(p_tid, c_tid, false), 1);
    let child = crate::perf::registry::live_task_events(c_tid).into_iter().next()
        .expect("the inherited child");
    assert!(!child.state.lock().counter.active,
            "the child has not been picked yet");

    // A second passes between the fork and the child's first slice.
    event_sched_in(&child, BLOCKED_NS);
    event_sched_out(&child, BLOCKED_NS + SLICE_NS);
    assert_eq!(child.read_value().0, SLICE_NS,
               "the child is charged its own slice, not the wait for it");
    drop((parent, child));
    crate::perf::inherit::on_task_exit(p_tid);
    crate::perf::inherit::on_task_exit(c_tid);
}
