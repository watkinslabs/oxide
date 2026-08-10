// Event scheduling lifecycle — `event_sched_in`/`event_sched_out` and the
// context halves that drive them from a context switch.
//
// An event counts while it is SCHEDULED IN, not while it is enabled. For a
// `pid == -1` event the two are the same thing: a CPU context is never
// scheduled out, so such an event counts from the moment it is enabled. For a
// task-scoped event they are not, and the difference is the whole of what this
// module exists for — a thread that opens `PERF_COUNT_SW_CPU_CLOCK` and then
// spends 99% of its life blocked on I/O must be charged the 1% it ran. Without
// a start and a stop at the switch its counter reads the wall-clock interval
// since it was enabled, which is a profile that says every thread is CPU-bound.
//
// The same start/stop drives three other things that are wrong for the same
// reason if it is missing: `total_time_enabled`/`total_time_running`, which are
// measured over the counting windows and not over the thread's lifetime; the
// sampling timer of a clock-PMU event, which must not produce samples for a
// thread that is not running; and the counter-site sampling gate, which takes
// an opportunity only for an event that is scheduled in.
//
// Pure over its inputs and free of any target gate, so the whole lifecycle is
// hosted-testable (`docs/53`); the only kernel-only part is the timestamp's
// journey from the switch site, which is the scheduler's.

use alloc::sync::Arc;

use super::context;
use super::counter::SwSource;
use super::event::PerfEvent;
use super::hrtimer;
use super::registry;

/// Whether a newly created event joins its context already scheduled in.
///
/// Three cases, and each of them is a state the context is genuinely in:
///
/// - a CPU context (`target` `None`) is always scheduled in;
/// - a fork-inherited event belongs to a child that has not run yet, so it
///   starts scheduled OUT and its first switch-in opens its first window —
///   otherwise the child is charged for the interval between the fork and the
///   first time it is picked;
/// - a task-scoped event is scheduled in exactly when the thread it targets is
///   the one running. Opening an event against some OTHER thread, which may be
///   blocked indefinitely, must not start it counting; its own switch-in will.
///
/// `running` `None` means there is no scheduler to ask. That is not a blocked
/// target: it is a kernel in which no context switch will ever happen, so an
/// event installed scheduled-out would never be scheduled in and could never
/// count at all. Scheduled-in is the only state in which it can behave.
/// # C: O(1)
pub fn install_active(target: Option<u32>, running: Option<u32>, inherited: bool) -> bool {
    if inherited { return false; }
    match (target, running) {
        (None, _)          => true,
        (Some(_), None)    => true,
        (Some(t), Some(r)) => t == r,
    }
}

/// `event_sched_in` — open this event's counting window at `ts`.
///
/// Re-arms the sampling timer of a clock-PMU event that retired itself while
/// its thread was off a CPU, and only then: an event whose timer is still
/// armed is left alone, so a switch costs one atomic load rather than a walk
/// of the timer wheel.
/// # C: O(1), plus one wheel insertion for a clock event that had retired
pub fn event_sched_in(ev: &Arc<PerfEvent>, ts: u64) {
    let src = sample_at(ev, ts);
    let was = { let mut g = ev.state.lock(); let a = g.counter.active; g.counter.start(src, ts); a };
    if !was { hrtimer::resume(ev); }
}

/// `event_sched_out` — close this event's counting window at `ts` and publish
/// what it has counted.
///
/// The publication is the reference's `perf_event_update_userpage` on the same
/// transition: a consumer reading the mapped control page enters no syscall at
/// all, so the value it finds there is only as fresh as the last thing that
/// stored one. The switch out is the moment the count stops changing, which
/// makes it exactly the right moment to store it.
/// # C: O(1)
pub fn event_sched_out(ev: &Arc<PerfEvent>, ts: u64) {
    let src = sample_at(ev, ts);
    let (count, enabled, running, rb) = {
        let mut g = ev.state.lock();
        if !g.counter.active { return; }
        g.counter.stop(src, ts);
        let t = g.counter.time_enabled(ts);
        (g.counter.count(src).wrapping_add(g.child_count),
         t.saturating_add(g.child_time_enabled),
         t.saturating_add(g.child_time_running),
         g.buffer.clone())
    };
    if let Some(rb) = rb { rb.update_userpage(count, enabled, running); }
}

/// The source value that closes or opens a window at the instant `ts`.
///
/// A clock event's source IS the wall clock, so its window must be stamped
/// with the switch's own timestamp and not with a reading taken later: this
/// runs from the bottom half, and by then the drain's delay has elapsed. Every
/// other source is a per-task quantity that stops advancing the moment the
/// thread leaves the CPU, so reading it late reads the same value.
/// # C: O(1) plus the source's own lookup
fn sample_at(ev: &Arc<PerfEvent>, ts: u64) -> u64 {
    match ev.source { SwSource::CpuClock => ts, _ => ev.sample() }
}

/// `ctx_sched_out` — every event of the thread leaving the CPU.
/// # C: O(events in this thread's context)
pub fn ctx_sched_out(tid: u32, ts: u64) {
    for ev in registry::live_task_events(tid) { event_sched_out(&ev, ts); }
}

/// `ctx_sched_in` — every event of the thread taking the CPU.
/// # C: O(events in this thread's context)
pub fn ctx_sched_in(tid: u32, ts: u64) {
    for ev in registry::live_task_events(tid) { event_sched_in(&ev, ts); }
}

/// `perf_event_task_sched_out` + `perf_event_task_sched_in` — one switch's
/// whole context half.
///
/// Order is fixed: the outgoing thread's windows close BEFORE anything else
/// touches them. The mid-life synchronisation that follows folds and publishes
/// against the clock of the moment it runs, which is later than `ts`; running
/// it first would fold the outgoing thread's window at that later instant and
/// leave the close with nothing to add.
///
/// Costs one relaxed atomic load on a kernel with no events open, which is
/// every boot that is not being profiled — the registry lock is not taken and
/// nothing is allocated.
/// # C: O(1) with no events open; O(events in the two contexts) otherwise
pub fn sched_switch(prev_tid: u32, next_tid: u32, ts: u64) {
    if prev_tid == next_tid { return; }
    if !registry::any_registered() { return; }
    ctx_sched_out(prev_tid, ts);
    ctx_sched_in(next_tid, ts);
    context::sched_out(prev_tid, next_tid);
}

#[cfg(test)]
mod tests;
