// `PERF_EVENT_IOC_SET_OUTPUT` — redirecting one event's records into another
// event's ring buffer.
//
// What it buys a profiler: one ring per CPU instead of one per event, so a
// group of counters produces a single ordered record stream. What it must never
// allow is two events writing a ring whose reader cannot decode the result —
// hence the constraint ladder below, every rung of which answers `EINVAL`.
//
// Pure over the facts the ioctl gathers, so the whole ladder — including the
// order the rungs are evaluated in, which decides which `EINVAL` a caller with
// two problems gets — is hosted-testable. Only `apply` touches live state.

use alloc::sync::Arc;

use syscall::errno::Errno;

use super::event::PerfEvent;
use super::uapi::attr_bit;

/// The two events' facts, as the redirect ladder reads them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RedirectCtx {
    /// The two events are the same open file description.
    pub same_event:   bool,
    /// The CPU each event is bound to; `-1` means "follows its task".
    pub cpu:          i32,
    pub out_cpu:      i32,
    /// The thread each event targets; `None` for a CPU-scoped event.
    pub tid:          Option<u32>,
    pub out_tid:      Option<u32>,
    /// The timestamp source each event's records are stamped with.
    pub clock:        i32,
    pub out_clock:    i32,
    /// Whether records are written from the end of the ring backwards.
    pub backward:     bool,
    pub out_backward: bool,
    /// This event already has a live mapping of its own ring, so its records
    /// cannot be redirected out from under the process reading it.
    pub mapped:       bool,
    /// The target event owns a ring with at least one live mapping.
    pub out_mapped:   bool,
}

/// Whether `event`'s records may be redirected into `target`'s ring.
/// `None` is the "stop redirecting" form, which only has to check that this
/// event has no live mapping of its own.
///
/// Every refusal is `EINVAL`; the ORDER matters because a caller that trips two
/// rungs must get the same answer every time. # C: O(1)
pub fn redirect_ok(c: &RedirectCtx, detach: bool) -> Result<(), Errno> {
    if !detach {
        // An event cannot be its own output: the redirect would be a cycle,
        // and a cycle of length one is still a cycle.
        if c.same_event { return Err(Errno::Einval); }
        // Records carry the CPU they were taken on; two CPUs sharing one ring
        // would interleave without an ordering a reader could recover.
        if c.out_cpu != c.cpu { return Err(Errno::Einval); }
        // A ring that follows a task rather than a CPU is that task's ring, so
        // only events on the same task may write it.
        if c.out_cpu == -1 && c.out_tid != c.tid { return Err(Errno::Einval); }
        // Timestamps from two different clocks in one stream cannot be ordered.
        if c.out_clock != c.clock { return Err(Errno::Einval); }
        // Forwards and backwards writers disagree about where the next record
        // goes, so one ring can only have one direction.
        if c.backward != c.out_backward { return Err(Errno::Einval); }
    }
    // Redirecting away from a ring this event still has mapped would leave the
    // process reading a ring nothing writes any more.
    if c.mapped { return Err(Errno::Einval); }
    // The target must actually own a mapped ring; redirecting into nothing
    // would silently discard every record.
    if !detach && !c.out_mapped { return Err(Errno::Einval); }
    Ok(())
}

/// Gather the ladder's inputs from two live events. # C: O(1)
pub fn ctx_of(ev: &Arc<PerfEvent>, target: Option<&Arc<PerfEvent>>) -> RedirectCtx {
    let mapped = ev.state.lock().mmap_count != 0;
    match target {
        None => RedirectCtx { mapped, cpu: ev.cpu, out_cpu: ev.cpu,
                              clock: clock_of(ev), out_clock: clock_of(ev), ..RedirectCtx::default() },
        Some(t) => RedirectCtx {
            same_event:   Arc::ptr_eq(ev, t),
            cpu:          ev.cpu,
            out_cpu:      t.cpu,
            tid:          ev.tid,
            out_tid:      t.tid,
            clock:        clock_of(ev),
            out_clock:    clock_of(t),
            backward:     ev.attr.bit(attr_bit::WRITE_BACKWARD),
            out_backward: t.attr.bit(attr_bit::WRITE_BACKWARD),
            mapped,
            out_mapped:   t.buffer().is_some_and(|rb| rb.acct().count() != 0),
        },
    }
}

/// The timestamp source an event's records are stamped with. Without an
/// explicit selection every event shares the one monotonic source, which is
/// what makes the mismatch rung a real check rather than a formality.
/// # C: O(1)
fn clock_of(ev: &Arc<PerfEvent>) -> i32 {
    if ev.attr.bit(attr_bit::USE_CLOCKID) { ev.attr.clockid } else { -1 }
}

/// Point `ev`'s records at `target`'s ring, or back at nothing.
///
/// The event does not take a mapping reference on the borrowed ring: the ring's
/// lifetime is its owner's mappings, and when the last of those goes the owner
/// detaches it. A redirected event whose target ring has gone simply has no
/// ring again, which is the same state it started in. # C: O(1)
pub fn apply(ev: &Arc<PerfEvent>, target: Option<&Arc<PerfEvent>>) -> Result<(), Errno> {
    let c = ctx_of(ev, target);
    redirect_ok(&c, target.is_none())?;
    let rb = match target { Some(t) => t.buffer(), None => None };
    ev.state.lock().buffer = rb;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_ctx() -> RedirectCtx {
        RedirectCtx { same_event: false, cpu: 0, out_cpu: 0, tid: None, out_tid: None,
                      clock: -1, out_clock: -1, backward: false, out_backward: false,
                      mapped: false, out_mapped: true }
    }

    #[test]
    fn a_matching_pair_is_admitted() {
        assert_eq!(redirect_ok(&ok_ctx(), false), Ok(()));
    }

    #[test]
    fn an_event_cannot_be_its_own_output() {
        let mut c = ok_ctx();
        c.same_event = true;
        assert_eq!(redirect_ok(&c, false), Err(Errno::Einval));
    }

    #[test]
    fn the_two_events_must_be_on_the_same_cpu() {
        let mut c = ok_ctx();
        c.out_cpu = 1;
        assert_eq!(redirect_ok(&c, false), Err(Errno::Einval));
    }

    /// A task-following ring belongs to its task: another task's event may not
    /// write it, but a second event on the SAME task may.
    #[test]
    fn a_task_following_ring_only_takes_events_from_that_task() {
        let mut c = ok_ctx();
        c.cpu = -1; c.out_cpu = -1;
        c.tid = Some(7); c.out_tid = Some(8);
        assert_eq!(redirect_ok(&c, false), Err(Errno::Einval));
        c.out_tid = Some(7);
        assert_eq!(redirect_ok(&c, false), Ok(()));
        // On a CPU-bound ring the task is irrelevant.
        c.cpu = 2; c.out_cpu = 2; c.out_tid = Some(9);
        assert_eq!(redirect_ok(&c, false), Ok(()));
    }

    #[test]
    fn mixed_clocks_and_mixed_directions_are_refused() {
        let mut c = ok_ctx();
        c.out_clock = 1;
        assert_eq!(redirect_ok(&c, false), Err(Errno::Einval));
        let mut c = ok_ctx();
        c.backward = true;
        assert_eq!(redirect_ok(&c, false), Err(Errno::Einval));
        c.out_backward = true;
        assert_eq!(redirect_ok(&c, false), Ok(()), "both backwards is one direction");
    }

    #[test]
    fn an_event_with_its_own_live_mapping_cannot_be_redirected() {
        let mut c = ok_ctx();
        c.mapped = true;
        assert_eq!(redirect_ok(&c, false), Err(Errno::Einval));
        // ... and neither can it be detached.
        assert_eq!(redirect_ok(&c, true), Err(Errno::Einval));
    }

    #[test]
    fn the_target_must_own_a_mapped_ring() {
        let mut c = ok_ctx();
        c.out_mapped = false;
        assert_eq!(redirect_ok(&c, false), Err(Errno::Einval));
    }

    /// THE recorded defect this closes: detaching an event that has no live
    /// mapping SUCCEEDS. It used to answer EINVAL, so a profiler undoing a
    /// redirect saw a failure where the operation had in fact nothing to do.
    /// Positive control: restore the unconditional EINVAL and this is the test
    /// that goes red.
    #[test]
    fn detaching_an_unmapped_event_succeeds() {
        let mut c = RedirectCtx { mapped: false, ..RedirectCtx::default() };
        assert_eq!(redirect_ok(&c, true), Ok(()));
        // The detach form ignores every cross-event rung: there is no other
        // event involved, so none of them can apply.
        c.same_event = true;
        c.out_cpu = 99;
        c.out_clock = 5;
        c.out_backward = true;
        c.out_mapped = false;
        assert_eq!(redirect_ok(&c, true), Ok(()));
    }

    /// Rung ORDER: a request that trips several must always report the first,
    /// so the errno a caller sees does not depend on evaluation accidents.
    #[test]
    fn the_first_failing_rung_decides_the_answer() {
        // Same event AND a CPU mismatch AND no target ring: still one answer.
        let c = RedirectCtx { same_event: true, cpu: 0, out_cpu: 3, out_mapped: false,
                              ..ok_ctx() };
        assert_eq!(redirect_ok(&c, false), Err(Errno::Einval));
    }

    // ---- live redirect ---------------------------------------------------

    use crate::perf::attr::PerfAttr;
    use crate::perf::counter::{SwSource, TaskCount};
    use crate::perf::ring::PerfBuffer;

    fn event(cpu: i32) -> Arc<PerfEvent> {
        PerfEvent::new(PerfAttr { sample_period: 1, ..PerfAttr::default() },
                       SwSource::TaskCount(TaskCount::PageFaultsMin), None, cpu, None)
    }

    /// A ring with one live mapping, as a successful `mmap(2)` leaves it.
    fn mapped_ring(ev: &Arc<PerfEvent>) -> Arc<PerfBuffer> {
        let rb = PerfBuffer::hosted(4, 0, false);
        rb.acct().opened();
        let mut g = ev.state.lock();
        g.buffer = Some(Arc::clone(&rb));
        g.mmap_count += 1;
        drop(g);
        rb
    }

    /// The whole point of the facility: after the redirect, the follower's
    /// samples land in the leader's ring.
    #[test]
    fn a_redirected_events_records_land_in_the_targets_ring() {
        use crate::perf::emit;
        use crate::perf::uapi::record as rec;
        let owner = event(0);
        let rb = mapped_ring(&owner);
        let follower = event(0);
        assert_eq!(apply(&follower, Some(&owner)), Ok(()));

        let before = rb.unread();
        emit::deliver(&follower, &sched::perf_sw::SwSite {
            kind: sched::perf_sw::CpuSw::MinFlt, cpu: 0, nr: 1, ip: 0x2000,
            addr: 0, user: false, charged: None }, 1, 1, None);
        assert!(rb.unread() > before, "the follower wrote the target's ring");
        assert_eq!(u32::from_le_bytes(rb.peek_data(before, 4).try_into().unwrap()),
                   rec::SAMPLE);
    }

    /// Detaching leaves the event with no ring, so it stops writing the
    /// target's — and the target keeps its own.
    #[test]
    fn detaching_stops_the_redirect_without_disturbing_the_target() {
        let owner = event(0);
        let rb = mapped_ring(&owner);
        let follower = event(0);
        assert_eq!(apply(&follower, Some(&owner)), Ok(()));
        assert!(follower.buffer().is_some());
        assert_eq!(apply(&follower, None), Ok(()));
        assert!(follower.buffer().is_none());
        assert!(owner.buffer().is_some());
        let _ = rb;
    }

    /// The live gather must read the same facts the pure ladder decides on: an
    /// unmapped target is refused, and an event holding its own live mapping
    /// cannot be redirected.
    #[test]
    fn the_live_gather_refuses_what_the_ladder_refuses() {
        let bare = event(0);
        let follower = event(0);
        assert_eq!(apply(&follower, Some(&bare)), Err(Errno::Einval),
                   "the target owns no mapped ring");

        let owner = event(0);
        let _rb = mapped_ring(&owner);
        let mine = event(0);
        let _own = mapped_ring(&mine);
        assert_eq!(apply(&mine, Some(&owner)), Err(Errno::Einval),
                   "this event still has its own live mapping");

        let other_cpu = event(1);
        assert_eq!(apply(&other_cpu, Some(&owner)), Err(Errno::Einval));
        assert_eq!(apply(&owner, Some(&owner)), Err(Errno::Einval), "no cycles");
    }
}
