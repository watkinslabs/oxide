use super::*;

fn tgt(ring_iopoll: bool, direct: bool, file_pollable: bool, hipri: bool) -> RwTarget {
    RwTarget { ring_iopoll, direct, file_pollable, hipri }
}

// --- opcode admission ---------------------------------------------------

#[test]
fn an_ordinary_ring_admits_every_opcode_the_polled_one_refuses() {
    // The flag must change nothing for a ring that does not carry it.
    for op in [IORING_OP_ACCEPT, IORING_OP_FSYNC, IORING_OP_TIMEOUT, IORING_OP_POLL_ADD,
               IORING_OP_READ, IORING_OP_NOP] {
        assert_eq!(admit_opcode(false, op), Ok(()), "op {op}");
    }
}

#[test]
fn a_polled_ring_admits_the_transfer_opcodes() {
    for op in [IORING_OP_READ, IORING_OP_WRITE, IORING_OP_READV, IORING_OP_WRITEV,
               IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED] {
        assert_eq!(admit_opcode(true, op), Ok(()), "op {op}");
        assert!(opcode_pollable(op), "op {op}");
    }
}

#[test]
fn a_polled_ring_admits_the_entries_that_finish_inside_submission() {
    // These need no poll at all: they complete before the submission that
    // issued them returns, so a polled ring can carry them safely.
    for op in [IORING_OP_NOP, IORING_OP_FILES_UPDATE, IORING_OP_PROVIDE_BUFFERS,
               IORING_OP_REMOVE_BUFFERS, IORING_OP_MSG_RING, IORING_OP_URING_CMD] {
        assert_eq!(admit_opcode(true, op), Ok(()), "op {op}");
    }
}

#[test]
fn a_polled_ring_refuses_every_opcode_whose_completion_no_poll_would_find() {
    // The failure mode this prevents is a HANG, not a wrong result: nothing
    // on a polled ring ever looks for these completions, so an accepted
    // entry would sit outstanding forever.
    for op in [IORING_OP_ACCEPT, IORING_OP_CONNECT, IORING_OP_FSYNC, IORING_OP_TIMEOUT,
               IORING_OP_POLL_ADD, IORING_OP_SEND, IORING_OP_RECV, IORING_OP_OPENAT,
               IORING_OP_CLOSE, IORING_OP_ASYNC_CANCEL, IORING_OP_LINK_TIMEOUT] {
        assert_eq!(admit_opcode(true, op), Err(Errno::Einval),
            "op {op} must be an argument error on a polled ring, not a missing feature");
        assert!(!opcode_pollable(op), "op {op}");
    }
}

// --- read/write file admission ------------------------------------------

#[test]
fn a_polled_transfer_needs_a_direct_transfer_on_a_pollable_backend() {
    assert_eq!(admit_rw(&tgt(true, true, true, false)), Ok(()));
    // Both halves are load-bearing, and each alone is not enough.
    assert_eq!(admit_rw(&tgt(true, false, true, false)), Err(Errno::Eopnotsupp),
        "a cached transfer has no outstanding device I/O a poll could find");
    assert_eq!(admit_rw(&tgt(true, true, false, false)), Err(Errno::Eopnotsupp),
        "a backend with no poll would never report this completion");
    assert_eq!(admit_rw(&tgt(true, false, false, false)), Err(Errno::Eopnotsupp));
}

#[test]
fn a_polled_transfer_refuses_with_eopnotsupp_not_einval() {
    // The distinction is what a caller acts on: EINVAL means the request is
    // malformed and retrying with another file is pointless; EOPNOTSUPP means
    // this FILE cannot serve it and another one might.
    let e = admit_rw(&tgt(true, false, true, false));
    assert_eq!(e, Err(Errno::Eopnotsupp));
    assert_ne!(e, Err(Errno::Einval));
}

#[test]
fn high_priority_is_refused_on_a_ring_that_does_not_poll() {
    // Silently dropping it would leave the caller believing it got a latency
    // guarantee no ring here would honour.
    assert_eq!(admit_rw(&tgt(false, true, true, true)), Err(Errno::Einval));
    assert_eq!(admit_rw(&tgt(false, false, false, true)), Err(Errno::Einval));
    // Without the request, an ordinary ring admits anything.
    assert_eq!(admit_rw(&tgt(false, false, false, false)), Ok(()));
    assert_eq!(admit_rw(&tgt(false, true, true, false)), Ok(()));
}

#[test]
fn high_priority_on_a_polled_ring_is_the_rings_business_not_the_entrys() {
    // A polled ring sets it for every transfer, so a caller that asked for it
    // is asking for what it already gets and must not be refused.
    assert_eq!(admit_rw(&tgt(true, true, true, true)), Ok(()));
    assert!(hipri_for(true));
    assert!(!hipri_for(false));
}

// --- the wait loop ------------------------------------------------------

#[test]
fn a_lost_completion_is_reported_before_anything_is_polled() {
    // Reported once, and ahead of the events already queued: a caller told
    // "here are your events" would never learn one was destroyed.
    assert_eq!(precheck(true, 0), Some(Err(Errno::Ebadr)));
    assert_eq!(precheck(true, 5), Some(Err(Errno::Ebadr)));
}

#[test]
fn completions_already_reapable_end_the_call_without_polling() {
    assert_eq!(precheck(false, 1), Some(Ok(())));
    assert_eq!(precheck(false, 0), None, "nothing reapable: the loop must run");
}

#[test]
fn nothing_outstanding_stops_the_loop_rather_than_spinning_forever() {
    // The hang this prevents: a request handed to a worker has not reached a
    // backend yet, so no poll can find it. Success with fewer completions
    // than asked for is the contract; the caller calls again.
    assert_eq!(before_poll(0, 4, false), Step::Stop);
    assert_eq!(before_poll(0, 0, false), Step::Stop);
}

#[test]
fn outstanding_work_drives_the_backend_poll() {
    assert_eq!(before_poll(1, 1, false), Step::Poll { oneshot: false });
    assert_eq!(before_poll(3, 2, false), Step::Poll { oneshot: false });
}

#[test]
fn a_zero_count_wait_takes_one_look_rather_than_spinning() {
    assert!(oneshot(0, false));
    assert_eq!(before_poll(2, 0, false), Step::Poll { oneshot: true });
}

#[test]
fn work_spanning_more_than_one_backend_never_spins_inside_one_of_them() {
    // Spinning in one backend holds up every completion waiting on the
    // others — the starvation the reference's `poll_multi_queue` prevents.
    assert!(oneshot(4, true));
    assert_eq!(before_poll(2, 4, true), Step::Poll { oneshot: true });
}

#[test]
fn a_signal_beats_both_the_count_and_the_yield() {
    // A spinning caller must not sit on a processor through a pending signal,
    // so the signal is checked first, even when the count is already met.
    assert_eq!(after_poll(0, 4, true, false), Step::Interrupted);
    assert_eq!(after_poll(9, 4, true, false), Step::Interrupted);
    assert_eq!(after_poll(9, 4, true, true), Step::Interrupted);
}

#[test]
fn needing_the_cpu_elsewhere_stops_the_loop_short_of_the_count() {
    assert_eq!(after_poll(1, 4, false, true), Step::Stop);
    assert_eq!(after_poll(0, 4, false, true), Step::Stop);
}

#[test]
fn the_loop_runs_until_the_callers_count_is_reached() {
    assert_eq!(after_poll(0, 4, false, false), Step::Poll { oneshot: false });
    assert_eq!(after_poll(3, 4, false, false), Step::Poll { oneshot: false });
    assert_eq!(after_poll(4, 4, false, false), Step::Stop);
    assert_eq!(after_poll(7, 4, false, false), Step::Stop, "more than asked for still stops");
}

#[test]
fn a_zero_count_wait_stops_after_its_single_look() {
    // min_events == 0 is satisfied by any count including zero, so the pass
    // that found nothing must still end the call.
    assert_eq!(after_poll(0, 0, false, false), Step::Stop);
}
