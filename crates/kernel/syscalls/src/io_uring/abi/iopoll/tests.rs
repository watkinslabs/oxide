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

// --- submit-then-poll ---------------------------------------------------

// The transfer family is what a poll can complete, and it is the ONLY thing a
// polled ring hands to the backend without a result. An entry that finishes
// inside submission has already posted its completion; putting one on this
// path would leave a request nothing ever reaps.
#[test]
fn only_transfers_on_a_polled_ring_take_the_submit_then_poll_path() {
    for op in [IORING_OP_READ, IORING_OP_WRITE, IORING_OP_READV, IORING_OP_WRITEV,
               IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED] {
        assert!(defers_to_backend(true, op, 0), "op {op} is a transfer");
        assert!(!defers_to_backend(false, op, 0), "an ordinary ring polls for nothing");
    }
    for op in [IORING_OP_NOP, IORING_OP_MSG_RING, IORING_OP_PROVIDE_BUFFERS,
               IORING_OP_REMOVE_BUFFERS, IORING_OP_FILES_UPDATE, IORING_OP_URING_CMD] {
        assert!(!defers_to_backend(true, op, 0), "op {op} finishes inside submission");
    }
}

// Every entry that defers to the backend is one the polled ring admits at all;
// the reverse does not hold. A deferral of an opcode the ring refuses would be
// a request submitted to a backend for an entry that never got past admission.
#[test]
fn everything_that_defers_is_admitted_by_the_polled_ring() {
    for op in 0u8..=63 {
        if defers_to_backend(true, op, 0) {
            assert!(opcode_pollable(op), "op {op} defers but is not admitted");
            assert_eq!(admit_opcode(true, op), Ok(()));
        }
    }
}

// The description's position cannot be shared between two outstanding
// transfers: both would read the same value and both would advance it, and
// there is no moment at which either could take it exclusively. Such an entry
// keeps the ordinary path, where the position is read and advanced inside one
// operation.
#[test]
fn a_transfer_at_the_descriptions_own_position_does_not_defer() {
    for op in [IORING_OP_READ, IORING_OP_WRITE, IORING_OP_READV, IORING_OP_WRITEV,
               IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED] {
        assert!(!defers_to_backend(true, op, CUR_POS), "op {op} at -1 keeps the ordinary path");
        assert!(defers_to_backend(true, op, CUR_POS - 1), "any other offset still defers");
        assert!(defers_to_backend(true, op, 0));
    }
}

// A refused direct submission has exactly two well-formed reasons, and they
// mean different things to a caller: a request that was not whole blocks stays
// wrong however often it is retried, while one that started past the end of the
// device is a fact about the device.
#[test]
fn a_refused_direct_submission_reports_its_own_reason() {
    assert_eq!(submit_errno(vfs::VfsError::Einval), Errno::Einval);
    assert_eq!(submit_errno(vfs::VfsError::Enospc), Errno::Enospc);
    assert_eq!(submit_errno(vfs::VfsError::Eio), Errno::Eio);
    assert_eq!(submit_errno(vfs::VfsError::Eopnotsupp), Errno::Eopnotsupp);
    // Anything a backend invents that names no better answer is an I/O error;
    // it must NOT surface as success or as a refusal the caller would retry.
    assert_eq!(submit_errno(vfs::VfsError::Eisdir), Errno::Eio);
}

// The direction decides which end of the transfer holds the caller's bytes at
// submission time, so a mislabelled opcode moves the wrong bytes.
#[test]
fn the_write_half_of_the_transfer_family_is_named_exactly() {
    for op in [IORING_OP_WRITE, IORING_OP_WRITEV, IORING_OP_WRITE_FIXED] {
        assert!(is_write(op));
    }
    for op in [IORING_OP_READ, IORING_OP_READV, IORING_OP_READ_FIXED, IORING_OP_NOP] {
        assert!(!is_write(op));
    }
}

// --- hybrid poll --------------------------------------------------------

// A ring that has never timed a transfer has nothing to sleep against, and
// sleeping on a guess would delay the very completions the mode exists to
// catch early.
#[test]
fn a_ring_with_no_estimate_yet_does_not_sleep() {
    assert_eq!(hybrid_sleep_ns(NO_ESTIMATE, false), 0);
}

// The reference's fraction: half the estimate.
#[test]
fn the_sleep_is_half_the_rings_estimate() {
    assert_eq!(hybrid_sleep_ns(1_000, false), 500);
    assert_eq!(hybrid_sleep_ns(1, false), 0, "an estimate below the resolution sleeps none");
    assert_eq!(hybrid_sleep_ns(0, false), 0);
}

// The sleep skips the front of ONE transfer's service time. Paying it again on
// every pass would make a device slower the more often it was polled, which is
// the opposite of what the caller asked for.
#[test]
fn a_request_that_already_slept_never_sleeps_again() {
    assert_eq!(hybrid_sleep_ns(1_000, true), 0);
    assert_eq!(hybrid_sleep_ns(NO_ESTIMATE, true), 0);
}

// The MINIMUM, not an average: with backends of different speeds, sleeping for
// longer than the fastest takes loses completions that were already ready.
#[test]
fn the_estimate_is_the_smallest_service_time_seen() {
    assert_eq!(observe_runtime(NO_ESTIMATE, 900), 900, "the first observation wins outright");
    assert_eq!(observe_runtime(900, 400), 400);
    assert_eq!(observe_runtime(400, 900), 400, "a slower backend does not raise it");
    assert_eq!(observe_runtime(400, 400), 400);
}

// An estimate that counted its own sleep would grow by half of itself every
// pass until the mode was a pure sleep with no poll left in it.
#[test]
fn the_observed_runtime_excludes_the_time_spent_asleep() {
    assert_eq!(hybrid_runtime(1_000, 0, 400), 600);
    assert_eq!(hybrid_runtime(1_000, 200, 0), 800);
    // Feeding the estimate back through a sleep must not ratchet it upwards.
    let mut est = 1_000u64;
    for _ in 0..8 {
        let slept = hybrid_sleep_ns(est, false);
        est = observe_runtime(est, hybrid_runtime(slept + 1_000, 0, slept));
    }
    assert_eq!(est, 1_000, "the estimate is stable under its own sleep");
}

// A clock that appears to go backwards must yield zero, not an enormous
// estimate that would then be halved into an enormous sleep.
#[test]
fn a_backwards_clock_observes_no_service_time() {
    assert_eq!(hybrid_runtime(100, 900, 0), 0);
    assert_eq!(hybrid_runtime(1_000, 0, 4_000), 0);
}

// A write reports what the device took; a read reports what reached the
// caller's buffer. Reporting the device's count for a read would tell a caller
// its buffer holds data that is not in it.
#[test]
fn a_completed_transfer_reports_the_count_its_own_direction_means() {
    assert_eq!(completed_res(true, 4096, 4096), 4096);
    assert_eq!(completed_res(false, 4096, 4096), 4096);
    assert_eq!(completed_res(false, 4096, 512), 512, "a short copy reports what landed");
    assert_eq!(completed_res(true, 512, 0), 512, "a write's payload already left the caller");
}

// Zero means end-of-file. A caller that read a failed copy as EOF would stop
// reading a file it had barely started, so a read that delivered bytes and
// landed none is EFAULT.
#[test]
fn a_read_that_landed_nothing_is_efault_not_end_of_file() {
    assert_eq!(completed_res(false, 4096, 0), -(Errno::Efault.as_i32() as i64));
    assert_eq!(completed_res(false, 0, 0), 0, "a transfer that delivered nothing IS end-of-file");
}
