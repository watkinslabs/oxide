use super::*;

fn sqe_of(op: u8) -> Sqe { Sqe { opcode: op, ..Sqe::default() } }

/// The rung that keeps a parking operation off the submitting task.
///
/// A futex wait, a vectored futex wait, a child wait and an epoll harvest all
/// park until something else happens. Running one inline would park the
/// SUBMITTER, so a submission holding both a wait and the wake that satisfies
/// it could never reach the wake — the ring would deadlock against itself with
/// no error to show for it. Nothing else in the engine states this.
#[test]
fn every_operation_that_parks_is_deferred_before_it_is_ever_attempted() {
    for op in [IORING_OP_FUTEX_WAIT, IORING_OP_FUTEX_WAITV,
               IORING_OP_WAITID, IORING_OP_EPOLL_WAIT] {
        assert!(always_async(op), "op {op} would park the submitting task");
    }
}

/// A wake never waits, so it must NOT be forced onto a worker: that would put
/// the cheapest operation in the family behind a queue.
#[test]
fn a_wake_is_not_deferred_because_it_never_waits() {
    assert!(!always_async(IORING_OP_FUTEX_WAKE));
}

/// A splice moves an unbounded number of bytes between two descriptions,
/// either of which may block.
#[test]
fn both_halves_of_the_splice_family_are_deferred() {
    assert!(always_async(IORING_OP_SPLICE));
    assert!(always_async(IORING_OP_TEE));
}

/// The entries that have nothing to do but wait, and the command the driver
/// rather than the submission completes.
#[test]
fn the_armed_entries_and_driver_commands_stay_deferred() {
    for op in [IORING_OP_TIMEOUT, IORING_OP_LINK_TIMEOUT, IORING_OP_POLL_ADD,
               IORING_OP_URING_CMD, IORING_OP_URING_CMD128] {
        assert!(always_async(op), "op {op}");
    }
}

/// An ordinary transfer must still be attempted inline: forcing every read
/// onto a worker would cost a hand-off for the case io_uring exists to make
/// cheap, and the description that would have blocked is what defers it.
#[test]
fn an_ordinary_transfer_is_not_forced_onto_a_worker() {
    for op in [IORING_OP_READ, IORING_OP_WRITE, IORING_OP_READV, IORING_OP_WRITEV,
               IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED,
               IORING_OP_READV_FIXED, IORING_OP_WRITEV_FIXED,
               IORING_OP_NOP, IORING_OP_OPENAT, IORING_OP_CLOSE,
               IORING_OP_EPOLL_CTL] {
        assert!(!always_async(op), "op {op}");
    }
}

/// The submitter's own request for a worker is honoured for an opcode that
/// would otherwise have run inline.
#[test]
fn the_submitter_can_force_a_worker_for_an_inline_opcode() {
    let mut s = sqe_of(IORING_OP_READ);
    assert!(!defers(&s));
    s.flags = IOSQE_ASYNC;
    assert!(defers(&s));
}

/// And an opcode that can only ever be deferred defers with no flag at all.
#[test]
fn a_parking_opcode_defers_without_the_submitter_asking() {
    assert!(defers(&sqe_of(IORING_OP_FUTEX_WAIT)));
    assert!(defers(&sqe_of(IORING_OP_SPLICE)));
}
