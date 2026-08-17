use super::*;

/// Every opcode `dispatch::router::run` (or the submission engine, for the
/// entries it arms rather than runs) has a handler for.
///
/// Maintained beside the router on purpose: it is the INDEPENDENT statement of
/// what the engine can execute, and `op_supported` is what the probe tells
/// userspace. A runtime asks the probe once at startup and trusts the answer
/// for the life of the process, so a claim the engine cannot honour does not
/// produce a clean `EINVAL` at feature-detection time — it produces a
/// submission whose completion never arrives.
const DISPATCHED: &[u8] = &[
    IORING_OP_NOP, IORING_OP_NOP128,

    IORING_OP_READ, IORING_OP_WRITE, IORING_OP_READV, IORING_OP_WRITEV,
    IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED,
    IORING_OP_READV_FIXED, IORING_OP_WRITEV_FIXED,
    IORING_OP_FSYNC, IORING_OP_SYNC_FILE_RANGE, IORING_OP_FALLOCATE,
    IORING_OP_FTRUNCATE, IORING_OP_FADVISE, IORING_OP_MADVISE,

    IORING_OP_OPENAT, IORING_OP_OPENAT2, IORING_OP_CLOSE, IORING_OP_STATX,
    IORING_OP_RENAMEAT, IORING_OP_UNLINKAT, IORING_OP_MKDIRAT,
    IORING_OP_SYMLINKAT, IORING_OP_LINKAT,
    IORING_OP_SETXATTR, IORING_OP_FSETXATTR, IORING_OP_GETXATTR,
    IORING_OP_FGETXATTR,
    IORING_OP_SPLICE, IORING_OP_TEE, IORING_OP_PIPE,
    IORING_OP_EPOLL_CTL, IORING_OP_EPOLL_WAIT,

    IORING_OP_SEND, IORING_OP_RECV, IORING_OP_SENDMSG, IORING_OP_RECVMSG,
    IORING_OP_SEND_ZC, IORING_OP_SENDMSG_ZC, IORING_OP_RECV_ZC,
    IORING_OP_ACCEPT, IORING_OP_CONNECT, IORING_OP_BIND, IORING_OP_LISTEN,
    IORING_OP_SHUTDOWN, IORING_OP_SOCKET,

    IORING_OP_FILES_UPDATE, IORING_OP_MSG_RING,
    IORING_OP_PROVIDE_BUFFERS, IORING_OP_REMOVE_BUFFERS,
    IORING_OP_FIXED_FD_INSTALL,

    IORING_OP_ASYNC_CANCEL, IORING_OP_TIMEOUT_REMOVE, IORING_OP_POLL_REMOVE,
    IORING_OP_TIMEOUT, IORING_OP_LINK_TIMEOUT, IORING_OP_POLL_ADD,

    IORING_OP_URING_CMD, IORING_OP_URING_CMD128,

    IORING_OP_WAITID,
    IORING_OP_FUTEX_WAIT, IORING_OP_FUTEX_WAKE, IORING_OP_FUTEX_WAITV,
];

/// The contract the probe carries, in the direction that hangs a caller.
#[test]
fn the_probe_claims_nothing_the_engine_cannot_run() {
    for op in 0u8..=255 {
        if op_supported(op) {
            assert!(DISPATCHED.contains(&op), "probe claims op {op}, no handler runs it");
        }
    }
}

/// And in the direction that hides working functionality: a runnable opcode
/// the probe denies makes a caller fall back to a slower path forever.
#[test]
fn the_probe_claims_everything_the_engine_can_run() {
    for op in DISPATCHED {
        assert!(op_supported(*op), "op {op} is dispatched but the probe denies it");
    }
}

/// The advertised set is enumerated, never a range check: an opcode number
/// defined by a later kernel must not be advertised the moment its constant
/// lands, before anything runs it.
#[test]
fn nothing_at_or_past_the_last_opcode_is_claimed() {
    for op in OP_LAST..=255 { assert!(!op_supported(op), "op {op}"); }
}

/// Every defined opcode but the one recorded as unimplemented below.
#[test]
fn every_defined_opcode_has_a_family() {
    for op in 0..OP_LAST {
        if op == IORING_OP_READ_MULTISHOT { continue; }
        assert!(op_family(op).is_some(), "op {op} has no handler family");
    }
    assert_eq!(DISPATCHED.len(), OP_LAST as usize - 1);
}

/// A duplicate in the table would make the count above agree with the opcode
/// range while an opcode was actually missing — the same shape as a
/// set-based check that cannot see duplicates (CLAUDE.md).
#[test]
fn the_dispatched_table_names_each_opcode_once() {
    for op in 0..OP_LAST {
        let want = if op == IORING_OP_READ_MULTISHOT { 0 } else { 1 };
        let n = DISPATCHED.iter().filter(|&&o| o == op).count();
        assert_eq!(n, want, "op {op} appears {n} times");
    }
}

#[test]
fn the_families_group_the_opcodes_the_reference_groups() {
    use OpFamily::*;
    assert_eq!(op_family(IORING_OP_SPLICE), Some(Fs));
    assert_eq!(op_family(IORING_OP_TEE), Some(Fs));
    assert_eq!(op_family(IORING_OP_EPOLL_WAIT), Some(Fs));
    assert_eq!(op_family(IORING_OP_READV_FIXED), Some(Rw));
    assert_eq!(op_family(IORING_OP_WRITEV_FIXED), Some(Rw));
    assert_eq!(op_family(IORING_OP_WAITID), Some(Proc));
    assert_eq!(op_family(IORING_OP_FUTEX_WAIT), Some(Proc));
    assert_eq!(op_family(IORING_OP_FUTEX_WAKE), Some(Proc));
    assert_eq!(op_family(IORING_OP_FUTEX_WAITV), Some(Proc));
    assert_eq!(op_family(IORING_OP_URING_CMD), Some(Cmd));
    assert_eq!(op_family(IORING_OP_TIMEOUT), Some(Armed));
    assert_eq!(op_family(OP_LAST), None);
}

/// The 128-byte nop IS dispatched, and the probe must say so: it is the
/// operation a caller uses to find out whether a ring carries 128-byte
/// entries at all, so hiding it would hide the answer.
#[test]
fn probe_claims_the_128_byte_nop() {
    assert!(op_supported(IORING_OP_NOP128));
    assert!(crate::io_uring_abi::sqe_slot::op_is_128(IORING_OP_NOP128));
}

/// Both zero-copy sends are dispatched: a caller that was told otherwise
/// would fall back to a send with no notification and keep its payload memory
/// live by hand.
#[test]
fn probe_claims_the_zero_copy_sends() {
    assert!(op_supported(IORING_OP_SEND_ZC));
    assert!(op_supported(IORING_OP_SENDMSG_ZC));
}

#[test]
fn probe_claims_zero_copy_receive() {
    assert!(op_supported(IORING_OP_RECV_ZC));
}

#[test]
fn probe_claims_the_asynchronous_opcodes_the_engine_arms() {
    // These never complete inside the submission that issued them: the engine
    // arms them on a clock, on a description or on the in-flight table. A
    // probe that hid them would tell a caller with an async engine underneath
    // it that there is none.
    for op in [IORING_OP_POLL_ADD, IORING_OP_POLL_REMOVE, IORING_OP_TIMEOUT,
               IORING_OP_TIMEOUT_REMOVE, IORING_OP_ASYNC_CANCEL, IORING_OP_LINK_TIMEOUT] {
        assert!(op_supported(op), "op {op}");
    }
}

#[test]
fn probe_claims_external_driver_commands() {
    assert!(op_supported(IORING_OP_URING_CMD));
    assert!(op_supported(IORING_OP_URING_CMD128));
}

#[test]
fn opcode_numbers_match_the_uapi_enum() {
    // The numbers are the ABI: an off-by-one anywhere in the table silently
    // runs the wrong operation for every caller past that point.
    assert_eq!(IORING_OP_NOP, 0);
    assert_eq!(IORING_OP_RECV, 27);
    assert_eq!(IORING_OP_SPLICE, 30);
    assert_eq!(IORING_OP_MSG_RING, 40);
    assert_eq!(IORING_OP_SOCKET, 45);
    assert_eq!(IORING_OP_WAITID, 50);
    assert_eq!(IORING_OP_FUTEX_WAIT, 51);
    assert_eq!(IORING_OP_FUTEX_WAKE, 52);
    assert_eq!(IORING_OP_FUTEX_WAITV, 53);
    assert_eq!(IORING_OP_FIXED_FD_INSTALL, 54);
    assert_eq!(IORING_OP_EPOLL_WAIT, 59);
    assert_eq!(IORING_OP_READV_FIXED, 60);
    assert_eq!(IORING_OP_WRITEV_FIXED, 61);
    assert_eq!(IORING_OP_PIPE, 62);
    assert_eq!(IORING_OP_URING_CMD128, 64);
    assert_eq!(OP_LAST, 65);
    assert!(!op_supported(OP_LAST));
}

/// The multishot read is the one defined opcode this engine does not run, and
/// the probe must keep saying so. Advertising it would let a caller build a
/// subscription that never delivers.
#[test]
fn the_one_unimplemented_opcode_is_not_claimed() {
    assert!(!op_supported(IORING_OP_READ_MULTISHOT));
    assert!(!DISPATCHED.contains(&IORING_OP_READ_MULTISHOT));
}

#[test]
fn sqe_flag_mask_covers_every_defined_bit_and_nothing_else() {
    assert_eq!(SQE_VALID_FLAGS, (1u8 << 7) - 1);
    assert_eq!(SQE_LINK_FLAGS, IOSQE_IO_LINK | IOSQE_IO_HARDLINK);
    assert_eq!(IOSQE_CQE_SKIP_SUCCESS, 1 << 6);
}

#[test]
fn buffer_select_is_offered_only_by_the_transfer_opcodes_that_take_a_group() {
    // A receive fills a buffer drawn from the group; a send DRAINS one the
    // caller already filled and published there, and hands it back through the
    // completion the same way. Both are the group's purpose.
    for op in [IORING_OP_READ, IORING_OP_READV, IORING_OP_RECV, IORING_OP_RECVMSG,
               IORING_OP_SEND] {
        assert!(op_buffer_select(op), "op {op}");
    }
    // A positional write names its own buffer: there is no group side to it,
    // and an operation that creates or configures something has no buffer at
    // all. A vectored-fixed transfer names a REGISTRATION in the same field
    // the group would be named in, so it cannot offer selection either.
    for op in [IORING_OP_WRITE, IORING_OP_WRITEV, IORING_OP_NOP, IORING_OP_OPENAT,
               IORING_OP_READV_FIXED, IORING_OP_WRITEV_FIXED] {
        assert!(!op_buffer_select(op), "op {op}");
    }
}
