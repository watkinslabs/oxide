use super::*;

#[test]
fn probe_never_claims_an_opcode_dispatch_would_reject() {
    // Real opcodes the engine does not run. Reporting one as supported makes
    // a caller submit an SQE that comes back -EINVAL.
    for op in [IORING_OP_POLL_ADD, IORING_OP_POLL_REMOVE, IORING_OP_TIMEOUT,
               IORING_OP_TIMEOUT_REMOVE, IORING_OP_ASYNC_CANCEL, IORING_OP_LINK_TIMEOUT,
               IORING_OP_SPLICE, IORING_OP_URING_CMD, IORING_OP_SEND_ZC,
               IORING_OP_SENDMSG_ZC, IORING_OP_READ_MULTISHOT, IORING_OP_WAITID,
               IORING_OP_FUTEX_WAIT, IORING_OP_FUTEX_WAKE, IORING_OP_FUTEX_WAITV,
               IORING_OP_RECV_ZC, IORING_OP_EPOLL_WAIT, IORING_OP_READV_FIXED,
               IORING_OP_WRITEV_FIXED, IORING_OP_NOP128, IORING_OP_URING_CMD128] {
        assert!(!op_supported(op), "op {op}");
    }
}

#[test]
fn probe_claims_every_dispatched_opcode() {
    for op in [IORING_OP_NOP, IORING_OP_READV, IORING_OP_WRITEV, IORING_OP_FSYNC,
               IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED, IORING_OP_ACCEPT,
               IORING_OP_CONNECT, IORING_OP_OPENAT, IORING_OP_OPENAT2, IORING_OP_CLOSE,
               IORING_OP_READ, IORING_OP_WRITE, IORING_OP_SEND, IORING_OP_RECV,
               IORING_OP_SENDMSG, IORING_OP_RECVMSG, IORING_OP_SYNC_FILE_RANGE,
               IORING_OP_FALLOCATE, IORING_OP_STATX, IORING_OP_FADVISE,
               IORING_OP_MADVISE, IORING_OP_EPOLL_CTL, IORING_OP_TEE,
               IORING_OP_SHUTDOWN, IORING_OP_RENAMEAT, IORING_OP_UNLINKAT,
               IORING_OP_MKDIRAT, IORING_OP_SYMLINKAT, IORING_OP_LINKAT,
               IORING_OP_FSETXATTR, IORING_OP_SETXATTR, IORING_OP_FGETXATTR,
               IORING_OP_GETXATTR, IORING_OP_SOCKET, IORING_OP_FTRUNCATE,
               IORING_OP_BIND, IORING_OP_LISTEN, IORING_OP_PIPE,
               IORING_OP_FILES_UPDATE, IORING_OP_MSG_RING,
               IORING_OP_PROVIDE_BUFFERS, IORING_OP_REMOVE_BUFFERS,
               IORING_OP_FIXED_FD_INSTALL] {
        assert!(op_supported(op), "op {op}");
    }
}

#[test]
fn opcode_numbers_match_the_uapi_enum() {
    // The numbers are the ABI: an off-by-one anywhere in the table silently
    // runs the wrong operation for every caller past that point.
    assert_eq!(IORING_OP_NOP, 0);
    assert_eq!(IORING_OP_RECV, 27);
    assert_eq!(IORING_OP_MSG_RING, 40);
    assert_eq!(IORING_OP_SOCKET, 45);
    assert_eq!(IORING_OP_FIXED_FD_INSTALL, 54);
    assert_eq!(IORING_OP_PIPE, 62);
    assert_eq!(IORING_OP_URING_CMD128, 64);
    assert_eq!(OP_LAST, 65);
    assert!(!op_supported(OP_LAST));
}

#[test]
fn sqe_flag_mask_covers_every_defined_bit_and_nothing_else() {
    assert_eq!(SQE_VALID_FLAGS, (1u8 << 7) - 1);
    assert_eq!(SQE_LINK_FLAGS, IOSQE_IO_LINK | IOSQE_IO_HARDLINK);
    assert_eq!(IOSQE_CQE_SKIP_SUCCESS, 1 << 6);
}

#[test]
fn buffer_select_is_offered_only_by_the_receiving_opcodes() {
    for op in [IORING_OP_READ, IORING_OP_READV, IORING_OP_RECV, IORING_OP_RECVMSG] {
        assert!(op_buffer_select(op), "op {op}");
    }
    // Selecting a buffer for a write would hand the kernel a buffer to send
    // that the caller never filled.
    for op in [IORING_OP_WRITE, IORING_OP_SEND, IORING_OP_NOP, IORING_OP_OPENAT] {
        assert!(!op_buffer_select(op), "op {op}");
    }
}
