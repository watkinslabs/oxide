use super::*;

const RING_FD: i32 = 3;

#[test]
fn opcode_past_last_is_einval() {
    // Linux SYSCALL_DEFINE4(io_uring_register): `opcode >= IORING_REGISTER_LAST`.
    assert_eq!(decode(IORING_REGISTER_LAST, RING_FD, 0, 0), Err(Errno::Einval));
    assert_eq!(decode(9999, RING_FD, 0, 0), Err(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_LAST | IORING_REGISTER_USE_REGISTERED_RING, RING_FD, 0, 0),
               Err(Errno::Einval));
}

#[test]
fn use_registered_ring_is_a_flag_not_an_unknown_opcode() {
    // The old handler matched the raw opcode, so bit 31 turned every valid
    // request into EINVAL instead of a registered-ring lookup.
    let r = decode(IORING_UNREGISTER_FILES | IORING_REGISTER_USE_REGISTERED_RING, RING_FD, 0, 0)
        .expect("flag must be stripped before the opcode is matched");
    assert!(r.registered_ring);
    assert_eq!(r.op, RegisterOp::UnregisterFiles);
}

#[test]
fn registered_ring_lookup_reports_linux_errnos() {
    // No IORING_REGISTER_RING_FDS support, so every in-range slot is empty.
    assert_eq!(registered_ring_error(0), Errno::Ebadf);
    assert_eq!(registered_ring_error(IO_RINGFD_REG_MAX as i32 - 1), Errno::Ebadf);
    assert_eq!(registered_ring_error(IO_RINGFD_REG_MAX as i32), Errno::Einval);
}

#[test]
fn blind_registration_separates_ring_less_opcodes_from_the_rest() {
    // Linux io_uring_register_blind(): four opcodes are legal with fd == -1,
    // everything else is EINVAL.
    for op in [IORING_REGISTER_SEND_MSG_RING, IORING_REGISTER_QUERY,
               IORING_REGISTER_RESTRICTIONS, IORING_REGISTER_BPF_FILTER] {
        assert_eq!(decode(op, -1, 0, 1), Err(Errno::Eopnotsupp), "op {op}");
    }
    assert_eq!(decode(IORING_REGISTER_BUFFERS, -1, 0x1000, 1), Err(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_PROBE, -1, 0x1000, 1), Err(Errno::Einval));
}

#[test]
fn null_arg_is_efault_for_the_two_registration_opcodes() {
    // Linux __io_uring_register(): BUFFERS/FILES set ret = -EFAULT if !arg.
    assert_eq!(decode(IORING_REGISTER_BUFFERS, RING_FD, 0, 4), Err(Errno::Efault));
    assert_eq!(decode(IORING_REGISTER_FILES, RING_FD, 0, 4), Err(Errno::Efault));
}

#[test]
fn unregister_opcodes_demand_empty_arguments() {
    for op in [IORING_UNREGISTER_BUFFERS, IORING_UNREGISTER_FILES, IORING_UNREGISTER_EVENTFD] {
        assert!(decode(op, RING_FD, 0, 0).is_ok(), "op {op}");
        assert_eq!(decode(op, RING_FD, 0x1000, 0), Err(Errno::Einval), "op {op} arg");
        assert_eq!(decode(op, RING_FD, 0, 1), Err(Errno::Einval), "op {op} nr_args");
    }
}

#[test]
fn eventfd_registration_demands_exactly_one_argument() {
    assert_eq!(decode(IORING_REGISTER_EVENTFD, RING_FD, 0x1000, 0), Err(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_EVENTFD, RING_FD, 0x1000, 2), Err(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_EVENTFD, RING_FD, 0x1000, 1).unwrap().op,
               RegisterOp::Eventfd { arg: 0x1000, async_only: false });
    // EVENTFD_ASYNC is a distinct opcode, not an unknown one.
    assert_eq!(decode(IORING_REGISTER_EVENTFD_ASYNC, RING_FD, 0x1000, 1).unwrap().op,
               RegisterOp::Eventfd { arg: 0x1000, async_only: true });
}

#[test]
fn probe_rejects_null_arg_and_more_than_256_ops() {
    assert_eq!(decode(IORING_REGISTER_PROBE, RING_FD, 0, 4), Err(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_PROBE, RING_FD, 0x1000, PROBE_MAX_OPS + 1), Err(Errno::Einval));
    // nr_args == 0 is legal: the caller gets the header and ops_len == 0.
    assert_eq!(decode(IORING_REGISTER_PROBE, RING_FD, 0x1000, 0).unwrap().op,
               RegisterOp::Probe { arg: 0x1000, nr: 0 });
}

#[test]
fn probe_clamps_instead_of_failing() {
    // Linux io_probe(): `if (nr_args > IORING_OP_LAST) nr_args = IORING_OP_LAST;`
    assert_eq!(probe_ops(1000, 28), 28);
    assert_eq!(probe_ops(4, 28), 4);
    assert_eq!(probe_ops(0, 28), 0);
}

#[test]
fn defined_but_unimplemented_opcodes_report_eopnotsupp_not_success() {
    // Every opcode Linux defines that oxide does not execute. Returning 0 for
    // any of these tells the caller a registration happened that did not.
    for op in [IORING_REGISTER_PERSONALITY, IORING_UNREGISTER_PERSONALITY,
               IORING_REGISTER_RESTRICTIONS, IORING_REGISTER_ENABLE_RINGS,
               IORING_REGISTER_FILES2, IORING_REGISTER_FILES_UPDATE2,
               IORING_REGISTER_BUFFERS2, IORING_REGISTER_BUFFERS_UPDATE,
               IORING_REGISTER_IOWQ_AFF, IORING_UNREGISTER_IOWQ_AFF,
               IORING_REGISTER_IOWQ_MAX_WORKERS, IORING_REGISTER_RING_FDS,
               IORING_UNREGISTER_RING_FDS, IORING_REGISTER_PBUF_RING,
               IORING_UNREGISTER_PBUF_RING, IORING_REGISTER_SYNC_CANCEL,
               IORING_REGISTER_FILE_ALLOC_RANGE, IORING_REGISTER_PBUF_STATUS,
               IORING_REGISTER_NAPI, IORING_UNREGISTER_NAPI, IORING_REGISTER_CLOCK,
               IORING_REGISTER_CLONE_BUFFERS, IORING_REGISTER_SEND_MSG_RING,
               IORING_REGISTER_ZCRX_IFQ, IORING_REGISTER_RESIZE_RINGS,
               IORING_REGISTER_MEM_REGION, IORING_REGISTER_QUERY,
               IORING_REGISTER_ZCRX_CTRL, IORING_REGISTER_BPF_FILTER] {
        assert_eq!(decode(op, RING_FD, 0x1000, 1), Err(Errno::Eopnotsupp), "op {op}");
    }
}

#[test]
fn every_opcode_below_last_is_decided() {
    // No gaps: each defined opcode either decodes or names an errno.
    for op in 0..IORING_REGISTER_LAST {
        let v = decode(op, RING_FD, 0x1000, 1);
        assert!(v.is_ok() || matches!(v, Err(Errno::Eopnotsupp) | Err(Errno::Einval) | Err(Errno::Efault)),
                "op {op} -> {v:?}");
    }
}

#[test]
fn buffer_registration_reports_ebusy_before_the_count_check() {
    // Linux io_sqe_buffers_register(): `if (ctx->buf_table.nr) return -EBUSY;`
    // comes BEFORE `if (!nr_args || nr_args > IORING_MAX_REG_BUFFERS)`.
    assert_eq!(buffers_admission(true, 0), Err(Errno::Ebusy));
    assert_eq!(buffers_admission(false, 0), Err(Errno::Einval));
    assert_eq!(buffers_admission(false, IORING_MAX_REG_BUFFERS + 1), Err(Errno::Einval));
    assert_eq!(buffers_admission(false, IORING_MAX_REG_BUFFERS), Ok(()));
}

#[test]
fn file_registration_bounds_are_emfile_not_einval() {
    // Linux io_sqe_files_register(): EBUSY, then EINVAL for zero, then EMFILE
    // for IORING_MAX_FIXED_FILES and again for RLIMIT_NOFILE.
    assert_eq!(files_admission(true, 4, 1024), Err(Errno::Ebusy));
    assert_eq!(files_admission(false, 0, 1024), Err(Errno::Einval));
    assert_eq!(files_admission(false, IORING_MAX_FIXED_FILES + 1, u32::MAX), Err(Errno::Emfile));
    assert_eq!(files_admission(false, 2048, 1024), Err(Errno::Emfile));
    assert_eq!(files_admission(false, 1024, 1024), Ok(()));
}

#[test]
fn files_update_checks_nr_then_registration_then_range() {
    assert_eq!(files_update_admission(Some(8), 0, 0), Err(Errno::Einval));
    assert_eq!(files_update_admission(None, 0, 1), Err(Errno::Enxio));
    assert_eq!(files_update_admission(Some(8), 8, 1), Err(Errno::Einval));
    assert_eq!(files_update_admission(Some(8), u32::MAX, 2), Err(Errno::Eoverflow));
    assert_eq!(files_update_admission(Some(8), 4, 4), Ok(()));
}
