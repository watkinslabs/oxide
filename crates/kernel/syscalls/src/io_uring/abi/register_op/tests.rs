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
    // With no ring, only the forms that need none are legal.
    assert_eq!(decode(IORING_REGISTER_SEND_MSG_RING, -1, 0x1000, 1).unwrap().op,
               RegisterOp::SendMsgRing { arg: 0x1000 });
    assert_eq!(decode(IORING_REGISTER_QUERY, -1, 0x1000, 0).unwrap().op,
               RegisterOp::Query { arg: 0x1000, nr: 0 });
    // A ring-less form still applies its own argument rules.
    assert_eq!(decode(IORING_REGISTER_SEND_MSG_RING, -1, 0, 1), Err(Errno::Einval));
    // Recognised but needing a mechanism this kernel lacks.
    for op in [IORING_REGISTER_RESTRICTIONS, IORING_REGISTER_BPF_FILTER] {
        assert_eq!(decode(op, -1, 0x1000, 1), Err(Errno::Eopnotsupp), "op {op}");
    }
    // Everything else without a ring is an argument error, not a missing
    // feature: the opcode exists, the caller just did not name a ring.
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
fn opcodes_needing_an_absent_mechanism_report_eopnotsupp_not_success() {
    // Each of these needs a whole mechanism this kernel does not have — a
    // worker pool, a per-task registered-ring array, multi-frame ring
    // regions, a zero-copy receive queue, busy-poll, or a program loader.
    // Returning 0 for any of them would tell the caller a registration
    // happened that did not.
    for op in [IORING_REGISTER_RING_FDS,
               IORING_UNREGISTER_RING_FDS, IORING_REGISTER_NAPI,
               IORING_UNREGISTER_NAPI, IORING_REGISTER_ZCRX_IFQ,
               IORING_REGISTER_RESIZE_RINGS, IORING_REGISTER_MEM_REGION,
               IORING_REGISTER_ZCRX_CTRL, IORING_REGISTER_BPF_FILTER] {
        assert_eq!(decode(op, RING_FD, 0x1000, 1), Err(Errno::Eopnotsupp), "op {op}");
    }
}

#[test]
fn the_worker_registrations_decode_to_their_own_requests() {
    assert_eq!(decode(IORING_REGISTER_IOWQ_MAX_WORKERS, RING_FD, 0x1000, 2).unwrap().op,
               RegisterOp::IowqMaxWorkers { arg: 0x1000 });
    // One count per work class, and there are two classes: any other count
    // means the caller and the kernel disagree about the argument's shape.
    for nr in [0u32, 1, 3] {
        assert_eq!(decode(IORING_REGISTER_IOWQ_MAX_WORKERS, RING_FD, 0x1000, nr),
                   Err(Errno::Einval), "nr {nr}");
    }
    assert_eq!(decode(IORING_REGISTER_IOWQ_MAX_WORKERS, RING_FD, 0, 2), Err(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_IOWQ_AFF, RING_FD, 0x1000, 8).unwrap().op,
               RegisterOp::IowqAff { arg: 0x1000, len: 8 });
    assert_eq!(decode(IORING_REGISTER_IOWQ_AFF, RING_FD, 0x1000, 0), Err(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_IOWQ_AFF, RING_FD, 0, 8), Err(Errno::Einval));
    // Unregistering names no mask at all; the two forms share one request.
    assert_eq!(decode(IORING_UNREGISTER_IOWQ_AFF, RING_FD, 0, 0).unwrap().op,
               RegisterOp::IowqAff { arg: 0, len: 0 });
    assert_eq!(decode(IORING_UNREGISTER_IOWQ_AFF, RING_FD, 0x1000, 0), Err(Errno::Einval));
}

#[test]
fn the_ring_state_opcodes_decode_to_their_own_requests() {
    let ok = |op, arg, nr| decode(op, RING_FD, arg, nr).unwrap().op;
    assert_eq!(ok(IORING_REGISTER_PERSONALITY, 0, 0), RegisterOp::Personality);
    // The personality id travels in nr_args, so only arg must be empty.
    assert_eq!(ok(IORING_UNREGISTER_PERSONALITY, 0, 7),
               RegisterOp::UnregisterPersonality { id: 7 });
    assert_eq!(decode(IORING_UNREGISTER_PERSONALITY, RING_FD, 0x1000, 7), Err(Errno::Einval));
    assert_eq!(ok(IORING_REGISTER_ENABLE_RINGS, 0, 0), RegisterOp::EnableRings);
    assert_eq!(decode(IORING_REGISTER_ENABLE_RINGS, RING_FD, 0, 1), Err(Errno::Einval));
    assert_eq!(ok(IORING_REGISTER_RESTRICTIONS, 0x1000, 3),
               RegisterOp::Restrictions { arg: 0x1000, nr: 3 });
    assert_eq!(ok(IORING_REGISTER_CLOCK, 0x1000, 0), RegisterOp::Clock { arg: 0x1000 });
    assert_eq!(decode(IORING_REGISTER_CLOCK, RING_FD, 0x1000, 1), Err(Errno::Einval));
    assert_eq!(ok(IORING_REGISTER_FILE_ALLOC_RANGE, 0x1000, 0),
               RegisterOp::FileAllocRange { arg: 0x1000 });
}

#[test]
fn tagged_resource_opcodes_carry_their_resource_kind() {
    let ok = |op| decode(op, RING_FD, 0x1000, 1).unwrap().op;
    assert_eq!(ok(IORING_REGISTER_FILES2), RegisterOp::Rsrc { arg: 0x1000, nr: 1, buffers: false });
    assert_eq!(ok(IORING_REGISTER_BUFFERS2), RegisterOp::Rsrc { arg: 0x1000, nr: 1, buffers: true });
    assert_eq!(ok(IORING_REGISTER_FILES_UPDATE2),
               RegisterOp::RsrcUpdate { arg: 0x1000, nr: 1, buffers: false });
    assert_eq!(ok(IORING_REGISTER_BUFFERS_UPDATE),
               RegisterOp::RsrcUpdate { arg: 0x1000, nr: 1, buffers: true });
}

#[test]
fn the_single_record_opcodes_demand_exactly_one_record() {
    for op in [IORING_REGISTER_PBUF_RING, IORING_UNREGISTER_PBUF_RING,
               IORING_REGISTER_PBUF_STATUS, IORING_REGISTER_SYNC_CANCEL,
               IORING_REGISTER_CLONE_BUFFERS] {
        assert!(decode(op, RING_FD, 0x1000, 1).is_ok(), "op {op}");
        assert_eq!(decode(op, RING_FD, 0, 1), Err(Errno::Einval), "op {op} null arg");
        assert_eq!(decode(op, RING_FD, 0x1000, 2), Err(Errno::Einval), "op {op} nr_args");
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
