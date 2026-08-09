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
fn ring_fds_register_ladder_bounds_nr_args() {
    // Linux: `if (!nr_args || nr_args > IO_RINGFD_REG_MAX) return -EINVAL;`
    assert_eq!(decode(IORING_REGISTER_RING_FDS, RING_FD, 0x1000, 0), Err(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_RING_FDS, RING_FD, 0x1000, IO_RINGFD_REG_MAX + 1),
               Err(Errno::Einval));
    assert_eq!(decode(IORING_REGISTER_RING_FDS, RING_FD, 0x1000, IO_RINGFD_REG_MAX).unwrap().op,
               RegisterOp::RingFds { arg: 0x1000, nr: IO_RINGFD_REG_MAX });
    assert_eq!(decode(IORING_REGISTER_RING_FDS, RING_FD, 0x1000, 1).unwrap().op,
               RegisterOp::RingFds { arg: 0x1000, nr: 1 });
}

#[test]
fn ring_fds_unregister_ladder_bounds_nr_args() {
    assert_eq!(decode(IORING_UNREGISTER_RING_FDS, RING_FD, 0x1000, 0), Err(Errno::Einval));
    assert_eq!(decode(IORING_UNREGISTER_RING_FDS, RING_FD, 0x1000, IO_RINGFD_REG_MAX + 1),
               Err(Errno::Einval));
    assert_eq!(decode(IORING_UNREGISTER_RING_FDS, RING_FD, 0x1000, 1).unwrap().op,
               RegisterOp::UnregisterRingFds { arg: 0x1000, nr: 1 });
}

#[test]
fn ring_fds_opcodes_are_not_blind_eligible() {
    // Linux `io_uring_register_blind` has no RING_FDS case: `fd == -1` must
    // stay -EINVAL for these, never fall through to the ring-fd ladder.
    assert_eq!(decode(IORING_REGISTER_RING_FDS, -1, 0x1000, 1), Err(Errno::Einval));
    assert_eq!(decode(IORING_UNREGISTER_RING_FDS, -1, 0x1000, 1), Err(Errno::Einval));
}

#[test]
fn ring_fds_reg_admission_rejects_nonzero_resv() {
    assert_eq!(ring_fds_reg_admission(0), Ok(()));
    assert_eq!(ring_fds_reg_admission(1), Err(Errno::Einval));
}

#[test]
fn ring_fds_unreg_admission_checks_resv_data_and_bounds() {
    assert_eq!(ring_fds_unreg_admission(0, 0, 0), Ok(()));
    assert_eq!(ring_fds_unreg_admission(1, 0, 0), Err(Errno::Einval), "resv must be zero");
    assert_eq!(ring_fds_unreg_admission(0, 7, 0), Err(Errno::Einval), "data must be zero");
    assert_eq!(ring_fds_unreg_admission(0, 0, IO_RINGFD_REG_MAX), Err(Errno::Einval),
               "offset must be in range");
    assert_eq!(ring_fds_unreg_admission(0, 0, IO_RINGFD_REG_MAX - 1), Ok(()));
}

#[test]
fn ring_fds_result_follows_the_reference_partial_success_rule() {
    // Linux: `return i ? i : ret;` — anything committed wins over the error
    // that stopped the loop.
    assert_eq!(ring_fds_result(0, Err(Errno::Ebusy)), -(Errno::Ebusy.as_i32() as i64));
    assert_eq!(ring_fds_result(3, Err(Errno::Ebusy)), 3, "committed entries win over the failure");
    assert_eq!(ring_fds_result(5, Ok(())), 5);
    assert_eq!(ring_fds_result(0, Ok(())), 0);
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
    // A task filtering ITSELF needs no ring. Its argument count travels with
    // the request because the permission check is decided before it.
    assert_eq!(decode(IORING_REGISTER_BPF_FILTER, -1, 0x1000, 1).unwrap().op,
               RegisterOp::BpfFilterTask { arg: 0x1000, nr: 1 });
    // A task restricting ITSELF needs no ring either, and for the same
    // reason carries its argument count through rather than being screened
    // here.
    assert_eq!(decode(IORING_REGISTER_RESTRICTIONS, -1, 0x1000, 1).unwrap().op,
               RegisterOp::RestrictionsTask { arg: 0x1000, nr: 1 });
    assert_eq!(decode(IORING_REGISTER_RESTRICTIONS, -1, 0x1000, 4).unwrap().op,
               RegisterOp::RestrictionsTask { arg: 0x1000, nr: 4 },
               "a wrong count is the work function's EINVAL, not the decoder's");
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
    // zero-copy receive queue with a device memory provider behind it.
    // Returning 0 for any of them would tell the caller a registration
    // happened that did not (`scratch/known_issues.md`).
    for op in [IORING_REGISTER_ZCRX_IFQ, IORING_REGISTER_ZCRX_CTRL] {
        assert_eq!(decode(op, RING_FD, 0x1000, 1), Err(Errno::Eopnotsupp), "op {op}");
    }
}

/// `IORING_REGISTER_RESIZE_RINGS` takes exactly one `io_uring_params`.
#[test]
fn resize_rings_takes_one_params_pointer() {
    assert_eq!(decode(IORING_REGISTER_RESIZE_RINGS, RING_FD, 0x1000, 1).unwrap().op,
               RegisterOp::ResizeRings { arg: 0x1000 });
    assert_eq!(decode(IORING_REGISTER_RESIZE_RINGS, RING_FD, 0, 1), Err(Errno::Einval));
    for nr in [0u32, 2] {
        assert_eq!(decode(IORING_REGISTER_RESIZE_RINGS, RING_FD, 0x1000, nr),
                   Err(Errno::Einval), "nr {nr}");
    }
    // No ring, no rings to resize.
    assert_eq!(decode(IORING_REGISTER_RESIZE_RINGS, -1, 0x1000, 1), Err(Errno::Einval));
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
