use super::*;

fn regs() -> Regs {
    Regs { nr: 0x3b, args: [1, 2, 3, 4, 5, 6], ip: 0x4000_1000, sp: 0x7fff_0000, rval: -14 }
}

#[test]
fn the_record_offsets_match_the_abi_struct() {
    assert_eq!((OFF_OP, OFF_RESERVED, OFF_FLAGS, OFF_ARCH), (0, 1, 2, 4));
    assert_eq!((OFF_IP, OFF_SP, OFF_UNION), (8, 16, 24));
    assert_eq!((OFF_ENTRY_NR, OFF_ENTRY_ARGS), (24, 32));
    assert_eq!((OFF_EXIT_RVAL, OFF_EXIT_IS_ERROR), (24, 32));
    assert_eq!(OFF_SECCOMP_RET_DATA, 80);
    assert_eq!(SIZEOF, 88);
}

#[test]
fn each_op_reports_its_own_offsetofend_as_the_actual_size() {
    assert_eq!(END_NONE, 24);
    assert_eq!(END_ENTRY, 80);
    assert_eq!(END_EXIT, 33);
    assert_eq!(END_SECCOMP, 84);
    let r = regs();
    assert_eq!(encode(OP_NONE, 0, &r, 0).1, END_NONE);
    assert_eq!(encode(OP_ENTRY, 0, &r, 0).1, END_ENTRY);
    assert_eq!(encode(OP_EXIT, 0, &r, 0).1, END_EXIT);
    assert_eq!(encode(OP_SECCOMP, 0, &r, 0).1, END_SECCOMP);
}

#[test]
fn the_entry_record_carries_the_number_and_all_six_arguments() {
    let r = regs();
    let (b, _) = encode(OP_ENTRY, 0xc000_003e, &r, 0);
    assert_eq!(b[OFF_OP], OP_ENTRY);
    assert_eq!(u32::from_ne_bytes([b[4], b[5], b[6], b[7]]), 0xc000_003e);
    assert_eq!(u64::from_ne_bytes(rec_u64(&b, OFF_IP)), r.ip);
    assert_eq!(u64::from_ne_bytes(rec_u64(&b, OFF_SP)), r.sp);
    assert_eq!(u64::from_ne_bytes(rec_u64(&b, OFF_ENTRY_NR)), r.nr);
    for i in 0..NARGS {
        assert_eq!(u64::from_ne_bytes(rec_u64(&b, OFF_ENTRY_ARGS + i * 8)), r.args[i]);
    }
    // The entry arm must not leak a ret_data into the seccomp slot.
    assert_eq!(u32::from_ne_bytes([b[80], b[81], b[82], b[83]]), 0);
}

#[test]
fn a_seccomp_record_is_an_entry_record_plus_ret_data() {
    let r = regs();
    let (e, _) = encode(OP_ENTRY, 7, &r, 0);
    let (s, _) = encode(OP_SECCOMP, 7, &r, 0xbeef);
    assert_eq!(e[OFF_UNION..OFF_SECCOMP_RET_DATA], s[OFF_UNION..OFF_SECCOMP_RET_DATA]);
    assert_eq!(u32::from_ne_bytes([s[80], s[81], s[82], s[83]]), 0xbeef);
}

#[test]
fn an_error_return_sets_is_error_and_keeps_the_negative_errno() {
    let mut r = regs();
    r.rval = -14;
    let (b, _) = encode(OP_EXIT, 0, &r, 0);
    assert_eq!(b[OFF_EXIT_IS_ERROR], 1);
    assert_eq!(i64::from_ne_bytes(rec_u64(&b, OFF_EXIT_RVAL)), -14);
}

#[test]
fn a_success_return_clears_is_error_even_when_large() {
    for rval in [0i64, 1, 4096, i64::MAX, -4096, -4097, i64::MIN] {
        let mut r = regs();
        r.rval = rval;
        let (b, _) = encode(OP_EXIT, 0, &r, 0);
        assert_eq!(b[OFF_EXIT_IS_ERROR], 0, "rval {rval} must not read as an error");
        assert_eq!(i64::from_ne_bytes(rec_u64(&b, OFF_EXIT_RVAL)), rval);
    }
}

#[test]
fn the_error_window_is_exactly_minus_max_errno_through_minus_one() {
    assert!(is_error(-1));
    assert!(is_error(-(MAX_ERRNO as i64)));
    assert!(!is_error(-(MAX_ERRNO as i64) - 1));
    assert!(!is_error(0));
}

#[test]
fn a_none_record_carries_only_the_header() {
    let (b, n) = encode(OP_NONE, 5, &regs(), 0);
    assert_eq!(n, OFF_UNION);
    assert!(b[OFF_UNION..].iter().all(|&x| x == 0));
}

#[test]
fn the_op_is_read_from_the_stop_code_and_the_recorded_message() {
    use crate::s101_ptrace_event as event;
    let sysgood = uapi::syscall_stop_code();
    assert_eq!(op_of(Some(sysgood), event::EVENTMSG_SYSCALL_ENTRY), OP_ENTRY);
    assert_eq!(op_of(Some(sysgood), event::EVENTMSG_SYSCALL_EXIT), OP_EXIT);
    assert_eq!(op_of(Some(sysgood), 0), OP_NONE);
    assert_eq!(op_of(Some(uapi::event_stop_code(uapi::EVENT_SECCOMP)), 0), OP_SECCOMP);
}

#[test]
fn a_signal_or_event_stop_is_not_a_syscall_stop() {
    use crate::s101_ptrace_event as event;
    assert_eq!(op_of(None, event::EVENTMSG_SYSCALL_ENTRY), OP_NONE);
    // A bare SIGTRAP is not SIGTRAP|0x80 — the TRACESYSGOOD bit is what
    // separates a syscall stop from a real trap.
    assert_eq!(op_of(Some(uapi::SIGTRAP_CODE), event::EVENTMSG_SYSCALL_ENTRY), OP_NONE);
    for e in [uapi::EVENT_FORK, uapi::EVENT_EXEC, uapi::EVENT_EXIT, uapi::EVENT_STOP] {
        assert_eq!(op_of(Some(uapi::event_stop_code(e)), 0), OP_NONE);
    }
}

fn entry_record(nr: i64, args: [u64; NARGS]) -> [u8; SIZEOF] {
    let r = Regs { nr: nr as u64, args, ip: 0, sp: 0, rval: 0 };
    encode(OP_ENTRY, 0, &r, 0).0
}

#[test]
fn a_short_user_size_is_refused_rather_than_truncated() {
    let rec = entry_record(1, [0; NARGS]);
    assert_eq!(decode_set(OP_ENTRY, SIZEOF - 1, &rec), Err(Errno::Einval));
    assert!(decode_set(OP_ENTRY, SIZEOF, &rec).is_ok());
}

#[test]
fn reserved_and_flags_must_be_zero() {
    let mut rec = entry_record(1, [0; NARGS]);
    rec[OFF_RESERVED] = 1;
    assert_eq!(decode_set(OP_ENTRY, SIZEOF, &rec), Err(Errno::Einval));
    let mut rec = entry_record(1, [0; NARGS]);
    rec[OFF_FLAGS] = 1;
    assert_eq!(decode_set(OP_ENTRY, SIZEOF, &rec), Err(Errno::Einval));
}

#[test]
fn changing_the_kind_of_stop_is_einval() {
    let rec = entry_record(1, [0; NARGS]);
    assert_eq!(decode_set(OP_EXIT, SIZEOF, &rec), Err(Errno::Einval));
    assert_eq!(decode_set(OP_NONE, SIZEOF, &rec), Err(Errno::Einval));
}

#[test]
fn a_syscall_number_that_does_not_fit_an_int_is_erange() {
    let mut rec = entry_record(1, [0; NARGS]);
    rec[OFF_ENTRY_NR..OFF_ENTRY_NR + 8].copy_from_slice(&0x1_0000_0000u64.to_ne_bytes());
    assert_eq!(decode_set(OP_ENTRY, SIZEOF, &rec), Err(Errno::Erange));
}

#[test]
fn a_sign_extended_negative_number_round_trips() {
    let rec = entry_record(-1, [9; NARGS]);
    assert_eq!(decode_set(OP_ENTRY, SIZEOF, &rec),
               Ok(SetRequest::Entry { nr: -1, args: [9; NARGS], set_args: false }));
}

#[test]
fn cancelling_the_syscall_leaves_the_argument_registers_alone() {
    // nr == -1 must NOT write the argument registers: on ABIs where the first
    // argument register is also the return register, writing it would clobber
    // the value the tracer is about to set.
    match decode_set(OP_ENTRY, SIZEOF, &entry_record(-1, [1, 2, 3, 4, 5, 6])).unwrap() {
        SetRequest::Entry { set_args, .. } => assert!(!set_args),
        other => panic!("{other:?}"),
    }
    match decode_set(OP_ENTRY, SIZEOF, &entry_record(60, [1, 2, 3, 4, 5, 6])).unwrap() {
        SetRequest::Entry { set_args, nr, args } => {
            assert!(set_args);
            assert_eq!(nr, 60);
            assert_eq!(args, [1, 2, 3, 4, 5, 6]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_seccomp_stop_accepts_the_entry_form_and_ignores_ret_data() {
    let r = Regs { nr: 5, args: [7; NARGS], ip: 0, sp: 0, rval: 0 };
    let (rec, _) = encode(OP_SECCOMP, 0, &r, 0xdead);
    assert_eq!(decode_set(OP_SECCOMP, SIZEOF, &rec),
               Ok(SetRequest::Entry { nr: 5, args: [7; NARGS], set_args: true }));
}

#[test]
fn the_exit_arm_round_trips_both_signs() {
    let r = Regs { nr: 0, args: [0; NARGS], ip: 0, sp: 0, rval: -22 };
    let (rec, _) = encode(OP_EXIT, 0, &r, 0);
    assert_eq!(decode_set(OP_EXIT, SIZEOF, &rec),
               Ok(SetRequest::Exit { rval: -22, is_error: true }));
    let r = Regs { rval: 1234, ..r };
    let (rec, _) = encode(OP_EXIT, 0, &r, 0);
    assert_eq!(decode_set(OP_EXIT, SIZEOF, &rec),
               Ok(SetRequest::Exit { rval: 1234, is_error: false }));
    assert_eq!(exit_return_register(-22, true), -22);
    assert_eq!(exit_return_register(1234, false), 1234);
}

#[test]
fn the_sud_record_is_exactly_four_quadwords_in_mode_selector_offset_len_order() {
    assert_eq!((SUD_OFF_MODE, SUD_OFF_SELECTOR, SUD_OFF_OFFSET, SUD_OFF_LEN), (0, 8, 16, 24));
    assert_eq!(SUD_SIZEOF, 32);
    let c = SudConfig { mode: PR_SYS_DISPATCH_ON, selector: 0xdead, offset: 0x1000, len: 0x200 };
    assert_eq!(sud_decode(&sud_encode(&c)), c);
}

#[test]
fn the_sud_record_size_must_match_exactly_in_both_directions() {
    assert_eq!(sud_size_ok(SUD_SIZEOF as u64), Ok(()));
    assert_eq!(sud_size_ok(SUD_SIZEOF as u64 - 1), Err(Errno::Einval));
    // Bigger is refused too: unlike GET_SYSCALL_INFO there is no truncation
    // rule, so a caller compiled against a future record is told so.
    assert_eq!(sud_size_ok(SUD_SIZEOF as u64 + 1), Err(Errno::Einval));
    assert_eq!(sud_size_ok(0), Err(Errno::Einval));
}
