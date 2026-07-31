// Hosted contract for `clone_abi`. Each case names the observable rule; the
// numbers are the ones a Linux-ABI program actually sees.

use super::*;

fn base() -> CloneArgs { CloneArgs::default() }

#[test]
fn size_gate_reports_oversize_before_undersize() {
    // A wild size is E2BIG even though it is also "not a known version".
    assert_eq!(clone3_size_ok(usize::MAX), Err(Errno::E2big));
    assert_eq!(clone3_size_ok(CLONE_ARGS_SIZE_MAX + 1), Err(Errno::E2big));
    assert_eq!(clone3_size_ok(CLONE_ARGS_SIZE_MAX), Ok(()));
    assert_eq!(clone3_size_ok(CLONE_ARGS_SIZE_VER0 - 1), Err(Errno::Einval));
    assert_eq!(clone3_size_ok(0), Err(Errno::Einval));
    for v in [CLONE_ARGS_SIZE_VER0, CLONE_ARGS_SIZE_VER1, CLONE_ARGS_SIZE_VER2] {
        assert_eq!(clone3_size_ok(v), Ok(()));
    }
}

#[test]
fn versioned_sizes_track_the_struct_tail() {
    assert_eq!(CLONE_ARGS_SIZE_VER0, (slot::TLS + 1) * 8);
    assert_eq!(CLONE_ARGS_SIZE_VER1, (slot::SET_TID_SIZE + 1) * 8);
    assert_eq!(CLONE_ARGS_SIZE_VER2, (slot::CGROUP + 1) * 8);
}

#[test]
fn unknown_trailing_bytes_must_be_zero() {
    let a = base();
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER2 + 8, false), Err(Errno::E2big));
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER2 + 8, true), Ok(()));
    // A short size has no tail to check.
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER0, false), Ok(()));
}

#[test]
fn set_tid_pointer_and_length_must_agree() {
    let mut a = base();
    a.set_tid_size = MAX_PID_NS_LEVEL as u64 + 1;
    a.set_tid = 0x1000;
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER1, true), Err(Errno::Einval));
    a = base(); a.set_tid_size = 1; a.set_tid = 0;
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER1, true), Err(Errno::Einval));
    a = base(); a.set_tid_size = 0; a.set_tid = 0x1000;
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER1, true), Err(Errno::Einval));
    a = base(); a.set_tid_size = MAX_PID_NS_LEVEL as u64; a.set_tid = 0x1000;
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER1, true), Ok(()));
}

#[test]
fn exit_signal_field_is_confined_to_the_signal_window() {
    let mut a = base();
    a.exit_signal = CSIGNAL + 1;
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER0, true), Err(Errno::Einval));
    a.exit_signal = 1u64 << 32;
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER0, true), Err(Errno::Einval));
    a.exit_signal = FORK_EXIT_SIGNAL as u64;
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER0, true), Ok(()));
}

#[test]
fn into_cgroup_needs_the_field_and_an_int_sized_fd() {
    let mut a = base();
    a.flags = CLONE_INTO_CGROUP;
    a.cgroup = 3;
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER1, true), Err(Errno::Einval));
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER2, true), Ok(()));
    // An fd that cannot be an `int` is a malformed argument, not a bad fd.
    a.cgroup = i32::MAX as u64 + 1;
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER2, true), Err(Errno::Einval));
    a.cgroup = u32::MAX as u64;
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER2, true), Err(Errno::Einval));
    // Without the flag the field is ignored entirely.
    a.flags = 0;
    assert_eq!(clone3_fields_ok(&a, CLONE_ARGS_SIZE_VER0, true), Ok(()));
}

#[test]
fn clone3_rejects_the_reserved_signal_window_but_keeps_newtime() {
    let mut a = base();
    a.flags = CLONE_NEWTIME;
    assert_eq!(clone3_flags_ok(&a, true), Ok(()));
    for bit in [0x01u64, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40] {
        a.flags = bit;
        assert_eq!(clone3_flags_ok(&a, true), Err(Errno::Einval));
    }
    a.flags = CLONE_DETACHED;
    assert_eq!(clone3_flags_ok(&a, true), Err(Errno::Einval));
}

#[test]
fn clone3_rejects_unknown_flag_bits() {
    let mut a = base();
    a.flags = 1 << 34;
    assert_eq!(clone3_flags_ok(&a, true), Err(Errno::Einval));
    a.flags = CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP;
    assert_eq!(clone3_flags_ok(&a, true), Ok(()));
}

#[test]
fn clear_sighand_conflicts_with_sharing_sighand() {
    let mut a = base();
    a.flags = CLONE_SIGHAND | CLONE_CLEAR_SIGHAND | CLONE_VM;
    assert_eq!(clone3_flags_ok(&a, true), Err(Errno::Einval));
}

#[test]
fn thread_or_parent_forbids_an_exit_signal() {
    let mut a = base();
    a.exit_signal = FORK_EXIT_SIGNAL as u64;
    a.flags = CLONE_THREAD | CLONE_SIGHAND | CLONE_VM;
    assert_eq!(clone3_flags_ok(&a, true), Err(Errno::Einval));
    a.flags = CLONE_PARENT;
    assert_eq!(clone3_flags_ok(&a, true), Err(Errno::Einval));
    a.exit_signal = 0;
    assert_eq!(clone3_flags_ok(&a, true), Ok(()));
}

#[test]
fn stack_and_size_are_all_or_nothing_and_a_bad_range_is_einval() {
    let mut a = base();
    a.stack = 0; a.stack_size = 4096;
    assert_eq!(clone3_flags_ok(&a, true), Err(Errno::Einval));
    a.stack = 0x7fff_0000; a.stack_size = 0;
    assert_eq!(clone3_flags_ok(&a, true), Err(Errno::Einval));
    a.stack = 0x7fff_0000; a.stack_size = 4096;
    // An unmapped/out-of-range stack is a malformed argument, not a fault.
    assert_eq!(clone3_flags_ok(&a, false), Err(Errno::Einval));
    assert_eq!(clone3_flags_ok(&a, true), Ok(()));
    assert_eq!(clone3_child_sp(&a), 0x7fff_0000 + 4096);
    a.stack = 0; a.stack_size = 0;
    assert_eq!(clone3_child_sp(&a), 0);
}

#[test]
fn legacy_flag_word_splits_into_flags_and_exit_signal() {
    let (f, s) = split_legacy_flags(FORK_EXIT_SIGNAL as u64);
    assert_eq!((f, s), (0, FORK_EXIT_SIGNAL));
    let (f, s) = split_legacy_flags(VFORK_FLAGS | FORK_EXIT_SIGNAL as u64);
    assert_eq!((f, s), (VFORK_FLAGS, FORK_EXIT_SIGNAL));
    // The time-namespace bit is not reachable from the legacy entry point: it
    // decodes as exit signal 128, which no signal number matches.
    let (f, s) = split_legacy_flags(CLONE_NEWTIME);
    assert_eq!(f, 0);
    assert!(!valid_exit_signal(s));
}

#[test]
fn exit_signal_range_matches_the_signal_table() {
    assert!(valid_exit_signal(0));
    assert!(valid_exit_signal(FORK_EXIT_SIGNAL));
    assert!(valid_exit_signal(64));
    assert!(!valid_exit_signal(65));
    assert!(!valid_exit_signal(128));
    assert!(!valid_exit_signal(255));
}

fn core_ok(flags: u64) -> Result<(), Errno> {
    validate_clone(flags, 0, CloneCaller::default(), false)
}

#[test]
fn shared_flag_matrix() {
    assert_eq!(core_ok(CLONE_NEWNS | CLONE_FS), Err(Errno::Einval));
    assert_eq!(core_ok(CLONE_NEWUSER | CLONE_FS), Err(Errno::Einval));
    assert_eq!(core_ok(CLONE_THREAD | CLONE_VM), Err(Errno::Einval));
    assert_eq!(core_ok(CLONE_SIGHAND), Err(Errno::Einval));
    assert_eq!(core_ok(CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_NEWPID), Err(Errno::Einval));
    assert_eq!(core_ok(CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_NEWUSER), Err(Errno::Einval));
    assert_eq!(core_ok(CLONE_PIDFD | CLONE_DETACHED), Err(Errno::Einval));
    assert_eq!(core_ok(CLONE_SIGHAND | CLONE_VM | CLONE_CLEAR_SIGHAND), Err(Errno::Einval));
    assert_eq!(core_ok(CLONE_THREAD | CLONE_SIGHAND | CLONE_VM), Ok(()));
    assert_eq!(core_ok(CLONE_NEWNS), Ok(()));
    assert_eq!(core_ok(CLONE_FS | CLONE_FILES | CLONE_VM | CLONE_SIGHAND), Ok(()));
}

#[test]
fn vfork_does_not_require_a_shared_address_space() {
    // The parent blocks until the child execs or exits either way; a private
    // address space is a legal, if unusual, request.
    assert_eq!(core_ok(CLONE_VFORK), Ok(()));
    assert_eq!(core_ok(VFORK_FLAGS), Ok(()));
}

#[test]
fn a_thread_may_request_a_pidfd_for_itself() {
    assert_eq!(core_ok(CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_PIDFD), Ok(()));
    assert!(pidfd_is_thread(CLONE_THREAD | CLONE_PIDFD));
    assert!(!pidfd_is_thread(CLONE_PIDFD));
}

#[test]
fn namespace_init_cannot_gain_a_sibling() {
    let init = CloneCaller { is_ns_init: true };
    assert_eq!(validate_clone(CLONE_PARENT, 0, init, false), Err(Errno::Einval));
    assert_eq!(validate_clone(CLONE_PARENT, 0, CloneCaller::default(), false), Ok(()));
    // Only CLONE_PARENT is restricted; init still forks normally.
    assert_eq!(validate_clone(0, FORK_EXIT_SIGNAL, init, false), Ok(()));
}

#[test]
fn a_pidfd_and_a_parent_tid_may_not_share_one_slot() {
    let c = CloneCaller::default();
    assert_eq!(validate_clone(CLONE_PIDFD | CLONE_PARENT_SETTID, 0, c, true), Err(Errno::Einval));
    assert_eq!(validate_clone(CLONE_PIDFD | CLONE_PARENT_SETTID, 0, c, false), Ok(()));
    // Aliasing only matters when both writes are requested.
    assert_eq!(validate_clone(CLONE_PIDFD, 0, c, true), Ok(()));
}

#[test]
fn an_out_of_range_exit_signal_is_rejected_by_the_shared_ladder() {
    let c = CloneCaller::default();
    assert_eq!(validate_clone(0, 65, c, false), Err(Errno::Einval));
    assert_eq!(validate_clone(0, FORK_EXIT_SIGNAL, c, false), Ok(()));
}

#[test]
fn requested_pids_must_be_usable_numbers_and_fit_the_namespace_depth() {
    assert_eq!(set_tid_values_ok(&[], 1), Ok(()));
    assert_eq!(set_tid_values_ok(&[42], 1), Ok(()));
    assert_eq!(set_tid_values_ok(&[42, 7], 1), Err(Errno::Einval));
    assert_eq!(set_tid_values_ok(&[42, 7], 2), Ok(()));
    assert_eq!(set_tid_values_ok(&[0], 1), Err(Errno::Einval));
    assert_eq!(set_tid_values_ok(&[PID_MAX_LIMIT], 1), Err(Errno::Einval));
    assert_eq!(set_tid_values_ok(&[PID_MAX_LIMIT - 1], 1), Ok(()));
    // A bad value anywhere in the array fails the whole request.
    assert_eq!(set_tid_values_ok(&[5, 0], 2), Err(Errno::Einval));
}

#[test]
fn args_decode_from_slots_in_struct_order() {
    let w: [u64; 11] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let a = CloneArgs::from_slots(&w);
    assert_eq!(a.flags, 1);
    assert_eq!(a.pidfd, 2);
    assert_eq!(a.child_tid, 3);
    assert_eq!(a.parent_tid, 4);
    assert_eq!(a.exit_signal, 5);
    assert_eq!(a.stack, 6);
    assert_eq!(a.stack_size, 7);
    assert_eq!(a.tls, 8);
    assert_eq!(a.set_tid, 9);
    assert_eq!(a.set_tid_size, 10);
    assert_eq!(a.cgroup, 11);
}
