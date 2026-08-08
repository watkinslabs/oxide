use super::*;

#[test]
fn a_full_cq_has_no_room() {
    assert!(cq_has_room(0, 0, 8));
    assert!(cq_has_room(7, 0, 8));
    // tail - head == entries: every slot holds an unreaped completion.
    assert!(!cq_has_room(8, 0, 8));
    assert_eq!(cq_space(8, 0, 8), 0);
    assert!(cq_has_room(8, 1, 8));
}

#[test]
fn cq_occupancy_survives_counter_wraparound() {
    assert!(cq_has_room(0, u32::MAX - 2, 8));
    assert_eq!(cq_space(0, u32::MAX, 8), 7);
    assert!(!cq_has_room(7, u32::MAX, 8));
    assert_eq!(cq_ready(3, u32::MAX), 4);
}

#[test]
fn out_of_range_sq_indices_are_rejected() {
    assert!(sq_index_valid(0, 8));
    assert!(sq_index_valid(7, 8));
    assert!(!sq_index_valid(8, 8));
    assert!(!sq_index_valid(u32::MAX, 8));
}

#[test]
fn unknown_enter_flags_are_refused() {
    assert_eq!(validate_flags(0), Ok(()));
    assert_eq!(validate_flags(IORING_ENTER_FLAGS), Ok(()));
    assert_eq!(validate_flags(1 << 8), Err(Errno::Einval));
    assert_eq!(validate_flags(IORING_ENTER_GETEVENTS | (1 << 31)), Err(Errno::Einval));
    // The mask is bits 0..=7 and nothing else.
    assert_eq!(IORING_ENTER_FLAGS, (1u32 << 8) - 1);
}

#[test]
fn argument_shape_follows_the_two_extended_argument_flags() {
    // No EXT_ARG: argp is a bare sigset pointer whatever argsz says, so no
    // size check happens here.
    assert_eq!(arg_kind(0, 0), Ok(ArgKind::BareSigmask));
    assert_eq!(arg_kind(0, 999), Ok(ArgKind::BareSigmask));
    assert_eq!(arg_kind(IORING_ENTER_EXT_ARG_REG, 999), Ok(ArgKind::BareSigmask));
    // EXT_ARG: exactly sizeof(struct io_uring_getevents_arg).
    assert_eq!(arg_kind(IORING_ENTER_EXT_ARG, GETEVENTS_ARG_BYTES), Ok(ArgKind::Getevents));
    assert_eq!(arg_kind(IORING_ENTER_EXT_ARG, GETEVENTS_ARG_BYTES - 1), Err(Errno::Einval));
    // EXT_ARG|EXT_ARG_REG: exactly sizeof(struct io_uring_reg_wait).
    assert_eq!(arg_kind(IORING_ENTER_EXT_ARG | IORING_ENTER_EXT_ARG_REG, REG_WAIT_BYTES),
               Ok(ArgKind::RegisteredWait));
    assert_eq!(arg_kind(IORING_ENTER_EXT_ARG | IORING_ENTER_EXT_ARG_REG, GETEVENTS_ARG_BYTES),
               Err(Errno::Einval));
}

#[test]
fn getevents_arg_decodes_at_the_wire_offsets() {
    let mut b = [0u8; GETEVENTS_ARG_BYTES as usize];
    b[0..8].copy_from_slice(&0xDEAD_BEEF_0000_1000u64.to_le_bytes());
    b[8..12].copy_from_slice(&8u32.to_le_bytes());
    b[12..16].copy_from_slice(&250u32.to_le_bytes());
    b[16..24].copy_from_slice(&0x4000u64.to_le_bytes());
    let (sig, sigsz, min_wait_usec, ts) = decode_getevents(&b);
    assert_eq!(sig, 0xDEAD_BEEF_0000_1000);
    assert_eq!(sigsz, 8);
    assert_eq!(min_wait_usec, 250);
    assert_eq!(ts, 0x4000);
}

#[test]
fn reg_wait_decodes_and_rejects_unknown_flag_bits() {
    let mut b = [0u8; REG_WAIT_BYTES as usize];
    b[0..8].copy_from_slice(&5i64.to_le_bytes());          // ts.tv_sec
    b[8..16].copy_from_slice(&17i64.to_le_bytes());        // ts.tv_nsec
    b[16..20].copy_from_slice(&100u32.to_le_bytes());      // min_wait_usec
    b[20..24].copy_from_slice(&IORING_REG_WAIT_TS.to_le_bytes());
    b[24..32].copy_from_slice(&0x9000u64.to_le_bytes());   // sigmask
    b[32..36].copy_from_slice(&8u32.to_le_bytes());        // sigmask_sz
    let a = decode_reg_wait(&b, IORING_ENTER_ABS_TIMER).unwrap();
    assert_eq!(a.ts, Some((5, 17)));
    assert_eq!(a.min_wait_ns, 100 * NSEC_PER_USEC);
    assert_eq!(a.sig, 0x9000);
    assert_eq!(a.sigsz, 8);
    assert!(a.abs);
    assert!(a.iowait);

    // Without the TS bit the embedded timespec is not a timeout.
    b[20..24].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(decode_reg_wait(&b, 0).unwrap().ts, None);
    // An unknown flag bit is refused rather than ignored.
    b[20..24].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(decode_reg_wait(&b, 0), Err(Errno::Einval));
}

#[test]
fn bare_sigmask_form_carries_no_timeout() {
    let a = bare_sigmask_arg(0x1234, 8, IORING_ENTER_NO_IOWAIT);
    assert_eq!(a.sig, 0x1234);
    assert_eq!(a.sigsz, 8);
    assert_eq!(a.ts, None);
    assert_eq!(a.min_wait_ns, 0);
    assert!(!a.iowait);
}

#[test]
fn min_complete_is_clamped_to_the_ring_depth() {
    assert_eq!(wait_min_events(0, 8), 0);
    assert_eq!(wait_min_events(3, 8), 3);
    // Asking for more completions than the ring can hold would wait forever.
    assert_eq!(wait_min_events(9, 8), 8);
    assert!(should_wake(8, 8));
    assert!(!should_wake(7, 8));
    assert!(should_wake(0, 0));
}

#[test]
fn getevents_runs_only_after_a_complete_submission() {
    assert!(!runs_getevents(0, 0, 0));
    assert!(runs_getevents(0, 0, IORING_ENTER_GETEVENTS));
    assert!(runs_getevents(4, 4, IORING_ENTER_GETEVENTS));
    // A short submission reports what it did and does not wait.
    assert!(!runs_getevents(2, 4, IORING_ENTER_GETEVENTS));
    assert!(!runs_getevents(-9, 4, IORING_ENTER_GETEVENTS));
}

#[test]
fn the_submitted_count_outranks_a_wait_error() {
    assert_eq!(enter_result(3, -(Errno::Etime.as_i32() as i64)), 3);
    assert_eq!(enter_result(0, -(Errno::Etime.as_i32() as i64)),
               -(Errno::Etime.as_i32() as i64));
    assert_eq!(enter_result(0, 0), 0);
}

#[test]
fn a_timeout_with_reapable_completions_is_a_success() {
    let etime = -(Errno::Etime.as_i32() as i64);
    assert_eq!(wait_result(etime, true), 0);
    assert_eq!(wait_result(etime, false), etime);
    assert_eq!(wait_result(-(Errno::Eintr.as_i32() as i64), true), 0);
}
