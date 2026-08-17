use super::*;
use ::ipc::futex2_flags::{FUTEX2_PRIVATE, FUTEX2_SIZE_U32, FUTEX2_SIZE_U64};

fn wait() -> Sqe {
    Sqe { opcode: IORING_OP_FUTEX_WAIT, fd: FUTEX2_SIZE_U32 as i32,
          addr: 0x1000, off: 1, addr3: u32::MAX as u64, ..Sqe::default() }
}
fn wake() -> Sqe { Sqe { opcode: IORING_OP_FUTEX_WAKE, ..wait() } }

#[test]
fn the_operands_come_from_the_fields_that_can_hold_them() {
    let s = wait();
    let f = prep(&s).expect("valid");
    // uaddr is `addr`, the compare value is `addr2` (the `off` word), the
    // bitset is `addr3`, and the futex2 flag word is `fd`. Any two of these
    // swapped would still be plausible integers and would park on the wrong
    // word or against the wrong value.
    assert_eq!(f.uaddr, 0x1000);
    assert_eq!(f.val, 1);
    assert_eq!(f.mask, u32::MAX as u64);
    assert_eq!(f.flags, FUTEX2_SIZE_U32);
}

#[test]
fn every_field_the_operation_does_not_read_must_be_zero() {
    for mutate in [
        (|s: &mut Sqe| s.len = 1) as fn(&mut Sqe),
        |s: &mut Sqe| s.op_flags = 1,
        |s: &mut Sqe| s.buf_index = 1,
        |s: &mut Sqe| s.splice_fd_in = 1,
    ] {
        let mut s = wait();
        mutate(&mut s);
        assert_eq!(prep(&s), Err(Errno::Einval));
    }
}

#[test]
fn an_undefined_futex2_flag_bit_is_refused() {
    let mut s = wait();
    s.fd = 0x4000 as i32;
    assert_eq!(prep(&s), Err(Errno::Einval));
}

#[test]
fn a_size_class_the_contract_does_not_implement_is_refused() {
    let mut s = wait();
    s.fd = FUTEX2_SIZE_U64 as i32;
    assert_eq!(prep(&s), Err(Errno::Einval));
}

/// The compare value arrives 64 bits wide and the futex word is 32. Narrowing
/// it would let a caller's mismatched value alias a real word value: the wait
/// would succeed against a word it does not actually match and never be woken.
#[test]
fn a_compare_value_wider_than_the_futex_word_is_refused_not_truncated() {
    let mut s = wait();
    s.off = 1u64 << 32;
    assert_eq!(prep(&s), Err(Errno::Einval));
}

#[test]
fn a_bitset_wider_than_the_futex_word_is_refused_not_truncated() {
    let mut s = wait();
    s.addr3 = 1u64 << 32;
    assert_eq!(prep(&s), Err(Errno::Einval));
}

/// A wait whose bitset is empty intersects no wake that can ever be issued:
/// the submission would stay outstanding for the life of the ring and its
/// completion would never arrive.
#[test]
fn a_wait_with_an_empty_bitset_is_refused() {
    let mut s = wait();
    s.addr3 = 0;
    assert_eq!(prep(&s), Err(Errno::Einval));
}

/// A wake with no bit set is a different question — it is the wake side's own
/// ladder, and refusing it here would report the wrong reason.
#[test]
fn a_wake_is_not_subject_to_the_waits_bitset_rung() {
    let mut s = wake();
    s.addr3 = 0;
    assert!(prep(&s).is_ok());
}

#[test]
fn the_private_bit_is_carried_through() {
    let mut s = wait();
    s.fd = (FUTEX2_SIZE_U32 | FUTEX2_PRIVATE) as i32;
    assert_eq!(prep(&s).expect("valid").flags, FUTEX2_SIZE_U32 | FUTEX2_PRIVATE);
}

// --- vectored wait ------------------------------------------------------

fn waitv() -> Sqe {
    Sqe { opcode: IORING_OP_FUTEX_WAITV, addr: 0x2000, len: 4, ..Sqe::default() }
}

#[test]
fn a_vectored_wait_reads_its_array_and_count() {
    let v = prep_waitv(&waitv()).expect("valid");
    assert_eq!(v.uaddr, 0x2000);
    assert_eq!(v.nr, 4);
}

/// Each element of the vector carries its own flag word and value, so a copy
/// on the entry would be a second answer to the same question.
#[test]
fn a_vectored_wait_refuses_a_flag_word_value_or_mask_of_its_own() {
    for mutate in [
        (|s: &mut Sqe| s.fd = 1) as fn(&mut Sqe),
        |s: &mut Sqe| s.off = 1,
        |s: &mut Sqe| s.addr3 = 1,
        |s: &mut Sqe| s.op_flags = 1,
        |s: &mut Sqe| s.buf_index = 1,
        |s: &mut Sqe| s.splice_fd_in = 1,
    ] {
        let mut s = waitv();
        mutate(&mut s);
        assert_eq!(prep_waitv(&s), Err(Errno::Einval));
    }
}

#[test]
fn an_empty_or_oversized_vector_is_refused() {
    let mut s = waitv();
    s.len = 0;
    assert_eq!(prep_waitv(&s), Err(Errno::Einval));
    s.len = FUTEX_WAITV_MAX + 1;
    assert_eq!(prep_waitv(&s), Err(Errno::Einval));
    s.len = FUTEX_WAITV_MAX;
    assert!(prep_waitv(&s).is_ok());
}

#[test]
fn the_family_predicate_names_all_three() {
    for op in [IORING_OP_FUTEX_WAIT, IORING_OP_FUTEX_WAKE, IORING_OP_FUTEX_WAITV] {
        assert!(is_futex(op), "op {op}");
    }
    assert!(!is_futex(crate::io_uring_abi::ops::IORING_OP_WAITID));
}
