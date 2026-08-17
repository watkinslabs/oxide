use super::*;

fn rv() -> Sqe {
    Sqe { opcode: IORING_OP_READV_FIXED, addr: 0x5000, len: 3, buf_index: 2,
          off: 4096, ..Sqe::default() }
}

#[test]
fn the_operands_come_from_the_fields_the_vector_shape_uses() {
    let v = prep_vec_fixed(&rv()).expect("valid");
    assert_eq!(v.uvec, 0x5000);
    assert_eq!(v.nr, 3);
    assert_eq!(v.buf_index, 2);
    assert_eq!(v.off, Some(4096));
    assert!(!v.write);
}

#[test]
fn the_write_form_is_told_apart_by_its_opcode_alone() {
    let mut s = rv();
    s.opcode = IORING_OP_WRITEV_FIXED;
    assert!(prep_vec_fixed(&s).expect("valid").write);
}

#[test]
fn an_oversized_vector_is_refused() {
    let mut s = rv();
    s.len = UIO_MAXIOV + 1;
    assert_eq!(prep_vec_fixed(&s), Err(Errno::Einval));
    s.len = UIO_MAXIOV;
    assert!(prep_vec_fixed(&s).is_ok());
}

/// A zero-segment vectored transfer is LEGAL and moves no bytes — the
/// long-standing answer for every vectored read and write, not an error.
/// Refusing it would report `EINVAL` for a request that must succeed with `0`.
#[test]
fn an_empty_vector_is_accepted_and_moves_nothing() {
    let mut s = rv();
    s.len = 0;
    assert_eq!(prep_vec_fixed(&s).expect("an empty vector is legal").nr, 0);
}

/// `buf_index` and `buf_group` are the SAME field, so an entry naming both a
/// group and a registration is a contradiction — but it is refused for EVERY
/// opcode whose table entry does not offer selection, by the submission
/// admission that reads `op_buffer_select`, and it is `EOPNOTSUPP` there. This
/// decoder must NOT answer the same question a second time with a different
/// errno; the table entry is what carries the contract.
#[test]
fn the_provided_buffer_question_is_left_to_the_table_that_owns_it() {
    assert!(!crate::io_uring_abi::ops::op_buffer_select(IORING_OP_READV_FIXED));
    assert!(!crate::io_uring_abi::ops::op_buffer_select(IORING_OP_WRITEV_FIXED));
    // The decoder itself is silent on the flag rather than duplicating the rung.
    let mut s = rv();
    s.flags = crate::io_uring_abi::ops::IOSQE_BUFFER_SELECT;
    assert!(prep_vec_fixed(&s).is_ok());
}

#[test]
fn the_offset_sentinel_means_the_descriptions_own_position() {
    let mut s = rv();
    s.off = CUR_POS;
    assert_eq!(prep_vec_fixed(&s).expect("valid").off, None);
    // Zero is a real offset, not the sentinel.
    s.off = 0;
    assert_eq!(prep_vec_fixed(&s).expect("valid").off, Some(0));
}

#[test]
fn a_segment_decodes_base_then_length() {
    let mut b = [0u8; IOVEC_BYTES as usize];
    b[..8].copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
    b[8..].copy_from_slice(&4096u64.to_le_bytes());
    let s = seg_from_wire(&b);
    assert_eq!(s.base, 0x1234_5678_9abc_def0);
    assert_eq!(s.len, 4096);
}

#[test]
fn the_segment_record_is_the_two_word_wire_form() {
    assert_eq!(IOVEC_BYTES, 16);
    assert_eq!(IOVEC_LEN_OFF, 8);
}

#[test]
fn the_family_predicate_names_both_and_nothing_else() {
    assert!(is_vec_fixed(IORING_OP_READV_FIXED));
    assert!(is_vec_fixed(IORING_OP_WRITEV_FIXED));
    assert!(!is_vec_fixed(crate::io_uring_abi::ops::IORING_OP_READV));
    assert!(!is_vec_fixed(crate::io_uring_abi::ops::IORING_OP_READ_FIXED));
}
