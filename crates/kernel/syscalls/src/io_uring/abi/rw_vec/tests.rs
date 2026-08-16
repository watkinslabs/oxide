use super::*;
use crate::io_uring_abi::ops::IOSQE_BUFFER_SELECT;

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
fn an_empty_or_oversized_vector_is_refused() {
    let mut s = rv();
    s.len = 0;
    assert_eq!(prep_vec_fixed(&s), Err(Errno::Einval));
    s.len = UIO_MAXIOV + 1;
    assert_eq!(prep_vec_fixed(&s), Err(Errno::Einval));
    s.len = UIO_MAXIOV;
    assert!(prep_vec_fixed(&s).is_ok());
}

/// `buf_index` and `buf_group` are the SAME field. An entry that also asks for
/// a provided buffer would have it read as a group by the selection path and
/// as a registration by this one — two different buffers for one transfer,
/// with whichever ran second winning silently.
#[test]
fn a_provided_buffer_group_and_a_registration_cannot_both_be_named() {
    let mut s = rv();
    s.flags = IOSQE_BUFFER_SELECT;
    assert_eq!(prep_vec_fixed(&s), Err(Errno::Einval));
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
