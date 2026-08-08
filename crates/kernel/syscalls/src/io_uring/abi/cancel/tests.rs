use super::*;

fn key(flags: u32) -> CancelKey { CancelKey { flags, data: 7, fd: 3, opcode: 22 } }

#[test]
fn cancel_flag_values_are_the_uapi_bit_positions() {
    assert_eq!(IORING_ASYNC_CANCEL_ALL, 0x01);
    assert_eq!(IORING_ASYNC_CANCEL_FD, 0x02);
    assert_eq!(IORING_ASYNC_CANCEL_ANY, 0x04);
    assert_eq!(IORING_ASYNC_CANCEL_FD_FIXED, 0x08);
    assert_eq!(IORING_ASYNC_CANCEL_USERDATA, 0x10);
    assert_eq!(IORING_ASYNC_CANCEL_OP, 0x20);
    assert_eq!(CANCEL_FLAGS, 0x3f);
}

#[test]
fn the_default_key_is_user_data_alone() {
    let k = key(0);
    assert!(k.matches(7, 99, 99));
    assert!(!k.matches(8, 3, 22));
}

#[test]
fn naming_a_descriptor_replaces_the_user_data_match_rather_than_narrowing_it() {
    // The trap: treating FD as an EXTRA condition would make a cancel-by-fd
    // find nothing, because the caller has no user_data to give.
    let k = key(IORING_ASYNC_CANCEL_FD);
    assert!(!k.matches_user_data());
    assert!(k.matches(0xDEAD, 3, 99), "any user_data on fd 3 matches");
    assert!(!k.matches(7, 4, 22));
}

#[test]
fn asking_for_both_keys_requires_both_to_match() {
    let k = key(IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_USERDATA);
    assert!(k.matches_user_data());
    assert!(k.matches(7, 3, 99));
    assert!(!k.matches(8, 3, 99));
    assert!(!k.matches(7, 4, 99));
}

#[test]
fn the_opcode_key_behaves_like_the_descriptor_key() {
    let k = key(IORING_ASYNC_CANCEL_OP);
    assert!(!k.matches_user_data());
    assert!(k.matches(0xDEAD, 99, 22));
    assert!(!k.matches(7, 3, 23));
}

#[test]
fn any_matches_every_request_and_ignores_the_other_keys() {
    let k = key(IORING_ASYNC_CANCEL_ANY);
    assert!(k.matches(0, 0, 0));
    assert!(k.matches(u64::MAX, -1, 64));
    assert!(k.all());
}

#[test]
fn a_descriptor_or_opcode_key_cannot_be_combined_with_match_everything() {
    for f in [IORING_ASYNC_CANCEL_FD, IORING_ASYNC_CANCEL_OP] {
        let mut s = Sqe::default();
        s.op_flags = f | IORING_ASYNC_CANCEL_ANY;
        assert_eq!(prep_cancel(&s), Err(Errno::Einval));
    }
    // Together, without ANY, they are a legal two-part key.
    let mut s = Sqe::default();
    s.op_flags = IORING_ASYNC_CANCEL_FD | IORING_ASYNC_CANCEL_OP;
    s.len = 1;
    assert!(prep_cancel(&s).is_ok());
}

#[test]
fn an_opcode_key_must_name_a_defined_opcode() {
    let mut s = Sqe::default();
    s.op_flags = IORING_ASYNC_CANCEL_OP;
    s.len = OP_LAST as u32;
    assert_eq!(prep_cancel(&s), Err(Errno::Einval));
    s.len = OP_LAST as u32 - 1;
    assert_eq!(prep_cancel(&s).unwrap().opcode, OP_LAST - 1);
}

#[test]
fn a_cancel_takes_no_offset_no_splice_descriptor_and_no_provided_buffer() {
    use crate::io_uring_abi::ops::IOSQE_BUFFER_SELECT;
    for f in [|s: &mut Sqe| s.off = 1, |s: &mut Sqe| s.splice_fd_in = 1,
              |s: &mut Sqe| s.flags = IOSQE_BUFFER_SELECT] {
        let mut s = Sqe::default(); f(&mut s);
        assert_eq!(prep_cancel(&s), Err(Errno::Einval));
    }
}

#[test]
fn an_unknown_cancel_flag_is_refused() {
    let mut s = Sqe::default();
    s.op_flags = 1 << 6;
    assert_eq!(prep_cancel(&s), Err(Errno::Einval));
}

#[test]
fn the_reported_value_is_a_count_only_when_every_match_was_wanted() {
    let one = key(0);
    assert_eq!(cancel_result(&one, 1, 0), 0);
    assert_eq!(cancel_result(&one, 0, -2), -2);
    for f in [IORING_ASYNC_CANCEL_ALL, IORING_ASYNC_CANCEL_ANY] {
        let k = key(f);
        assert_eq!(cancel_result(&k, 3, -2), 3, "a count, not the last errno");
        assert_eq!(cancel_result(&k, 0, -2), 0, "finding none is a count of zero");
    }
}

/// A wire image of `struct io_uring_sync_cancel_reg`.
fn reg(addr: u64, fd: i32, flags: u32, ts: (i64, i64), opcode: u8) -> [u8; SYNC_CANCEL_BYTES] {
    let mut b = [0u8; SYNC_CANCEL_BYTES];
    b[0..8].copy_from_slice(&addr.to_le_bytes());
    b[8..12].copy_from_slice(&fd.to_le_bytes());
    b[12..16].copy_from_slice(&flags.to_le_bytes());
    b[16..24].copy_from_slice(&ts.0.to_le_bytes());
    b[24..32].copy_from_slice(&ts.1.to_le_bytes());
    b[32] = opcode;
    b
}

#[test]
fn the_sync_cancel_record_decodes_at_its_wire_offsets() {
    let b = reg(0xF00D, 9, IORING_ASYNC_CANCEL_FD, (1, 2), 22);
    let s = decode_sync_cancel(&b).unwrap();
    assert_eq!((s.key.data, s.key.fd, s.key.flags, s.key.opcode), (0xF00D, 9, IORING_ASYNC_CANCEL_FD, 22));
    assert_eq!(s.timeout, Some((1, 2)));
    assert_eq!(SYNC_CANCEL_BYTES, 64);
}

#[test]
fn the_all_ones_timespec_means_no_deadline_at_all() {
    let b = reg(1, 0, 0, SYNC_CANCEL_NO_TIMEOUT, 0);
    assert_eq!(decode_sync_cancel(&b).unwrap().timeout, None);
    let b = reg(1, 0, 0, (0, 0), 0);
    assert_eq!(decode_sync_cancel(&b).unwrap().timeout, Some((0, 0)),
               "a zero timespec is a real zero deadline, not the sentinel");
}

#[test]
fn a_nonzero_pad_byte_is_refused_so_the_record_can_grow() {
    for off in [33usize, 39, 40, 63] {
        let mut b = reg(1, 0, 0, (0, 0), 0);
        b[off] = 1;
        assert_eq!(decode_sync_cancel(&b), Err(Errno::Einval), "pad byte {}", off);
    }
}

#[test]
fn an_unknown_sync_cancel_flag_is_refused() {
    let b = reg(1, 0, 1 << 6, (0, 0), 0);
    assert_eq!(decode_sync_cancel(&b), Err(Errno::Einval));
}

#[test]
fn finding_nothing_to_cancel_is_a_success_for_the_registration_form() {
    assert_eq!(sync_cancel_result(-(Errno::Enoent.as_i32() as i64)), 0);
    assert_eq!(sync_cancel_result(3), 0, "a count means the work is gone");
    assert_eq!(sync_cancel_result(0), 0);
    assert_eq!(sync_cancel_result(-(Errno::Etime.as_i32() as i64)),
               -(Errno::Etime.as_i32() as i64), "a deadline that ran out is not success");
}
