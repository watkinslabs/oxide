use super::*;
use net::socket_args::{parse_accept_flags, SOCK_CLOEXEC, SOCK_NONBLOCK};

/// Build a wire SQE by writing one field at its documented offset.
fn wire(off: usize, bytes: &[u8]) -> [u8; SQE_BYTES] {
    let mut b = [0u8; SQE_BYTES];
    b[off..off + bytes.len()].copy_from_slice(bytes);
    b
}

#[test]
fn every_field_decodes_at_its_wire_offset() {
    assert_eq!(Sqe::from_bytes(&wire(0, &[7u8])).opcode, 7);
    assert_eq!(Sqe::from_bytes(&wire(1, &[3u8])).flags, 3);
    assert_eq!(Sqe::from_bytes(&wire(2, &9u16.to_le_bytes())).ioprio, 9);
    assert_eq!(Sqe::from_bytes(&wire(4, &(-1i32).to_le_bytes())).fd, -1);
    assert_eq!(Sqe::from_bytes(&wire(8, &0x1122u64.to_le_bytes())).off, 0x1122);
    assert_eq!(Sqe::from_bytes(&wire(16, &0x3344u64.to_le_bytes())).addr, 0x3344);
    assert_eq!(Sqe::from_bytes(&wire(24, &55u32.to_le_bytes())).len, 55);
    assert_eq!(Sqe::from_bytes(&wire(28, &0x77u32.to_le_bytes())).op_flags, 0x77);
    assert_eq!(Sqe::from_bytes(&wire(32, &0xF00Du64.to_le_bytes())).user_data, 0xF00D);
    assert_eq!(Sqe::from_bytes(&wire(40, &12u16.to_le_bytes())).buf_index, 12);
    assert_eq!(Sqe::from_bytes(&wire(42, &34u16.to_le_bytes())).personality, 34);
    assert_eq!(Sqe::from_bytes(&wire(44, &(-2i32).to_le_bytes())).splice_fd_in, -2);
    assert_eq!(Sqe::from_bytes(&wire(48, &0xBEEFu64.to_le_bytes())).addr3, 0xBEEF);
}

#[test]
fn addr_len_and_file_index_share_the_splice_fd_word() {
    // One 32-bit word, read three ways. Reading `addr_len` from `len` — the
    // obvious-looking wrong offset — would take a byte count as an address
    // length.
    let s = Sqe::from_bytes(&wire(44, &0x0001_0010u32.to_le_bytes()));
    assert_eq!(s.addr_len, 0x0010);
    assert_eq!(s.file_index(), 0x0001_0010);
    assert_eq!(s.splice_fd_in, 0x0001_0010);
}

#[test]
fn personality_does_not_alias_the_buffer_index() {
    let mut b = [0u8; SQE_BYTES];
    b[40..42].copy_from_slice(&5u16.to_le_bytes());
    b[42..44].copy_from_slice(&6u16.to_le_bytes());
    let s = Sqe::from_bytes(&b);
    assert_eq!((s.buf_index, s.personality), (5, 6));
}

#[test]
fn accept_uses_addr2_for_addrlen_and_accept_flags_for_descriptor_state() {
    let flags = SOCK_CLOEXEC | SOCK_NONBLOCK;
    let mut s = Sqe::default();
    s.fd = 7; s.off = 0x2222; s.addr = 0x1111; s.op_flags = flags;
    let args = s.accept_args(9);
    assert_eq!((args.a0, args.a1, args.a2, args.a3), (9, 0x1111, 0x2222, flags as u64));
    let parsed = parse_accept_flags(args.a3).unwrap();
    assert!(parsed.cloexec);
    assert!(parsed.nonblock);
}

#[test]
fn accept_does_not_take_flags_or_addrlen_from_len() {
    let mut s = Sqe::default();
    s.fd = 7; s.off = 0x3333; s.addr = 0x1111; s.len = u32::MAX;
    let args = s.accept_args(7);
    assert_eq!(args.a2, 0x3333);
    assert_eq!(args.a3, 0);
    assert!(!parse_accept_flags(args.a3).unwrap().cloexec);
}
