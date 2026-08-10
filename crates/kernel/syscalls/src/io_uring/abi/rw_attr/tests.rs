// The attribute vector a read or write entry carries: its wire form, its mask
// ladder, and which descriptions can serve it.

use super::*;
use crate::io_uring_abi::ops::{IORING_OP_FSYNC, IORING_OP_READ, IORING_OP_READV,
                               IORING_OP_READ_FIXED, IORING_OP_RECV, IORING_OP_SEND,
                               IORING_OP_WRITE, IORING_OP_WRITEV, IORING_OP_WRITE_FIXED};

/// `struct io_uring_attr_pi`: flags, app_tag, len, addr, seed, reserved.
fn wire(flags: u16, app_tag: u16, len: u32, addr: u64, seed: u64, rsvd: u64)
    -> [u8; ATTR_PI_BYTES]
{
    let mut b = [0u8; ATTR_PI_BYTES];
    b[0..2].copy_from_slice(&flags.to_le_bytes());
    b[2..4].copy_from_slice(&app_tag.to_le_bytes());
    b[4..8].copy_from_slice(&len.to_le_bytes());
    b[8..16].copy_from_slice(&addr.to_le_bytes());
    b[16..24].copy_from_slice(&seed.to_le_bytes());
    b[24..32].copy_from_slice(&rsvd.to_le_bytes());
    b
}

/// The record is 32 bytes and every field sits where the wire says.
#[test]
fn the_attribute_record_decodes_at_its_wire_offsets() {
    let b = wire(0xabcd, 0x1234, 0x4000, 0xdead_beef_0000, 0x99, 0);
    let pi = parse_pi(&b).expect("decode");
    assert_eq!(pi, AttrPi { flags: 0xabcd, app_tag: 0x1234, len: 0x4000,
                            addr: 0xdead_beef_0000, seed: 0x99 });
    assert_eq!(ATTR_PI_BYTES, 32);
}

/// The reserved word is where a later attribute type grows. A caller that set
/// it expects something this kernel would silently drop, so it is refused.
#[test]
fn a_non_zero_reserved_word_is_refused() {
    assert_eq!(parse_pi(&wire(0, 0, 0, 0, 0, 1)), Err(Errno::Einval));
    assert_eq!(parse_pi(&wire(0, 0, 0, 0, 0, u64::MAX)), Err(Errno::Einval));
    assert!(parse_pi(&wire(0, 0, 0, 0, 0, 0)).is_ok());
}

/// An absent mask means no attribute; the one defined type is honoured; any
/// other value is a guarantee this kernel would not give, so it is refused
/// rather than masked down to the bit it recognises.
#[test]
fn the_mask_names_exactly_one_type_or_none() {
    assert_eq!(wants_attr(0), Ok(false));
    assert_eq!(wants_attr(IORING_RW_ATTR_FLAG_PI), Ok(true));
    assert_eq!(wants_attr(1 << 1), Err(Errno::Einval));
    assert_eq!(wants_attr(IORING_RW_ATTR_FLAG_PI | (1 << 1)), Err(Errno::Einval));
    assert_eq!(wants_attr(u64::MAX), Err(Errno::Einval));
    assert_eq!(wants_attr(1u64 << 63), Err(Errno::Einval));
}

/// Only the transfer opcodes read those two words; on every other opcode they
/// carry that opcode's own operands, so reading a mask there would be reading
/// somebody else's field.
#[test]
fn only_a_transfer_entry_carries_an_attribute_vector() {
    for op in [IORING_OP_READ, IORING_OP_WRITE, IORING_OP_READV, IORING_OP_WRITEV,
               IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED] {
        assert!(op_takes_attr(op), "opcode {op}");
    }
    for op in [IORING_OP_FSYNC, IORING_OP_SEND, IORING_OP_RECV] {
        assert!(!op_takes_attr(op), "opcode {op}");
    }
}

/// Two different refusals, and the difference is the point. A target with no
/// integrity metadata cannot serve the request in ANY configuration — the
/// entry is malformed. A target that has it, being reached through the page
/// cache, could serve the request on another description — so the caller is
/// told the operation is not supported HERE, not that it was wrong.
#[test]
fn a_target_without_integrity_metadata_is_a_different_refusal_from_a_cached_one() {
    assert_eq!(admit_target(false, true), Err(Errno::Einval));
    assert_eq!(admit_target(false, false), Err(Errno::Einval));
    assert_eq!(admit_target(true, false), Err(Errno::Eopnotsupp));
    assert_eq!(admit_target(true, true), Ok(()));
}
