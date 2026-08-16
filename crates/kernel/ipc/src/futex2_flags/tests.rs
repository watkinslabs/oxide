// futex2 flag-word admission ladder. Provenance for the verified contract:
// the accepted bit set, the one implemented size class, the NUMA node-id
// width rule, and the no-truncation rule for oversized operands.

use super::*;

#[test]
fn only_the_32_bit_size_class_is_served() {
    assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32),
               Ok(Futex2Flags { size_bytes: 4, private: false, numa: false, mpol: false }));
    // The other three classes are reserved, not served at some other width:
    // a caller that asked for a 64-bit futex must be told no, never handed a
    // 32-bit one that compares half its value.
    for sz in [FUTEX2_SIZE_U8, FUTEX2_SIZE_U16, FUTEX2_SIZE_U64] {
        assert_eq!(validate_futex2_flags(sz), Err(Futex2Reject::UnsupportedSize));
    }
}

#[test]
fn private_bit_is_decoded_not_rejected() {
    assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | FUTEX2_PRIVATE),
               Ok(Futex2Flags { size_bytes: 4, private: true, numa: false, mpol: false }));
}

#[test]
fn bits_outside_the_valid_mask_are_rejected() {
    assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | 0x10), Err(Futex2Reject::UnknownBit));
    assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | 0x20), Err(Futex2Reject::UnknownBit));
    assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | 0x40), Err(Futex2Reject::UnknownBit));
    assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | 0x8000_0000), Err(Futex2Reject::UnknownBit));
}

#[test]
fn numa_and_mpol_are_accepted_and_decoded() {
    assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | FUTEX2_NUMA),
               Ok(Futex2Flags { size_bytes: 4, private: false, numa: true, mpol: false }));
    assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | FUTEX2_MPOL),
               Ok(Futex2Flags { size_bytes: 4, private: false, numa: false, mpol: true }));
    assert_eq!(validate_futex2_flags(FUTEX2_SIZE_U32 | FUTEX2_NUMA | FUTEX2_MPOL | FUTEX2_PRIVATE),
               Ok(Futex2Flags { size_bytes: 4, private: true, numa: true, mpol: true }));
}

#[test]
fn numa_doubles_the_operand_and_nothing_else_does() {
    let plain = validate_futex2_flags(FUTEX2_SIZE_U32).unwrap();
    assert_eq!(plain.access_bytes(), 4);
    let mpol = validate_futex2_flags(FUTEX2_SIZE_U32 | FUTEX2_MPOL).unwrap();
    assert_eq!(mpol.access_bytes(), 4, "MPOL carries no second word");
    let numa = validate_futex2_flags(FUTEX2_SIZE_U32 | FUTEX2_NUMA).unwrap();
    assert_eq!(numa.access_bytes(), 8, "the node-id word follows the futex word");
}

#[test]
fn a_futex_word_must_out_represent_the_node_count() {
    // A node count equal to the sentinel value would make a real node id
    // indistinguishable from FUTEX_NO_NODE, so the rule is strict.
    assert!(numa_node_id_fits(4));
    assert!(numa_node_id_fits(8));
    // 1 and 2 byte words also out-represent a single-node machine; the size
    // class is refused earlier, so this only pins the width rule itself.
    assert!(numa_node_id_fits(1));
    assert!(numa_node_id_fits(2));
}

#[test]
fn a_value_wider_than_the_futex_word_is_rejected_not_truncated() {
    assert!(validate_futex2_input(4, 0xffff_ffff));
    assert!(!validate_futex2_input(4, 0x1_0000_0000),
            "a 33-bit val on a 32-bit futex must be EINVAL, not a silent truncation to 0");
    assert!(!validate_futex2_input(4, 1u64 << 40));
    assert!(validate_futex2_input(8, u64::MAX));
}
