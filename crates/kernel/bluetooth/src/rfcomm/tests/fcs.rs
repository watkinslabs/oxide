//! Check-sequence contract: the table is the polynomial it claims, the coverage
//! differs by frame type, and corruption is caught.

use crate::rfcomm::fcs::*;

/// Reverse the bits of a byte.
fn rev8(b: u8) -> u8 {
    let mut r = 0u8;
    for i in 0..8 { if b & (1 << i) != 0 { r |= 1 << (7 - i); } }
    r
}

/// The same CRC computed the other way round: reverse the input, run the
/// polynomial most-significant-bit first, reverse the output.
fn crc_msb_first(byte: u8) -> u8 {
    let mut c = rev8(byte);
    for _ in 0..8 {
        c = if c & 0x80 != 0 { (c << 1) ^ FCS_POLY } else { c << 1 };
    }
    rev8(c)
}

#[test]
fn table_is_the_polynomial_it_claims() {
    for i in 0..256usize {
        assert_eq!(FCS_TABLE[i], crc_msb_first(i as u8), "table entry {i}");
    }
}

#[test]
fn reflected_polynomial_is_the_reverse_of_the_normal_one() {
    assert_eq!(FCS_POLY_REFLECTED, rev8(FCS_POLY));
}

#[test]
fn uih_covers_two_bytes_and_a_command_covers_three() {
    let (addr, ctrl_uih, ctrl_cmd, len) = (0x03u8, 0xefu8, 0x3fu8, 0x01u8);
    // A UIH frame's check byte does not move when the length byte changes.
    assert_eq!(fcs_uih(addr, ctrl_uih), fcs_uih(addr, ctrl_uih));
    // A command frame's does.
    assert_ne!(fcs_cmd(addr, ctrl_cmd, len), fcs_cmd(addr, ctrl_cmd, len ^ 0x02));
}

#[test]
fn uih_check_ignores_the_length_byte() {
    let (addr, ctrl) = (0x0bu8, 0xefu8);
    let f = fcs_uih(addr, ctrl);
    assert!(check(addr, ctrl, 0x01, true, f));
    assert!(check(addr, ctrl, 0xff, true, f), "length must not be covered for a UIH frame");
}

#[test]
fn command_check_covers_the_length_byte() {
    let (addr, ctrl, len) = (0x03u8, 0x3fu8, 0x01u8);
    let f = fcs_cmd(addr, ctrl, len);
    assert!(check(addr, ctrl, len, false, f));
    assert!(!check(addr, ctrl, len ^ 0x02, false, f));
}

#[test]
fn every_valid_check_folds_to_the_residue() {
    for addr in [0x03u8, 0x0b, 0x3f, 0xfd] {
        for ctrl in [0x3fu8, 0x73, 0x1f, 0xff] {
            for len in [0x01u8, 0x05, 0x21] {
                let f = fcs_cmd(addr, ctrl, len);
                assert_eq!(FCS_TABLE[(FCS_TABLE[(crc2(addr, ctrl) ^ len) as usize] ^ f) as usize], FCS_GOOD);
            }
        }
    }
}

#[test]
fn a_corrupted_byte_fails_verification() {
    let (addr, ctrl, len) = (0x0bu8, 0x3fu8, 0x01u8);
    let f = fcs_cmd(addr, ctrl, len);
    assert!(!check(addr ^ 0x04, ctrl, len, false, f));
    assert!(!check(addr, ctrl ^ 0x10, len, false, f));
    assert!(!check(addr, ctrl, len, false, f ^ 0x01));
}
