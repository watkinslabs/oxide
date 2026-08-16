//! The substitution table is derived, not transcribed, so the published
//! entries are the check that the derivation matches the standard.

use crate::sbox::{SBOX, gmul, sub_byte, xtime};

#[test]
fn field_double_reduces_on_carry() {
    assert_eq!(xtime(0x01), 0x02);
    assert_eq!(xtime(0x40), 0x80);
    assert_eq!(xtime(0x80), 0x1b);
    assert_eq!(xtime(0xff), 0xe5);
}

#[test]
fn field_multiply_matches_worked_examples() {
    assert_eq!(gmul(0x57, 0x83), 0xc1);
    assert_eq!(gmul(0x57, 0x13), 0xfe);
    assert_eq!(gmul(0x00, 0xff), 0x00);
    assert_eq!(gmul(0x01, 0xa5), 0xa5);
}

#[test]
fn sbox_matches_published_entries() {
    // Corner and interior entries of the standard table.
    assert_eq!(sub_byte(0x00), 0x63);
    assert_eq!(sub_byte(0x01), 0x7c);
    assert_eq!(sub_byte(0x10), 0xca);
    assert_eq!(sub_byte(0x53), 0xed);
    assert_eq!(sub_byte(0x7f), 0xd2);
    assert_eq!(sub_byte(0xc4), 0x1c);
    assert_eq!(sub_byte(0xff), 0x16);
}

#[test]
fn sbox_is_a_permutation() {
    let mut seen = [false; 256];
    for i in 0..256 { seen[SBOX[i] as usize] = true; }
    assert!(seen.iter().all(|s| *s));
}
