//! The published substitution table against its closed form.

use crate::sbox::{sbox_of, sub_byte, SBOX};

#[test]
fn table_matches_closed_form() {
    for x in 0..=255u8 { assert_eq!(SBOX[x as usize], sbox_of(x), "entry {x:#04x}"); }
}

#[test]
fn table_is_a_permutation() {
    let mut seen = [false; 256];
    for x in 0..=255u8 {
        let y = SBOX[x as usize] as usize;
        assert!(!seen[y], "value {y:#04x} appears twice");
        seen[y] = true;
    }
}

#[test]
fn published_corner_entries() {
    assert_eq!(sub_byte(0x00), 0xd6);
    assert_eq!(sub_byte(0x0f), 0x05);
    assert_eq!(sub_byte(0xf0), 0x18);
    assert_eq!(sub_byte(0xff), 0x48);
}
