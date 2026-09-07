//! Startup-info flag updates report the value that was in force.
use super::*;

#[test]
fn a_masked_update_clears_the_named_bits_then_adds_the_new_ones() {
    assert_eq!(modify(0b1010, 0b0110, 0b0100), 0b1100);
    assert_eq!(modify(0b1010, u32::MAX, 0b0011), 0b0011);
    assert_eq!(modify(0, 0b0001, 0b0001), 0b0001);
}

#[test]
fn flags_outside_the_mask_are_still_added() {
    // The update is a clear of the mask followed by a set of every named flag,
    // so a flag the mask does not cover is set all the same.
    assert_eq!(modify(0b1010, 0, 0b0101), 0b1111);
    assert_eq!(modify(0b1010, 0, 0), 0b1010);
}
