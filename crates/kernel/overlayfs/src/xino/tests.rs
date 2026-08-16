//! Inode-number remapping.

use super::{overflows, remap, spare_bits, Mode};

#[test]
fn a_small_number_gets_its_layer_tag() {
    // With four tag bits the shift is 60, and the lowest tag bit is reserved,
    // so layer 1 lands at bit 61.
    assert_eq!(remap(7, 4, 1), 7 | (1u64 << 61));
    assert_eq!(remap(7, 4, 2), 7 | (2u64 << 61));
}

#[test]
fn layer_zero_is_left_alone() {
    assert_eq!(remap(7, 4, 0), 7);
}

#[test]
fn two_layers_stop_colliding() {
    assert_ne!(remap(42, 4, 1), remap(42, 4, 2));
}

#[test]
fn a_number_too_large_to_tag_is_returned_unchanged() {
    // Changing it would be worse than a duplicate: a program holding the old
    // number would see the file's identity change under it.
    let big = 1u64 << 61;
    assert_eq!(remap(big, 4, 1), big);
    assert!(overflows(big, 4));
    assert!(!overflows(7, 4));
}

#[test]
fn no_bits_means_no_remap() {
    assert_eq!(remap(7, 0, 3), 7);
    assert!(!overflows(u64::MAX, 0));
}

#[test]
fn spare_bits_counts_the_unused_high_end() {
    assert_eq!(spare_bits(u32::MAX as u64), 32);
    assert_eq!(spare_bits(u64::MAX), 0);
    assert_eq!(spare_bits(1), 63);
}

#[test]
fn the_mode_says_what_the_mount_will_do() {
    assert!(Mode::SameFs.same_fs());
    assert!(Mode::SameFs.same_dev());
    assert_eq!(Mode::SameFs.bits(), 0);
    assert!(Mode::Bits(4).same_dev());
    assert!(!Mode::Bits(4).same_fs());
    assert_eq!(Mode::Bits(4).bits(), 4);
    assert!(!Mode::Off.same_dev());
}
