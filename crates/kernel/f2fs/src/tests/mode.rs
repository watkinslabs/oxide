//! The stored mode word, and the device number beside it.

use super::*;
use alloc::vec;

#[test]
fn each_type_field_maps_to_its_own_kind() {
    assert_eq!(file_type(S_IFREG | 0o644), FileType::Regular);
    assert_eq!(file_type(S_IFDIR | 0o755), FileType::Directory);
    assert_eq!(file_type(S_IFLNK | 0o777), FileType::Symlink);
    assert_eq!(file_type(S_IFCHR | 0o600), FileType::CharDev);
    assert_eq!(file_type(S_IFBLK | 0o660), FileType::BlockDev);
    assert_eq!(file_type(S_IFIFO | 0o644), FileType::Fifo);
    assert_eq!(file_type(S_IFSOCK | 0o777), FileType::Socket);
}

#[test]
fn the_permission_bits_do_not_disturb_the_type() {
    for perm in [0u16, 0o777, 0o7777] {
        assert_eq!(file_type(S_IFDIR | perm), FileType::Directory);
    }
}

#[test]
fn the_permission_bits_include_the_set_id_and_sticky_bits() {
    assert_eq!(perm(S_IFREG | 0o4755), 0o4755);
    assert_eq!(perm(S_IFDIR | 0o1777), 0o1777);
    assert_eq!(PERM_MASK, 0o7777);
}

#[test]
fn the_type_field_is_not_part_of_the_permission_bits() {
    assert_eq!(perm(S_IFREG), 0);
}

#[test]
fn only_the_four_special_kinds_carry_a_device_number() {
    assert!(has_rdev(S_IFCHR));
    assert!(has_rdev(S_IFBLK));
    assert!(has_rdev(S_IFIFO));
    assert!(has_rdev(S_IFSOCK));
    assert!(!has_rdev(S_IFREG));
    assert!(!has_rdev(S_IFDIR));
    assert!(!has_rdev(S_IFLNK));
}

#[test]
fn a_zero_first_slot_sends_the_reader_to_the_wide_second_one() {
    // Reading only the first returns zero for every device made since the
    // wide form arrived.
    let mut b = vec![0u8; 64];
    let wide = vfs::getattr::encode_dev(8, 300);
    b[4..8].copy_from_slice(&wide.to_le_bytes());
    assert_eq!(rdev(0, &b), wide);
}

#[test]
fn a_nonzero_first_slot_is_the_narrow_form() {
    let mut b = vec![0u8; 64];
    // Major five, minor seven, packed one byte each.
    b[0..4].copy_from_slice(&((5u32 << 8) | 7).to_le_bytes());
    assert_eq!(rdev(0, &b), vfs::getattr::encode_dev(5, 7));
}

#[test]
fn the_narrow_form_cannot_carry_a_minor_past_a_byte() {
    // Which is exactly why the wide slot exists.
    assert_eq!(decode_old((5 << 8) | 0xFF), vfs::getattr::encode_dev(5, 255));
    assert_ne!(decode_old(0xFFFF), vfs::getattr::encode_dev(255, 256));
}

#[test]
fn the_device_number_is_read_from_the_shifted_base() {
    let mut b = vec![0u8; 512];
    let base = 396;
    b[base..base + 4].copy_from_slice(&((3u32 << 8) | 4).to_le_bytes());
    assert_eq!(rdev(base, &b), vfs::getattr::encode_dev(3, 4));
    // The nominal base holds something else entirely.
    assert_eq!(rdev(360, &b), 0);
}

#[test]
fn both_slots_zero_reports_no_device() {
    assert_eq!(rdev(0, &vec![0u8; 64]), 0);
}

#[test]
fn a_base_past_the_block_reports_no_device_rather_than_panicking() {
    assert_eq!(rdev(4096, &vec![0u8; 64]), 0);
}
