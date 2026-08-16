//! The inode block, and the address array's real extent.
//!
//! The arithmetic here is the one nearly every read depends on. Both
//! carve-outs are exercised alone and together, and each is checked against a
//! NUMBER rather than against the same expression the code uses, so a change
//! to the formula shows up.

use super::*;
use crate::test_image::nodes::{self, Spec};
use crate::test_image::{Builder, DEFAULT_FEATURE};

/// An inode block for `s`, plus the feature word it should be read under.
fn block_for(s: &Spec) -> alloc::vec::Vec<u8> { nodes::inode_block(s) }

#[test]
fn the_nominal_widths_are_what_the_format_defines() {
    assert_eq!(DEF_ADDRS_PER_INODE, 923);
    assert_eq!(OFFSET_OF_END_OF_I_EXT, 360);
    assert_eq!(I_NID_OFF, 360 + 923 * 4);
    assert_eq!(I_NID_OFF + DEF_NIDS_PER_INODE * 4, NODE_FOOTER_OFF);
    assert_eq!(TOTAL_EXTRA_ATTR_SIZE, 36);
}

#[test]
fn a_fixture_inode_parses_and_passes_sanity() {
    let s = Spec::file(4);
    let b = block_for(&s);
    let i = parse(&b, DEFAULT_FEATURE).unwrap();
    let mut i2 = i.clone();
    i2.blocks = 1;
    assert_eq!(sanity(&i2, 4, DEFAULT_FEATURE), Ok(()));
}

#[test]
fn the_stored_fields_read_back() {
    let mut s = Spec::file(4);
    s.size = 4321;
    s.links = 3;
    let i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    assert_eq!(i.mode, crate::mode::S_IFREG | 0o644);
    assert_eq!(i.size, 4321);
    assert_eq!(i.links, 3);
    assert_eq!(i.uid, 1000);
    assert_eq!(i.gid, 1000);
    assert_eq!(i.atime, (1_700_000_001, 11));
    assert_eq!(i.ctime, (1_700_000_002, 22));
    assert_eq!(i.mtime, (1_700_000_003, 33));
}

#[test]
fn the_creation_time_is_read_only_when_the_volume_keeps_one() {
    let s = Spec::file(4);
    let b = block_for(&s);
    assert_eq!(parse(&b, DEFAULT_FEATURE).unwrap().crtime, Some((1_700_000_000, 44)));
    let without = DEFAULT_FEATURE & !FEATURE_INODE_CRTIME;
    assert_eq!(parse(&b, without).unwrap().crtime, None);
}

#[test]
fn a_creation_time_the_extra_region_is_too_narrow_for_is_not_read() {
    let mut s = Spec::file(4);
    s.extra_isize = 8;
    let i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    assert_eq!(i.crtime, None);
}

#[test]
fn without_the_extra_attribute_feature_the_region_is_not_read_at_all() {
    let s = Spec::file(4);
    let i = parse(&block_for(&s), 0).unwrap();
    assert_eq!(i.extra_isize, 0);
    assert_eq!(i.addr_base(), OFFSET_OF_END_OF_I_EXT);
}

#[test]
fn the_extra_region_shifts_the_address_array_head() {
    let s = Spec::file(4);
    let i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    assert_eq!(i.extra_isize, 36);
    assert_eq!(i.addr_base(), 360 + 36);
}

#[test]
fn the_two_carve_outs_together_give_the_usable_width() {
    let s = Spec::file(4);
    let i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    // 923 nominal, less 36/4 = 9 for the extra region, less 50 reserved.
    assert_eq!(i.addrs_per_inode(), 864);
}

#[test]
fn without_either_carve_out_the_width_is_the_nominal_one() {
    let mut s = Spec::file(4);
    s.extra_isize = 0;
    s.inline_xattr_addrs = 0;
    s.inline = 0;
    let i = parse(&block_for(&s), 0).unwrap();
    assert_eq!(i.addrs_per_inode(), DEF_ADDRS_PER_INODE);
}

#[test]
fn the_reservation_defaults_to_the_fixed_size_without_the_flexible_feature() {
    // An inode with inline entries reserves the fixed amount even when the
    // volume states nothing, because the entry layout was defined around it.
    let mut s = Spec::file(4);
    s.inline |= INLINE_DENTRY;
    let i = parse(&block_for(&s), FEATURE_EXTRA_ATTR).unwrap();
    assert_eq!(i.inline_xattr_addrs, DEFAULT_INLINE_XATTR_ADDRS);
}

#[test]
fn an_inode_with_neither_inline_flag_reserves_nothing_without_the_feature() {
    let s = Spec::file(4);
    let i = parse(&block_for(&s), FEATURE_EXTRA_ATTR).unwrap();
    assert_eq!(i.inline_xattr_addrs, 0);
    assert_eq!(i.addrs_per_inode(), DEF_ADDRS_PER_INODE - 9);
}

#[test]
fn the_flexible_feature_takes_the_inodes_own_number() {
    let mut s = Spec::file(4);
    s.inline_xattr_addrs = 17;
    let i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    assert_eq!(i.inline_xattr_addrs, 17);
    assert_eq!(i.addrs_per_inode(), 923 - 9 - 17);
}

#[test]
fn an_address_is_read_from_the_shifted_base() {
    let s = Spec::file(4);
    let mut b = block_for(&s);
    let base = 360 + 36;
    b[base..base + 4].copy_from_slice(&4242u32.to_le_bytes());
    let i = parse(&b, DEFAULT_FEATURE).unwrap();
    assert_eq!(i.addr(&b, 0), Some(4242));
    // The nominal base holds the extra attributes, not an address.
    assert_ne!(u32::from_le_bytes(b[360..364].try_into().unwrap()), 4242);
}

#[test]
fn an_address_past_the_usable_width_is_refused() {
    let s = Spec::file(4);
    let b = block_for(&s);
    let i = parse(&b, DEFAULT_FEATURE).unwrap();
    assert!(i.addr(&b, 863).is_some());
    assert!(i.addr(&b, 864).is_none());
}

#[test]
fn the_last_usable_address_stops_before_the_reservation() {
    let s = Spec::file(4);
    let i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    let last_end = i.addr_base() + i.addrs_per_inode() * 4;
    let (xattr_at, _) = (OFFSET_OF_END_OF_I_EXT + (DEF_ADDRS_PER_INODE - 50) * 4, 0);
    assert_eq!(last_end, xattr_at);
}

#[test]
fn the_inline_region_is_anchored_to_the_nominal_end_not_the_usable_one() {
    // The region does not move when the extra attributes grow; anchoring it to
    // the usable end would slide it by nine slots.
    let mut s = Spec::file(4);
    s.inline |= INLINE_XATTR;
    let wide = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    s.extra_isize = 8;
    let narrow = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    assert_eq!(wide.inline_xattr_span(), narrow.inline_xattr_span());
    assert_eq!(wide.inline_xattr_span(), Some((360 + (923 - 50) * 4, 200)));
}

#[test]
fn an_inode_without_the_inline_attribute_flag_has_no_region() {
    let s = Spec::file(4);
    let i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    assert_eq!(i.inline_xattr_span(), None);
}

#[test]
fn the_inline_data_region_starts_one_slot_past_the_base() {
    let s = Spec::file(4);
    let i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    assert_eq!(i.inline_data_span(), (360 + 36 + 4, (864 - 1) * 4));
}

#[test]
fn the_inline_data_region_ends_where_the_reservation_begins() {
    let s = Spec::file(4);
    let i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    let (at, len) = i.inline_data_span();
    assert_eq!(at + len, OFFSET_OF_END_OF_I_EXT + (DEF_ADDRS_PER_INODE - 50) * 4);
}

#[test]
fn the_five_node_slots_read_from_the_arrays_fixed_end() {
    let s = Spec::file(4);
    let mut b = block_for(&s);
    for slot in 0..DEF_NIDS_PER_INODE {
        b[I_NID_OFF + slot * 4..I_NID_OFF + slot * 4 + 4]
            .copy_from_slice(&(100 + slot as u32).to_le_bytes());
    }
    let i = parse(&b, DEFAULT_FEATURE).unwrap();
    assert_eq!(i.nid(&b, 0), Some(100));
    assert_eq!(i.nid(&b, 4), Some(104));
    assert_eq!(i.nid(&b, 5), None);
}

#[test]
fn the_node_slots_do_not_move_with_the_extra_region() {
    // They are anchored to the block's end, not to the array's base.
    let mut s = Spec::file(4);
    s.extra_isize = 8;
    let b = block_for(&s);
    let i = parse(&b, DEFAULT_FEATURE).unwrap();
    assert_eq!(i.addr_base(), 368);
    assert_eq!(I_NID_OFF, 4052);
    assert!(i.nid(&b, 4).is_some());
}

#[test]
fn the_inline_flags_read_back() {
    let mut s = Spec::file(4);
    s.inline |= INLINE_DATA | DATA_EXIST | INLINE_DENTRY;
    let i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    assert!(i.inline_data());
    assert!(i.inline_dentry());
    assert!(i.has(DATA_EXIST));
    assert!(i.has(EXTRA_ATTR));
}

#[test]
fn the_attribute_flags_read_back() {
    let mut s = Spec::file(4);
    s.flags = F2FS_COMPR_FL | F2FS_ENCRYPT_FL | F2FS_CASEFOLD_FL;
    let i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    assert!(i.compressed());
    assert!(i.encrypted());
    assert!(i.casefolded());
}

#[test]
fn a_zero_block_count_fails_sanity() {
    // The count includes the inode's own block, so zero means the inode was
    // never written and every address in it is stale.
    let s = Spec::file(4);
    let mut i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    i.blocks = 0;
    assert!(sanity(&i, 4, DEFAULT_FEATURE).is_err());
}

#[test]
fn an_attribute_node_equal_to_the_inode_fails_sanity() {
    let s = Spec::file(4);
    let mut i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    i.blocks = 1;
    i.xattr_nid = 4;
    assert!(sanity(&i, 4, DEFAULT_FEATURE).is_err());
}

#[test]
fn an_extra_region_wider_than_the_layout_fails_sanity() {
    let s = Spec::file(4);
    let mut i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    i.blocks = 1;
    i.extra_isize = TOTAL_EXTRA_ATTR_SIZE + 4;
    assert!(sanity(&i, 4, DEFAULT_FEATURE).is_err());
}

#[test]
fn an_extra_region_narrower_than_the_minimum_fails_sanity() {
    let s = Spec::file(4);
    let mut i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    i.blocks = 1;
    i.extra_isize = 2;
    assert!(sanity(&i, 4, DEFAULT_FEATURE).is_err());
}

#[test]
fn an_extra_region_not_a_multiple_of_four_fails_sanity() {
    let s = Spec::file(4);
    let mut i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    i.blocks = 1;
    i.extra_isize = 10;
    assert!(sanity(&i, 4, DEFAULT_FEATURE).is_err());
}

#[test]
fn an_inode_claiming_the_region_on_a_volume_without_it_fails_sanity() {
    let s = Spec::file(4);
    let mut i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    i.blocks = 1;
    assert!(sanity(&i, 4, 0).is_err());
}

#[test]
fn a_reservation_wider_than_the_array_fails_sanity() {
    let s = Spec::file(4);
    let mut i = parse(&block_for(&s), DEFAULT_FEATURE).unwrap();
    i.blocks = 1;
    i.inline_xattr_addrs = DEF_ADDRS_PER_INODE;
    assert!(sanity(&i, 4, DEFAULT_FEATURE).is_err());
}

#[test]
fn a_sealed_inode_passes_its_checksum() {
    let mut b = Builder::new();
    let s = Spec::file(4);
    nodes::place_inode(&mut b, &s, nodes::inode_block(&s), 1);
    let addr = b.nat[0].1.block_addr;
    let block = b.block(addr).to_vec();
    let i = parse(&block, DEFAULT_FEATURE).unwrap();
    let seed = crate::checksum::inode_seed(&b.uuid);
    assert!(checksum_ok(&i, &block, seed, DEFAULT_FEATURE));
}

#[test]
fn a_changed_inode_fails_its_checksum() {
    let mut b = Builder::new();
    let s = Spec::file(4);
    nodes::place_inode(&mut b, &s, nodes::inode_block(&s), 1);
    let addr = b.nat[0].1.block_addr;
    let mut block = b.block(addr).to_vec();
    block[I_SIZE] ^= 0xFF;
    let i = parse(&block, DEFAULT_FEATURE).unwrap();
    let seed = crate::checksum::inode_seed(&b.uuid);
    assert!(!checksum_ok(&i, &block, seed, DEFAULT_FEATURE));
}

#[test]
fn a_volume_without_inode_checksums_does_not_check_one() {
    let s = Spec::file(4);
    let block = block_for(&s);
    let i = parse(&block, DEFAULT_FEATURE).unwrap();
    assert!(checksum_ok(&i, &block, 1, DEFAULT_FEATURE & !FEATURE_INODE_CHKSUM));
}

#[test]
fn an_inode_without_the_extra_region_does_not_check_one() {
    let mut s = Spec::file(4);
    s.inline = 0;
    s.extra_isize = 0;
    let block = block_for(&s);
    let i = parse(&block, DEFAULT_FEATURE).unwrap();
    assert!(checksum_ok(&i, &block, 1, DEFAULT_FEATURE));
}

#[test]
fn a_short_block_does_not_parse() {
    assert_eq!(parse(&[0u8; 100], DEFAULT_FEATURE), None);
}
