//! Free space, the segment table, and attribute regions.

use super::*;
use crate::test_image::nodes::dir::add_file_with_xattrs;
use crate::uapi::{XATTR_INDEX_SECURITY, XATTR_INDEX_TRUSTED, XATTR_INDEX_USER};
use alloc::vec;
use alloc::vec::Vec;

fn attr(index: u8, name: &str, value: &str) -> (u8, Vec<u8>, Vec<u8>) {
    (index, name.as_bytes().to_vec(), value.as_bytes().to_vec())
}

#[test]
fn the_reported_total_excludes_the_leading_superblock_area() {
    let v = test_image::with_root().mount().unwrap();
    let s = v.space();
    assert_eq!(s.total, test_image::BLOCK_COUNT - u64::from(test_image::CP_BLKADDR));
    assert_eq!(s.block_bytes, BLKSIZE as u32);
}

#[test]
fn the_free_count_is_the_user_count_less_what_is_live() {
    let mut b = test_image::with_root();
    nodes::add_sparse_file(&mut b, 4, BLKSIZE as u64, &[(0, vec![b'x'])]);
    let live = b.valid_block_count;
    let v = b.mount().unwrap();
    let s = v.space();
    let user = u64::from(test_image::SEG_MAIN * BLKS_PER_SEG);
    assert_eq!(s.free, user - live);
}

#[test]
fn a_reservation_comes_out_of_what_is_available_not_out_of_what_is_free() {
    let b = test_image::with_root();
    let mut opts = crate::opts::Options::defaults();
    opts.reserve_root = 100;
    let v = Volume::mount_with(b.image(), opts, false).unwrap();
    let s = v.space();
    assert_eq!(s.avail, s.free - 100);
}

#[test]
fn released_blocks_replenish_the_reserved_pool_and_reduce_ordinary_free_space() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"x");
    let v = b.mount().unwrap();
    let addr = (test_image::MAIN_BLKADDR..test_image::MAIN_BLKADDR + 32)
        .find(|&a| v.block_is_live(a).unwrap())
        .expect("fixture has a live main block");
    let mut v = v;
    v.set_reserved_blocks(4).unwrap();
    v.current_reserved_blocks = 0;
    let before = v.space();
    v.release_block(addr).unwrap();
    let after = v.space();
    assert_eq!(v.current_reserved_blocks(), 1);
    assert_eq!(after.free, before.free);
    assert_eq!(after.avail, before.avail);
}

#[test]
fn carve_out_only_changes_the_reported_total() {
    let mut v = test_image::with_root().mount().unwrap();
    let total = v.space().total;
    v.set_reserved_blocks(4).unwrap();
    v.current_reserved_blocks = 2;
    let ordinary = v.space();
    v.set_carve_out(true);
    let carved = v.space();
    assert_eq!(carved.total, total - 2);
    assert_eq!(carved.free, ordinary.free);
    assert_eq!(carved.avail, ordinary.avail);
}

#[test]
fn the_node_count_is_the_tables_capacity_less_the_reserved_ids() {
    let v = test_image::with_root().mount().unwrap();
    let s = v.space();
    let nodes = u64::from(v.max_nid()) - u64::from(RESERVED_NODE_NUM);
    let user = u64::from(test_image::SEG_MAIN * BLKS_PER_SEG);
    // The table is far wider than the volume here, so the block count caps it.
    assert!(nodes > user);
    assert_eq!(s.files, user);
}

#[test]
fn the_free_node_count_never_exceeds_what_is_available() {
    let v = test_image::with_root().mount().unwrap();
    let s = v.space();
    assert!(s.ffree <= s.avail);
}

#[test]
fn the_segment_table_reports_the_live_count_the_fixture_wrote() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"x");
    let want = b.sit_valid[0];
    let v = b.mount().unwrap();
    assert_eq!(v.seg_entry(0).unwrap().valid_blocks(), want);
}

#[test]
fn a_segment_number_past_the_main_area_is_refused() {
    let v = test_image::with_root().mount().unwrap();
    assert_eq!(v.seg_entry(test_image::SEG_MAIN).err(), Some(Errno::Einval));
}

#[test]
fn the_segment_bitmap_selects_the_second_table_copy() {
    let mut b = test_image::with_root();
    b.sit_bitmap[0] |= 1;
    nodes::add_inline_file(&mut b, 4, b"x");
    let want = b.sit_valid[0];
    let v = b.mount().unwrap();
    assert_eq!(v.seg_entry(0).unwrap().valid_blocks(), want);
}

#[test]
fn a_live_block_is_reported_live_and_an_unwritten_one_is_not() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"x");
    let used = b.next_main;
    let v = b.mount().unwrap();
    assert!(v.block_is_live(test_image::MAIN_BLKADDR).unwrap());
    assert!(!v.block_is_live(used).unwrap());
}

#[test]
fn an_address_outside_the_main_area_is_not_live() {
    let v = test_image::with_root().mount().unwrap();
    assert!(!v.block_is_live(0).unwrap());
    assert!(!v.block_is_live(test_image::NAT_BLKADDR).unwrap());
}

#[test]
fn an_inode_with_no_attributes_lists_nothing() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"x");
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert!(v.list_xattr(&i, 4).unwrap().is_empty());
}

#[test]
fn an_inline_attribute_reads_back() {
    let mut b = test_image::with_root();
    add_file_with_xattrs(&mut b, 4, &[attr(XATTR_INDEX_USER, "colour", "blue")], false);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.get_xattr(&i, 4, "user.colour").unwrap(), b"blue".to_vec());
}

#[test]
fn several_inline_attributes_list_with_their_prefixes() {
    let mut b = test_image::with_root();
    add_file_with_xattrs(
        &mut b,
        4,
        &[attr(XATTR_INDEX_USER, "a", "1"), attr(XATTR_INDEX_TRUSTED, "b", "2")],
        false,
    );
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.list_xattr(&i, 4).unwrap(), b"user.a\0trusted.b\0".to_vec());
}

#[test]
fn an_absent_attribute_reports_no_data() {
    let mut b = test_image::with_root();
    add_file_with_xattrs(&mut b, 4, &[attr(XATTR_INDEX_USER, "a", "1")], false);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.get_xattr(&i, 4, "user.b").err(), Some(Errno::Enodata));
}

#[test]
fn a_name_under_no_known_prefix_is_refused() {
    let mut b = test_image::with_root();
    add_file_with_xattrs(&mut b, 4, &[attr(XATTR_INDEX_USER, "a", "1")], false);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.get_xattr(&i, 4, "bogus.a").err(), Some(Errno::Eopnotsupp));
}

#[test]
fn an_attribute_in_the_block_half_is_found_through_the_joined_region() {
    // The block continues the inline list; searching the two separately loses
    // whatever the block holds.
    let mut b = test_image::with_root();
    add_file_with_xattrs(
        &mut b,
        4,
        // The first value is wide enough that the record after it starts past
        // the inline region and lives in the block half.
        &[attr(XATTR_INDEX_USER, "inline", &"h".repeat(160)),
          attr(XATTR_INDEX_SECURITY, "selinux", "ctx")],
        true,
    );
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_ne!(i.xattr_nid, 0);
    assert_eq!(v.get_xattr(&i, 4, "user.inline").unwrap(), "h".repeat(160).into_bytes());
    assert_eq!(v.get_xattr(&i, 4, "security.selinux").unwrap(), b"ctx".to_vec());
}

#[test]
fn a_listing_reports_both_halves_in_storage_order() {
    let mut b = test_image::with_root();
    add_file_with_xattrs(
        &mut b,
        4,
        &[attr(XATTR_INDEX_USER, "one", &"1".repeat(160)),
          attr(XATTR_INDEX_USER, "two", "2")],
        true,
    );
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.list_xattr(&i, 4).unwrap(), b"user.one\0user.two\0".to_vec());
}

#[test]
fn the_attribute_nodes_footer_must_name_the_owning_inode() {
    let mut b = test_image::with_root();
    let s = add_file_with_xattrs(
        &mut b,
        4,
        &[attr(XATTR_INDEX_USER, "a", &"1".repeat(160)), attr(XATTR_INDEX_USER, "b", "2")],
        true,
    );
    let addr = b.nat.iter().find(|(n, _)| *n == s.xattr_nid).unwrap().1.block_addr;
    let mut bytes = b.finish();
    let at = addr as usize * BLKSIZE + NODE_FOOTER_OFF + FOOTER_INO;
    bytes[at..at + 4].copy_from_slice(&99u32.to_le_bytes());
    let img = sectors::MemImage::from_bytes(BLKSIZE as u32, bytes);
    let v = Volume::mount_with(img, crate::opts::Options::defaults(), false).unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.list_xattr(&i, 4).err(), Some(Errno::Eio));
}

#[test]
fn the_attribute_region_is_the_inline_span_plus_the_block_and_a_pad() {
    let mut b = test_image::with_root();
    let s = add_file_with_xattrs(&mut b, 4, &[attr(XATTR_INDEX_USER, "a", "1")], false);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    let area = v.xattr_area(&i, 4).unwrap();
    assert_eq!(area.len(), s.inline_xattr_addrs * 4 + 4);
}

#[test]
fn an_inode_with_no_inline_region_still_reads_its_attribute_block() {
    let mut b = test_image::with_root();
    let mut s = nodes::Spec::file(4);
    b.use_ino(4);
    s.xattr_nid = b.alloc_nid();
    let block = nodes::inode_block(&s);
    nodes::add_xattr_block(&mut b, 4, s.xattr_nid, &[attr(XATTR_INDEX_USER, "z", "9")]);
    nodes::place_inode(&mut b, &s, block, 2);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(i.inline_xattr_span(), None);
    assert_eq!(v.get_xattr(&i, 4, "user.z").unwrap(), b"9".to_vec());
}

#[test]
fn a_value_of_zero_length_is_stored_and_read_back() {
    let mut b = test_image::with_root();
    add_file_with_xattrs(&mut b, 4, &[attr(XATTR_INDEX_USER, "empty", "")], false);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.get_xattr(&i, 4, "user.empty").unwrap(), Vec::<u8>::new());
}

#[test]
fn a_long_value_reads_back_whole() {
    let value = "v".repeat(120);
    let mut b = test_image::with_root();
    add_file_with_xattrs(&mut b, 4, &[attr(XATTR_INDEX_USER, "long", &value)], false);
    let v = b.mount().unwrap();
    let i = v.read_inode(4).unwrap();
    assert_eq!(v.get_xattr(&i, 4, "user.long").unwrap(), value.as_bytes().to_vec());
}

#[test]
fn the_option_set_a_mount_was_given_is_what_it_reports() {
    let b = test_image::with_root();
    let opts = crate::opts::parse(&crate::opts::Options::defaults(), "noacl,mode=lfs").unwrap();
    let v = Volume::mount_with(b.image(), opts.clone(), false).unwrap();
    assert_eq!(*v.options(), opts);
    let shown = crate::opts::show(v.options(), v.super_block().feature);
    assert!(shown.contains(",noacl"));
    assert!(shown.contains(",mode=lfs"));
}

#[test]
fn the_volumes_own_fields_survive_the_mount() {
    let v = test_image::with_root().mount().unwrap();
    let sb = v.super_block();
    assert_eq!(sb.volume_name, "oxide");
    assert_eq!(sb.uuid, [0x5A; 16]);
    assert_eq!(sb.extensions, vec!["jpg", "mp4"]);
}
