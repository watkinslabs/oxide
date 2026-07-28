use super::*;
use crate::superblock::SUPERBLOCK_LEN;

fn fake_sb_inode_size(isize: u16) -> Superblock {
    let mut b = [0u8; SUPERBLOCK_LEN];
    b[0x18..0x1C].copy_from_slice(&2u32.to_le_bytes());
    b[0x38..0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
    b[0x58..0x5A].copy_from_slice(&isize.to_le_bytes());
    Superblock::parse(&b).expect("sb")
}

fn make_inode_buf(
    isize: usize,
    mode: u16,
    size: u64,
    links: u16,
    i_block: [u8; I_BLOCK_LEN],
) -> std::vec::Vec<u8> {
    let mut b = std::vec![0u8; isize];
    b[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
    b[0x04..0x08].copy_from_slice(&((size & 0xFFFF_FFFF) as u32).to_le_bytes());
    b[0x1A..0x1C].copy_from_slice(&links.to_le_bytes());
    b[0x28..0x28 + I_BLOCK_LEN].copy_from_slice(&i_block);
    b[0x6C..0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
    b
}

fn make_extent_iblock(hdr_entries: u16, depth: u16, leaves: &[(u32, u16, u64)]) -> [u8; I_BLOCK_LEN] {
    let mut b = [0u8; I_BLOCK_LEN];
    b[0..2].copy_from_slice(&EXT4_EXT_MAGIC.to_le_bytes());
    b[2..4].copy_from_slice(&hdr_entries.to_le_bytes());
    b[4..6].copy_from_slice(&4u16.to_le_bytes());
    b[6..8].copy_from_slice(&depth.to_le_bytes());
    b[8..12].copy_from_slice(&0u32.to_le_bytes());
    for (i, &(block, len, start)) in leaves.iter().enumerate() {
        let off = 12 + i * 12;
        b[off..off + 4].copy_from_slice(&block.to_le_bytes());
        b[off + 4..off + 6].copy_from_slice(&len.to_le_bytes());
        b[off + 6..off + 8].copy_from_slice(&((start >> 32) as u16).to_le_bytes());
        b[off + 8..off + 12].copy_from_slice(&((start & 0xFFFF_FFFF) as u32).to_le_bytes());
    }
    b
}

#[test]
fn parse_regular_file_4g() {
    let sb = fake_sb_inode_size(256);
    let big = (1u64 << 32) | 0x123;
    let buf = make_inode_buf(256, S_IFREG | 0o644, big, 1, [0u8; I_BLOCK_LEN]);
    let ino = Inode::parse(&buf, &sb).expect("parse");
    assert!(ino.is_reg());
    assert_eq!(ino.size, big);
    assert_eq!(ino.links_count, 1);
}

#[test]
fn parse_owner_merges_low_and_high_words() {
    let sb = fake_sb_inode_size(256);
    let mut buf = make_inode_buf(256, S_IFREG | 0o644, 0, 1, [0u8; I_BLOCK_LEN]);
    let uid: u32 = 0x0001_2345;
    let gid: u32 = 0x0002_BEEF;
    buf[0x02..0x04].copy_from_slice(&((uid & 0xFFFF) as u16).to_le_bytes());
    buf[0x18..0x1A].copy_from_slice(&((gid & 0xFFFF) as u16).to_le_bytes());
    buf[0x78..0x7A].copy_from_slice(&((uid >> 16) as u16).to_le_bytes());
    buf[0x7A..0x7C].copy_from_slice(&((gid >> 16) as u16).to_le_bytes());
    let ino = Inode::parse(&buf, &sb).expect("parse");
    assert_eq!(ino.uid, uid);
    assert_eq!(ino.gid, gid);
}

#[test]
fn parse_project_id_when_inode_is_large_enough() {
    let sb = fake_sb_inode_size(256);
    let mut buf = make_inode_buf(256, S_IFREG | 0o644, 0, 1, [0u8; I_BLOCK_LEN]);
    buf[0x9C..0xA0].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let ino = Inode::parse(&buf, &sb).expect("parse");
    assert_eq!(ino.i_projid, 0x1234_5678);
}

#[test]
fn parse_project_id_defaults_zero_for_old_inode_size() {
    let sb = fake_sb_inode_size(128);
    let buf = make_inode_buf(128, S_IFREG | 0o644, 0, 1, [0u8; I_BLOCK_LEN]);
    let ino = Inode::parse(&buf, &sb).expect("parse");
    assert_eq!(ino.i_projid, 0);
}

#[test]
fn parse_directory_kind() {
    let sb = fake_sb_inode_size(256);
    let buf = make_inode_buf(256, S_IFDIR | 0o755, 4096, 2, [0u8; I_BLOCK_LEN]);
    let ino = Inode::parse(&buf, &sb).expect("parse");
    assert!(ino.is_dir());
    assert!(!ino.is_reg());
}

#[test]
fn rejects_buf_smaller_than_isize() {
    let sb = fake_sb_inode_size(256);
    let buf = std::vec![0u8; 100];
    assert_eq!(Inode::parse(&buf, &sb), Err(InodeError::BadLen));
}

#[test]
fn extent_header_magic_pinned() {
    assert_eq!(EXT4_EXT_MAGIC, 0xF30A);
}

#[test]
fn extent_header_parse_canonical() {
    let ib = make_extent_iblock(2, 0, &[(0, 1, 0x100), (1, 4, 0x200)]);
    let hdr = parse_extent_header(&ib).expect("hdr");
    assert_eq!(hdr.magic, EXT4_EXT_MAGIC);
    assert_eq!(hdr.entries, 2);
    assert_eq!(hdr.depth, 0);
}

#[test]
fn extent_header_rejects_bad_magic() {
    let mut ib = make_extent_iblock(0, 0, &[]);
    ib[0] = 0;
    ib[1] = 0;
    assert_eq!(parse_extent_header(&ib), Err(InodeError::BadExtentMagic));
}

#[test]
fn extent_header_rejects_5_inline_entries() {
    let ib = make_extent_iblock(5, 0, &[]);
    assert_eq!(parse_extent_header(&ib), Err(InodeError::TooManyExtents));
}

#[test]
fn parse_inline_extent_walk() {
    let ib = make_extent_iblock(2, 0, &[(0, 1, 0x1234_5678), (1, 4, 0x000000010000_0042)]);
    let hdr = parse_extent_header(&ib).unwrap();
    let e0 = parse_inline_extent(&ib, &hdr, 0).expect("e0");
    let e1 = parse_inline_extent(&ib, &hdr, 1).expect("e1");
    let e2 = parse_inline_extent(&ib, &hdr, 2);
    assert_eq!(e0.block, 0);
    assert_eq!(e0.len, 1);
    assert_eq!(e0.start_lba(), 0x1234_5678);
    assert_eq!(e1.block, 1);
    assert_eq!(e1.len, 4);
    assert_eq!(e1.start_lba(), 0x0001_0000_0042);
    assert!(e2.is_none());
}

#[test]
fn parse_inline_extent_skips_indexed_tree() {
    let ib = make_extent_iblock(1, 1, &[(0, 1, 0x100)]);
    let hdr = parse_extent_header(&ib).unwrap();
    assert_eq!(hdr.depth, 1);
    assert!(parse_inline_extent(&ib, &hdr, 0).is_none());
}

#[test]
fn file_type_helpers() {
    assert_eq!(S_IFMT, 0xF000);
    let mode_reg = S_IFREG | 0o644;
    let mode_dir = S_IFDIR | 0o755;
    let mode_lnk = S_IFLNK | 0o777;
    assert_eq!(mode_reg & S_IFMT, S_IFREG);
    assert_eq!(mode_dir & S_IFMT, S_IFDIR);
    assert_eq!(mode_lnk & S_IFMT, S_IFLNK);
}

#[test]
fn extent_backed_60_byte_symlink_is_not_fast() {
    let sb = fake_sb_inode_size(256);
    let ib = make_extent_iblock(1, 0, &[(0, 1, 0x120)]);
    let mut buf = make_inode_buf(256, S_IFLNK | 0o777, I_BLOCK_LEN as u64, 1, ib);
    buf[0x1C..0x20].copy_from_slice(&8u32.to_le_bytes());
    buf[0x20..0x24].copy_from_slice(&EXT4_EXTENTS_FL.to_le_bytes());
    let ino = Inode::parse(&buf, &sb).expect("parse");
    assert!(ino.is_link());
    assert_eq!(ino.size, I_BLOCK_LEN as u64);
    assert!(ino.fast_symlink_target().is_none());
}

#[test]
fn extent_child_depth_bounds_descent() {
    // Valid step: child exactly one level shallower.
    assert!(extent_child_depth_ok(5, 4));
    assert!(extent_child_depth_ok(1, 0));
    // Non-decreasing (cycle) / equal / deeper: rejected.
    assert!(!extent_child_depth_ok(2, 2));
    assert!(!extent_child_depth_ok(2, 3));
    assert!(!extent_child_depth_ok(3, 1)); // skipped a level
    // A leaf (parent depth 0) can have no children.
    assert!(!extent_child_depth_ok(0, 0));
    // u16 edge: child_depth+1 must not wrap to match parent 0.
    assert!(!extent_child_depth_ok(0, u16::MAX));
}

/// Write a raw `(base, extra)` timestamp pair straight into an inode slot, as
/// the on-disk bytes an image would carry.
fn put_raw_time(buf: &mut [u8], base_off: usize, extra_off: usize, base: u32, extra: u32) {
    buf[base_off..base_off + 4].copy_from_slice(&base.to_le_bytes());
    buf[extra_off..extra_off + 4].copy_from_slice(&extra.to_le_bytes());
}

#[test]
fn parse_decodes_a_pre_1970_mtime_as_negative_seconds() {
    // The regression this fixes: `i_mtime` with the high bit set and
    // `i_mtime_extra == 0` is a 1906 timestamp. Zero-extending the base word
    // read it back as 0x8DE7_3600 seconds ≈ year 2106.
    let sb = fake_sb_inode_size(256);
    let mut buf = make_inode_buf(256, S_IFREG | 0o644, 0, 1, [0u8; I_BLOCK_LEN]);
    let raw_base = (-2_000_000_000i32) as u32;
    put_raw_time(&mut buf, 0x10, 0x88, raw_base, 0);
    let ino = Inode::parse(&buf, &sb).expect("parse");
    assert_eq!(ino.mtime, vfs::Timespec64::from_secs(-2_000_000_000));
    assert!(ino.mtime.sec < 0, "1906 mtime stays pre-epoch");
    assert_ne!(ino.mtime.sec, raw_base as i64, "not the zero-extended year-2106 reading");
}

#[test]
fn parse_decodes_the_far_future_epoch_band() {
    // Top row of the ext4.h epoch table: epoch bits 1,1 with msb 0 → year 2378+.
    let sb = fake_sb_inode_size(256);
    let mut buf = make_inode_buf(256, S_IFREG | 0o644, 0, 1, [0u8; I_BLOCK_LEN]);
    put_raw_time(&mut buf, 0x08, 0x8C, 0, 0x3 | (500u32 << 2));
    let ino = Inode::parse(&buf, &sb).expect("parse");
    assert_eq!(ino.atime, vfs::Timespec64::new(0x3_0000_0000, 500));
}

#[test]
fn a_128_byte_inode_reports_no_birth_time() {
    // `EXT4_EINODE_GET_XTIME(i_crtime)`: absent, not epoch-zero.
    let sb = fake_sb_inode_size(128);
    let buf = make_inode_buf(128, S_IFREG | 0o644, 0, 1, [0u8; I_BLOCK_LEN]);
    let ino = Inode::parse(&buf, &sb).expect("parse");
    assert_eq!(ino.crtime, None);
    // ...while a 256-byte inode born at the epoch reports Some(ZERO): the old
    // `0`-means-absent sentinel is gone.
    let sb256 = fake_sb_inode_size(256);
    let buf256 = make_inode_buf(256, S_IFREG | 0o644, 0, 1, [0u8; I_BLOCK_LEN]);
    let ino256 = Inode::parse(&buf256, &sb256).expect("parse");
    assert_eq!(ino256.crtime, Some(vfs::Timespec64::ZERO));
}

#[test]
fn a_128_byte_inode_decodes_seconds_only_and_still_sign_extends() {
    let sb = fake_sb_inode_size(128);
    let mut buf = make_inode_buf(128, S_IFREG | 0o644, 0, 1, [0u8; I_BLOCK_LEN]);
    buf[0x0C..0x10].copy_from_slice(&((-1i32) as u32).to_le_bytes());
    let ino = Inode::parse(&buf, &sb).expect("parse");
    assert_eq!(ino.ctime, vfs::Timespec64::from_secs(-1), "1969-12-31T23:59:59");
    assert_eq!(ino.ctime.nsec, 0, "no extra field ⇒ no sub-second part");
}
