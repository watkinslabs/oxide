use super::*;


fn test_sb(blocks: u32, bpg: u32, ipg: u32, reserved_gdt: u16) -> Superblock {
    let mut b = [0u8; crate::superblock::SUPERBLOCK_LEN];
    b[0x00..0x04].copy_from_slice(&(ipg * 2).to_le_bytes());
    b[0x04..0x08].copy_from_slice(&blocks.to_le_bytes());
    b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    b[0x18..0x1C].copy_from_slice(&0u32.to_le_bytes());
    b[0x20..0x24].copy_from_slice(&bpg.to_le_bytes());
    b[0x28..0x2C].copy_from_slice(&ipg.to_le_bytes());
    b[0x38..0x3A].copy_from_slice(&crate::superblock::EXT4_SUPER_MAGIC.to_le_bytes());
    b[0x58..0x5A].copy_from_slice(&256u16.to_le_bytes());
    b[0x60..0x64].copy_from_slice(&crate::superblock::INCOMPAT_EXTENTS.to_le_bytes());
    b[0x64..0x68].copy_from_slice(&crate::superblock::RO_COMPAT_SPARSE_SUPER.to_le_bytes());
    b[crate::superblock::SB_OFF_RESERVED_GDT_BLOCKS..crate::superblock::SB_OFF_RESERVED_GDT_BLOCKS + 2]
        .copy_from_slice(&reserved_gdt.to_le_bytes());
    Superblock::parse(&b).unwrap()
}

fn put_desc(gdt_buf: &mut [u8], n: usize, bbm: u32, ibm: u32, it: u32, flags: u16) {
    let off = n * 32;
    gdt_buf[off..off + 4].copy_from_slice(&bbm.to_le_bytes());
    gdt_buf[off + 4..off + 8].copy_from_slice(&ibm.to_le_bytes());
    gdt_buf[off + 8..off + 12].copy_from_slice(&it.to_le_bytes());
    gdt_buf[off + gdt::GD_OFF_FLAGS..off + gdt::GD_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
}

fn bit_set(bitmap: &[u8], bit: usize) -> bool {
    bitmap[bit >> 3] & (1u8 << (bit & 7)) != 0
}

#[test]
fn first_clear_in_full_byte_returns_none() {
    assert_eq!(find_first_clear(&[0xFF; 4], 32), None);
}

#[test]
fn first_clear_picks_lsb_first() {
    // byte 0 = 0b00000110 (bits 1,2 set) → first clear is bit 0
    assert_eq!(find_first_clear(&[0b0000_0110, 0xFF], 16), Some(0));
    // byte 0 = 0xFF, byte 1 = 0xFE → first clear is bit 8
    assert_eq!(find_first_clear(&[0xFF, 0xFE], 16), Some(8));
}

#[test]
fn first_clear_respects_max_bits_tail() {
    // 12 bits total. byte 0 full, byte 1 = 0b0000_0001 (bit 0 set).
    // Tail covers bits 8..12 (lower nibble of byte 1). bit 8 is set;
    // bit 9 is clear → 9.
    assert_eq!(find_first_clear(&[0xFF, 0b0000_0001], 12), Some(9));
    // All 12 bits set in lower nibble → None even though high
    // nibble has clears (those are out of range).
    assert_eq!(find_first_clear(&[0xFF, 0b0000_1111], 12), None);
}

#[test]
fn contiguous_run_requires_every_bit_and_stays_in_the_bitmap() {
    let bitmap = [0b0000_0011, 0b0001_0000];
    assert_eq!(find_contiguous_run(&bitmap, 16, 3, 0, None), Some(13));
    assert_eq!(find_contiguous_run(&bitmap, 8, 7, 0, None), None,
               "a used bit breaks the requested run");
    assert_eq!(find_contiguous_run(&bitmap, 16, 17, 0, None), None,
               "a request past the bitmap is not free");
}

#[test]
fn contiguous_run_prefers_the_smallest_sufficient_free_extent() {
    // Free runs are [2, 6) and [7, 10). For a three-block request Linux's
    // best-found policy chooses the exact-sized second run, not first-fit.
    let bitmap = [0b0100_0011, 0b0000_0000];
    assert_eq!(find_contiguous_run(&bitmap, 10, 3, 0, None), Some(7));
}

#[test]
fn contiguous_run_honors_linux_satisfied_scan_limit() {
    // Linux accepts a satisfied candidate after ten extents. A later,
    // smaller extent must not turn this into an unbounded best-fit search.
    let mut bitmap = alloc::vec![0xffu8; 512];
    let mut cursor = 0usize;
    for len in 4..=14 {
        for bit in cursor..cursor + len { bitmap[bit >> 3] &= !(1 << (bit & 7)); }
        cursor += len + 1;
    }
    // Eleventh extent: smaller than every extent considered by the limit.
    for bit in cursor..cursor + 3 { bitmap[bit >> 3] &= !(1 << (bit & 7)); }
    assert_eq!(find_contiguous_run(&bitmap, (cursor + 3) as u32, 2, 0, None), Some(0));
}

#[test]
fn goal_run_is_used_only_when_the_requested_extent_is_free() {
    let bitmap = [0b0000_0011, 0b0000_0000];
    assert_eq!(find_goal_run(&bitmap, 16, 3, 0, 4, 0), Some(4));
    assert_eq!(find_goal_run(&bitmap, 16, 3, 0, 1, 0), None,
        "a used goal cannot bypass the normal scan");
    assert_eq!(find_goal_run(&bitmap, 16, 3, 0, 4, 4), Some(4));
    assert_eq!(find_goal_run(&bitmap, 16, 8, 0, 4, 8), None,
        "a stripe-sized request keeps its physical alignment");
}

#[test]
fn first_clear_zero_max() {
    assert_eq!(find_first_clear(&[0x00; 4], 0), None);
}

#[test]
fn stream_goal_hash_uses_linux_slot_geometry() {
    assert_eq!(stream_goal_slot_with_slots(17, 1), 0);
    assert_eq!(stream_goal_slot_with_slots(17, 4), 1);
    assert_eq!(stream_goal_slot_with_slots(17, 0), 0);
}

#[test]
fn block_uninit_bitmap_marks_backup_and_flex_metadata() {
    let sb = test_sb(16_384, 8192, 64, 2);
    let first1 = group_first_block(&sb, 1) as u32;
    let mut gdt_buf = alloc::vec![0u8; 64];
    put_desc(&mut gdt_buf, 0, 10, 11, 12, 0);
    put_desc(&mut gdt_buf, 1, first1 + 100, first1 + 101, first1 + 102, gdt::EXT4_BG_BLOCK_UNINIT);
    let bm = init_block_bitmap_for_group(&sb, &gdt_buf, 1).unwrap();
    for bit in 0..4 {
        assert!(bit_set(&bm, bit), "backup super/GDT/reserved bit {bit} must be used");
    }
    assert!(bit_set(&bm, 100), "block bitmap must be used");
    assert!(bit_set(&bm, 101), "inode bitmap must be used");
    for bit in 102..118 {
        assert!(bit_set(&bm, bit), "inode table bit {bit} must be used");
    }
    assert_eq!(find_first_clear(&bm, blocks_in_group_sb(&sb, 1)), Some(4));
}

#[test]
fn block_uninit_bitmap_marks_last_group_tail_used() {
    let sb = test_sb(8192 + 102, 8192, 64, 0);
    let first1 = group_first_block(&sb, 1) as u32;
    let mut gdt_buf = alloc::vec![0u8; 64];
    put_desc(&mut gdt_buf, 0, 10, 11, 12, 0);
    put_desc(&mut gdt_buf, 1, first1 + 10, first1 + 11, first1 + 12, gdt::EXT4_BG_BLOCK_UNINIT);
    let bm = init_block_bitmap_for_group(&sb, &gdt_buf, 1).unwrap();
    assert!(!bit_set(&bm, 100), "last real block remains allocatable unless metadata owns it");
    assert!(bit_set(&bm, 101), "tail bit past group end must be used");
    assert_eq!(find_first_clear(&bm, sb.blocks_per_group), Some(2));
}
