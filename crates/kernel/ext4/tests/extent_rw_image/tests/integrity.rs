use super::*;

#[test]
fn corrupt_external_extent_block_tail_is_rejected() {
    // Read-side metadata_csum verify (Linux ext4_extent_block_csum_verify): an
    // external extent block whose et_checksum tail no longer matches must fail
    // the read rather than silently returning wrong data.
    let disk = build_disk();
    let m = ext4::Mount::open(disk.clone()).unwrap();
    if !m.sb.has_metadata_csum() { return; } // no-op on non-csum images
    let n = m.create_file(2, b"corrupt.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    let payloads: std::vec::Vec<std::vec::Vec<u8>> = (0..5).map(|i| std::vec![i as u8; bs]).collect();
    for i in 0..5 {
        let _spacer = m.alloc_block(0).unwrap();
        m.append_block(n, &payloads[i]).unwrap();
    }
    let inode = m.read_inode(n).unwrap();
    assert!(ext4::parse_extent_header(&inode.i_block).unwrap().depth >= 1);

    // Clean read succeeds first.
    m.read_file_block(&inode, 0).unwrap();

    // Corrupt the first external (leaf) block's csum tail on disk.
    let leaf_lba = inline_idx_lba(&inode.i_block, 0);
    let mut leaf = read_fs_block(&disk, leaf_lba, m.sb.block_size);
    let last = leaf.len() - 1;
    leaf[last] ^= 0xFF;
    write_fs_block(&disk, leaf_lba, m.sb.block_size, leaf);

    // A fresh mount (bypasses any cached block) must now reject the read.
    let m2 = ext4::Mount::open(disk).unwrap();
    let inode2 = m2.read_inode(n).unwrap();
    assert!(m2.read_file_block(&inode2, 0).is_err(),
        "corrupted extent-block csum tail must be rejected on read");
}

#[test]
fn truncate_depth1_frees_tail_and_keeps_head() {
    // Regression: truncate_inode must work at depth>=1 (was DepthUnsupported,
    // so truncating ANY multi-extent file failed).
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"trunc_deep.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    // Force depth>=1 with 6 non-contiguous extents (spacer breaks contiguity).
    for i in 0..6u8 {
        let _spacer = m.alloc_block(0).unwrap();
        m.append_block(n, &std::vec![i; bs]).unwrap();
    }
    let inode = m.read_inode(n).unwrap();
    let hdr = ext4::parse_extent_header(&inode.i_block).unwrap();
    assert!(hdr.depth >= 1, "test needs a depth>=1 tree");
    let pre_free = m.state_free_blocks();

    // Truncate 6 blocks → 2.
    m.truncate_inode(n, 2 * bs as u64).unwrap();
    let inode2 = m.read_inode(n).unwrap();
    assert_eq!(inode2.size, 2 * bs as u64, "size reflects truncation");
    // Surviving head blocks read their original content via the deep walk.
    assert_eq!(m.read_file_block(&inode2, 0).unwrap()[0], 0u8);
    assert_eq!(m.read_file_block(&inode2, 1).unwrap()[0], 1u8);
    // The 4 tail data blocks were freed (the authoritative "tail is gone" check).
    assert!(m.state_free_blocks() >= pre_free + 4, "freed >=4 tail data blocks");
    // The truncated logical block is now a HOLE — its extent was removed, so it
    // reads as zeros (Linux sparse-file semantics), not the old freed content.
    assert_eq!(m.read_file_block(&inode2, 2).unwrap(), std::vec![0u8; bs],
        "block past new EOF is a hole reading zeros");
}

#[test]
fn truncate_depth1_to_zero_resets_to_empty() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"trunc_zero.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    for i in 0..6u8 {
        let _spacer = m.alloc_block(0).unwrap();
        m.append_block(n, &std::vec![i; bs]).unwrap();
    }
    assert!(ext4::parse_extent_header(&m.read_inode(n).unwrap().i_block).unwrap().depth >= 1);
    m.truncate_inode(n, 0).unwrap();
    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, 0);
    // Tree collapsed back to an empty depth-0 inline header.
    let hdr = ext4::parse_extent_header(&inode.i_block).unwrap();
    assert_eq!(hdr.depth, 0, "empty tree resets to depth 0");
    assert_eq!(hdr.entries, 0, "no extents remain");
    // Re-append after truncate-to-zero still works.
    m.append_block(n, &std::vec![0x99; bs]).unwrap();
    let inode2 = m.read_inode(n).unwrap();
    assert_eq!(m.read_file_block(&inode2, 0).unwrap()[0], 0x99);
}

#[test]
fn rmw_write_and_read_into_depth1_file() {
    // Regression: write_file_block / read_file_block must work at depth>=1.
    // Pre-fix write_file_block returned DepthUnsupported for any multi-extent
    // file, so write_at's RMW phase silently failed on fragmented files.
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"deeprmw.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    // Force depth>=1 with 5 non-contiguous extents (spacer breaks contiguity).
    for i in 0..5u8 {
        let _spacer = m.alloc_block(0).unwrap();
        m.append_block(n, &std::vec![i; bs]).unwrap();
    }
    let inode = m.read_inode(n).unwrap();
    let hdr = ext4::parse_extent_header(&inode.i_block).unwrap();
    assert!(hdr.depth >= 1, "test needs a depth>=1 tree to exercise the deep walk");

    // RMW-write into logical block 3 (mid-file) via write_at — exercises
    // write_file_block's depth-agnostic resolve. Straddle no boundary: a
    // sub-block write at offset 3*bs+10.
    let off = 3 * bs as u64 + 10;
    let payload: std::vec::Vec<u8> = (100..132u8).collect();
    m.write_at(n, off, &payload).unwrap();

    // Read it back via the deep read_file_block walk.
    let inode2 = m.read_inode(n).unwrap();
    let blk3 = m.read_file_block(&inode2, 3).unwrap();
    assert_eq!(&blk3[10..10 + payload.len()], &payload[..], "RMW bytes round-trip at depth>=1");
    // Untouched logical block 4 still reads its original append content.
    let blk4 = m.read_file_block(&inode2, 4).unwrap();
    assert_eq!(blk4[0], 4u8, "neighbouring deep block intact");
}


