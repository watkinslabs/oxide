use super::*;

#[test]
fn truncate_shrinks_and_frees_blocks() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"shrink.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    let pre_free = m.state_free_blocks();
    for _ in 0..4 { m.append_block(n, &std::vec![0xCC; bs]).unwrap(); }
    assert_eq!(m.state_free_blocks(), pre_free - 4);
    // Truncate to 1.5 blocks worth: 1 full block + half of block 1.
    m.truncate_inode(n, (bs as u64) + (bs as u64 / 2)).unwrap();
    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, bs as u64 + bs as u64 / 2);
    // Two trailing whole blocks freed.
    assert_eq!(m.state_free_blocks(), pre_free - 2);
}

#[test]
fn truncate_unwritten_extent_frees_only_its_real_coverage() {
    // `ee_len` carries the unwritten flag in its high bit.  Truncation must
    // free the decoded block count, not the raw on-disk value, or it walks
    // past the extent and corrupts the allocator bitmap.
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"unwritten-truncate.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    let pre_free = m.state_free_blocks();

    m.fallocate_inode(n, 0, (bs * 3) as u64, false).unwrap();
    assert_eq!(m.state_free_blocks(), pre_free - 3);
    m.truncate_inode(n, 0).expect("truncate unwritten extent");

    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, 0);
    assert_eq!(m.state_free_blocks(), pre_free, "exactly the three extent blocks were released");
}

#[test]
fn append_promotes_inline_to_depth1_when_full() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"deep.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    // Explicit logical gaps are required: Linux-shaped append preallocation
    // intentionally makes ordinary sequential appends contiguous.
    let logicals = [0, 2, 4, 6, 8];
    let payloads = fragmented_file(&m, n, bs, &logicals);
    let inode = m.read_inode(n).unwrap();
    let hdr = ext4::parse_extent_header(&inode.i_block).unwrap();
    assert!(hdr.depth >= 1, "5 sparse extents promoted to depth=1");
    // Read each logical block back; they must match.
    for (logical, want) in logicals.iter().zip(payloads.iter()) {
        let got = m.read_file_block(&inode, *logical).unwrap();
        assert_eq!(&got[..], &want[..], "logical block {} round-trips", logical);
    }
}

