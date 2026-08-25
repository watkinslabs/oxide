use super::*;

#[test]
fn fallocate_keep_size_inserts_sparse_inline_extents_sorted() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"falloc_sparse.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;

    m.fallocate_inode(n, (bs * 2) as u64, bs as u64, true).unwrap();
    m.fallocate_inode(n, bs as u64, bs as u64, true).unwrap();

    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, 0, "KEEP_SIZE preserves i_size");
    let hdr = ext4::parse_extent_header(&inode.i_block).unwrap();
    assert_eq!(hdr.depth, 0, "two sparse extents stay inline");
    assert_eq!(hdr.entries, 2);
    let e0 = ext4::parse_inline_extent(&inode.i_block, &hdr, 0).unwrap();
    let e1 = ext4::parse_inline_extent(&inode.i_block, &hdr, 1).unwrap();
    assert_eq!((e0.block, e1.block), (1, 2), "inline extents are sorted by logical block");
    for lb in 1..=2 {
        let blk = m.read_file_block(&inode, lb).unwrap();
        assert!(blk.iter().all(|&b| b == 0), "block {} is allocated and zeroed", lb);
    }
}

#[test]
fn fallocate_keep_size_inserts_sparse_depth1_leaf_sorted() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk.clone()).unwrap();
    let n = m.create_file(2, b"falloc_d1.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;

    for lb in [8u32, 6, 4, 2, 0] {
        m.fallocate_inode(n, lb as u64 * bs as u64, bs as u64, true).unwrap();
    }
    let inode = m.read_inode(n).unwrap();
    let hdr = ext4::parse_extent_header(&inode.i_block).unwrap();
    assert_eq!(hdr.depth, 1, "five sparse extents promote to one depth-1 leaf");

    m.fallocate_inode(n, bs as u64, bs as u64, true).unwrap();
    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, 0, "KEEP_SIZE remains intact after depth-1 insert");
    let hdr = ext4::parse_extent_header(&inode.i_block).unwrap();
    assert_eq!(hdr.depth, 1);
    assert_eq!(hdr.entries, 1);
    let leaf_lba = inline_idx_lba(&inode.i_block, 0);
    let leaf = read_fs_block(&disk, leaf_lba, m.sb.block_size);
    assert_eq!(leaf_extent_blocks(&leaf), std::vec![0, 1, 2, 4, 6, 8]);
    for lb in [0u32, 1, 2, 4, 6, 8] {
        let blk = m.read_file_block(&inode, lb).unwrap();
        assert!(blk.iter().all(|&b| b == 0), "block {} is allocated and zeroed", lb);
    }
}

#[test]
fn fallocate_sparse_extents_promotes_full_root_to_depth3() {
    let disk = build_disk();
    let mut m = ext4::Mount::open(disk.clone()).unwrap();
    let n = m.create_file(2, b"falloc_d3.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    let mut logicals = std::vec::Vec::new();

    for lb in [0u32, 2, 4, 6, 8] {
        m.fallocate_inode(n, lb as u64 * bs as u64, bs as u64, true).unwrap();
        logicals.push(lb);
    }
    assert_eq!(ext4::parse_extent_header(&m.read_inode(n).unwrap().i_block).unwrap().depth, 1);

    // mini.img has 1 KiB blocks, so real external extent nodes hold ~84
    // entries. Constrain only this test-created tree's external eh_max fields
    // to 4 so the same split propagation reaches depth 3 within the fixture.
    // Poking `eh_max` writes straight to the backing device, behind the
    // mount's own metadata buffer cache — the same hazard a real ext4 mount
    // has against an out-of-band device write (e.g. `debugfs -w` on a live
    // mount): the cache keeps serving the pre-poke bytes until something
    // forces it to re-read. A real system would remount or drop caches;
    // here that means reopening the `Mount` so the next read is a cold
    // read of what's actually on disk.
    let inode0 = m.read_inode(n).unwrap();
    force_tree_external_maxes(&disk, &m.sb, n, inode0.generation, &inode0.i_block, m.sb.block_size, 4);
    m = ext4::Mount::open(disk.clone()).unwrap();

    let mut next_lb = 10u32;
    while ext4::parse_extent_header(&m.read_inode(n).unwrap().i_block).unwrap().depth < 3 {
        m.fallocate_inode(n, next_lb as u64 * bs as u64, bs as u64, true).unwrap();
        logicals.push(next_lb);
        let ino_cur = m.read_inode(n).unwrap();
        force_tree_external_maxes(&disk, &m.sb, n, ino_cur.generation, &ino_cur.i_block, m.sb.block_size, 4);
        m = ext4::Mount::open(disk.clone()).unwrap();
        next_lb += 2;
        assert!(logicals.len() < 96, "test should reach depth 3 with constrained fanout");
    }

    let at_depth3 = next_lb;
    m.fallocate_inode(n, at_depth3 as u64 * bs as u64, bs as u64, true).unwrap();
    logicals.push(at_depth3);

    let inode = m.read_inode(n).unwrap();
    let hdr = ext4::parse_extent_header(&inode.i_block).unwrap();
    assert!(hdr.depth >= 3, "root promoted past depth 2 instead of returning ExtentTreeFull");
    assert_eq!(inode.size, 0, "KEEP_SIZE still preserves i_size on deep insert");

    for lb in logicals {
        let blk = m.read_file_block(&inode, lb).unwrap();
        assert!(blk.iter().all(|&b| b == 0), "logical block {} remains readable", lb);
    }
}


