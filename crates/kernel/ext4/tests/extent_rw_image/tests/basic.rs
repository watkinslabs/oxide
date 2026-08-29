use super::*;

#[test]
fn append_block_then_read_back() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk.clone()).unwrap();
    let ino_n = m.lookup_path(b"/hello.txt").unwrap();
    let pre = m.read_inode(ino_n).unwrap();
    let bs = m.sb.block_size as usize;

    let mut payload = std::vec![0u8; bs];
    for (i, b) in payload.iter_mut().enumerate() { *b = (i & 0xFF) as u8; }
    let new_lb = m.append_block(ino_n, &payload).unwrap();
    assert_eq!(new_lb, 1, "first appended block lives at logical 1 (0 is original content)");

    // Inode now reports +1 fs-block worth of data.
    let post = m.read_inode(ino_n).unwrap();
    assert_eq!(post.size, pre.size + bs as u64);

    let blk = m.read_file_block(&post, 1).unwrap();
    assert_eq!(blk, payload, "appended bytes round-trip via extent walk");
}

#[test]
fn append_extends_or_adds_inline_extents() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let ino_n = m.lookup_path(b"/hello.txt").unwrap();
    let bs = m.sb.block_size as usize;
    // Append three fs-blocks; bitmap-allocator picks the next-clear
    // bit each time (often contiguous), so the trailing extent's
    // `len` should grow rather than spawning new leaves.
    for _ in 0..3 {
        let payload = std::vec![0xAB; bs];
        m.append_block(ino_n, &payload).unwrap();
    }
    let post = m.read_inode(ino_n).unwrap();
    let hdr = ext4::parse_extent_header(&post.i_block).unwrap();
    assert!(hdr.entries >= 1 && hdr.entries <= 4, "stayed inline");
    // Read back logical block 3 (last appended).
    let blk = m.read_file_block(&post, 3).unwrap();
    assert_eq!(blk[0], 0xAB);
}

#[test]
fn write_at_extends_and_round_trips() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"wa.bin", 0o644, 0, 0).unwrap();
    // Write straddling block boundary into a brand-new file.
    let bs = m.sb.block_size as u64;
    let off = bs - 8;
    let payload: std::vec::Vec<u8> = (0..32u8).collect();
    m.write_at(n, off, &payload).unwrap();
    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, off + payload.len() as u64);
    // Read back via two block fetches + splice.
    let blk0 = m.read_file_block(&inode, 0).unwrap();
    let blk1 = m.read_file_block(&inode, 1).unwrap();
    let mut got = std::vec::Vec::new();
    got.extend_from_slice(&blk0[off as usize..]);
    got.extend_from_slice(&blk1[..(payload.len() - 8)]);
    assert_eq!(got, payload, "spliced bytes match");
}

#[test]
fn sequential_regular_writes_reuse_inode_preallocation() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"pa.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    let before = m.state_free_blocks();

    m.write_at(n, 0, &std::vec![0x11; bs]).unwrap();
    let after_first = m.state_free_blocks();
    m.write_at(n, bs as u64, &std::vec![0x22; bs]).unwrap();
    let after_second = m.state_free_blocks();

    assert_eq!(before - after_first, 1,
        "the first stream write durably allocates only its written block");
    assert_eq!(after_first - after_second, 1,
        "consuming the inode PA durably claims exactly one more block");
    let map = m.extent_map(n).unwrap();
    assert_eq!(map[0].2, 2, "the two writes remain one physical extent");
}

#[test]
fn freeing_an_orphan_releases_its_unused_inode_preallocation() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"orphan-pa.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;

    m.append_block(n, &vec![0x33; bs]).unwrap();
    assert!(m.inode_prealloc_free_blocks() > 0, "append retains an inode PA tail");
    let out = m.unlink(2, b"orphan-pa.bin").unwrap();
    assert!(out.orphaned(), "last link must place the inode on the orphan path");

    m.free_orphan_inode(out.ino).unwrap();
    assert_eq!(m.inode_prealloc_free_blocks(), 0,
        "orphan eviction must release every unused inode PA block");
}

#[test]
fn fresh_appends_create_and_reuse_locality_preallocation() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"append-fresh-pa.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    let before = m.state_free_blocks();

    m.append_block(n, &std::vec![0x51; bs]).unwrap();
    let after_first = m.state_free_blocks();
    let first_phys = m.extent_map(n).unwrap()[0].1;
    m.append_block(n, &std::vec![0x52; bs]).unwrap();
    let after_second = m.state_free_blocks();
    let map = m.extent_map(n).unwrap();

    assert_eq!(before - after_first, 1,
        "fresh append persists only its data block; the PA tail remains free on disk");
    assert_eq!(after_first - after_second, 1,
        "the next append consumes one block from the fresh PA");
    assert_eq!(map[0].1, first_phys, "fresh appends preserve the physical start");
    assert_eq!(map[0].2, 2, "fresh appends remain one contiguous extent");
    assert_eq!(m.read_file_block(&m.read_inode(n).unwrap(), 1).unwrap()[0], 0x52);
}

#[test]
fn failed_append_rolls_back_fresh_primary_and_pa_claims() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let bs = m.sb.block_size as usize;
    let fresh = m.create_file(2, b"append-failure-fresh.bin", 0o644, 0, 0).unwrap();
    let before = m.state_free_blocks();
    m.fail_next_inode_write_for_tests();
    assert!(m.append_block(fresh, &vec![0x61; bs]).is_err());
    assert_eq!(m.state_free_blocks(), before, "failed fresh append returns its primary block");
    m.append_block(fresh, &vec![0x62; bs]).unwrap();

    let pa = m.create_file(2, b"append-failure-pa.bin", 0o644, 0, 0).unwrap();
    m.append_block(pa, &vec![0x71; bs]).unwrap();
    let pa_phys = m.extent_map(pa).unwrap()[0].1 + 1;
    let before_retry = m.state_free_blocks();
    m.fail_next_inode_write_for_tests();
    assert!(m.append_block(pa, &vec![0x72; bs]).is_err());
    assert_eq!(m.state_free_blocks(), before_retry, "failed PA append returns its claimed block");
    m.append_block(pa, &vec![0x73; bs]).unwrap();
    let retry_map = m.extent_map(pa).unwrap();
    assert_eq!(retry_map[0].1 + 1, pa_phys,
        "failed PA append restores the exact reusable physical block");
}

#[test]
fn failed_write_rolls_back_preallocated_claim() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let bs = m.sb.block_size as usize;
    let ino = m.create_file(2, b"write-failure-pa.bin", 0o644, 0, 0).unwrap();

    m.write_at(ino, 0, &vec![0x81; bs]).unwrap();
    let first_phys = m.extent_map(ino).unwrap()[0].1;
    let before_retry = m.state_free_blocks();
    m.fail_next_inode_write_for_tests();
    assert!(m.write_at(ino, bs as u64, &vec![0x82; bs]).is_err());
    assert_eq!(m.state_free_blocks(), before_retry,
        "failed write returns its claimed preallocated block");

    m.write_at(ino, bs as u64, &vec![0x83; bs]).unwrap();
    let map = m.extent_map(ino).unwrap();
    assert_eq!(map[0].1, first_phys);
    assert_eq!(map[0].2, 2, "retry reuses the restored contiguous PA block");
}

#[test]
fn small_files_reuse_locality_preallocation() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let first = m.create_file(2, b"locality-a.bin", 0o644, 0, 0).unwrap();
    let second = m.create_file(2, b"locality-b.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;

    m.write_at(first, 0, &std::vec![0x31; bs]).unwrap();
    let first_phys = m.extent_map(first).unwrap()[0].1;
    m.write_at(second, 0, &std::vec![0x32; bs]).unwrap();
    let second_phys = m.extent_map(second).unwrap()[0].1;

    assert_eq!(second_phys, first_phys + 1,
        "a small file consumes the reusable locality tail before a fresh scan");
}

#[test]
fn sequential_appends_reuse_preallocation() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"append-pa.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    let before = m.state_free_blocks();

    m.write_at(n, 0, &std::vec![0x41; bs]).unwrap();
    let after_first = m.state_free_blocks();
    let first_phys = m.extent_map(n).unwrap()[0].1;
    m.append_block(n, &std::vec![0x42; bs]).unwrap();
    let after_second = m.state_free_blocks();
    let map = m.extent_map(n).unwrap();

    assert_eq!(before - after_first, 1, "preallocation tail stays free on disk");
    assert_eq!(after_first - after_second, 1, "append claims one PA block");
    assert_eq!(map[0].1, first_phys, "first physical block is stable");
    assert_eq!(map[0].2, 2, "appends merge into one contiguous extent");
    assert_eq!(m.read_file_block(&m.read_inode(n).unwrap(), 1).unwrap()[0], 0x42);
}

#[test]
fn fallocate_extends_size_and_allocates_zeroed_blocks() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"falloc.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;

    m.fallocate_inode(n, 0, (bs * 3) as u64, false).unwrap();

    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, (bs * 3) as u64);
    for lb in 0..3 {
        let blk = m.read_file_block(&inode, lb).unwrap();
        assert!(blk.iter().all(|&b| b == 0), "allocated block {} is zeroed", lb);
    }
}

#[test]
fn fallocate_keep_size_allocates_without_extending_size() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"falloc_keep.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;

    m.fallocate_inode(n, bs as u64, (bs * 2) as u64, true).unwrap();

    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, 0);
    for lb in 1..3 {
        let blk = m.read_file_block(&inode, lb).unwrap();
        assert!(blk.iter().all(|&b| b == 0), "keep-size block {} is allocated and zeroed", lb);
    }
}
