//! P7b-02 integration: append + read-back against mini.img.
//!
//! Append one fs-block of fresh data to /hello.txt, then re-open
//! the FS (same backing disk) and verify the new logical block is
//! readable + matches what we wrote.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;

fn build_disk() -> Arc<dyn BlockDevice> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(),
    };
    disk.submit_sync(&mut req).unwrap();
    disk
}

fn read_fs_block(disk: &Arc<dyn BlockDevice>, fs_lba: u64, fs_bs: u32) -> std::vec::Vec<u8> {
    let sectors = fs_bs / SECTOR;
    let mut req = BlockRequest {
        op: BlockOp::Read,
        start_block: fs_lba * sectors as u64,
        len_blocks: sectors,
        buffer: std::vec![0u8; fs_bs as usize],
    };
    disk.submit_sync(&mut req).unwrap();
    req.buffer
}

fn write_fs_block(disk: &Arc<dyn BlockDevice>, fs_lba: u64, fs_bs: u32, buffer: std::vec::Vec<u8>) {
    let sectors = fs_bs / SECTOR;
    let mut req = BlockRequest {
        op: BlockOp::Write,
        start_block: fs_lba * sectors as u64,
        len_blocks: sectors,
        buffer,
    };
    disk.submit_sync(&mut req).unwrap();
}

fn inline_idx_lba(i_block: &[u8], idx: usize) -> u64 {
    let off = 12 + idx * 12;
    let leaf_lo = u32::from_le_bytes([i_block[off + 4], i_block[off + 5], i_block[off + 6], i_block[off + 7]]);
    let leaf_hi = u16::from_le_bytes([i_block[off + 8], i_block[off + 9]]);
    ((leaf_hi as u64) << 32) | leaf_lo as u64
}

fn slice_idx_lba(buf: &[u8], idx: usize) -> u64 {
    let off = 12 + idx * 12;
    let leaf_lo = u32::from_le_bytes([buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]]);
    let leaf_hi = u16::from_le_bytes([buf[off + 8], buf[off + 9]]);
    ((leaf_hi as u64) << 32) | leaf_lo as u64
}

fn extent_header_entries(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[2], buf[3]])
}

fn extent_header_depth(buf: &[u8]) -> u16 {
    u16::from_le_bytes([buf[6], buf[7]])
}

fn force_external_extent_maxes(disk: &Arc<dyn BlockDevice>, sb: &ext4::Superblock,
                               ino: u32, gen: u32, fs_lba: u64, fs_bs: u32, max: u16) {
    let mut buf = read_fs_block(disk, fs_lba, fs_bs);
    let entries = extent_header_entries(&buf) as usize;
    let depth = extent_header_depth(&buf);
    buf[4..6].copy_from_slice(&max.to_le_bytes());
    // Poking eh_max invalidates the block's metadata_csum tail; re-stamp it so
    // the on-disk block stays consistent (mirrors what a real e2fsprogs tool
    // would do). Without this, read-side verify correctly rejects the block.
    ext4::csum::stamp_extent_block_csum(sb, ino, gen, &mut buf);
    write_fs_block(disk, fs_lba, fs_bs, buf.clone());

    if depth > 0 {
        for i in 0..entries {
            force_external_extent_maxes(disk, sb, ino, gen, slice_idx_lba(&buf, i), fs_bs, max);
        }
    }
}

fn force_tree_external_maxes(disk: &Arc<dyn BlockDevice>, sb: &ext4::Superblock,
                             ino: u32, gen: u32, i_block: &[u8], fs_bs: u32, max: u16) {
    let depth = extent_header_depth(i_block);
    if depth == 0 {
        return;
    }
    for i in 0..extent_header_entries(i_block) as usize {
        force_external_extent_maxes(disk, sb, ino, gen, inline_idx_lba(i_block, i), fs_bs, max);
    }
}

fn leaf_extent_blocks(buf: &[u8]) -> std::vec::Vec<u32> {
    let entries = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    let mut out = std::vec::Vec::with_capacity(entries);
    for i in 0..entries {
        let off = 12 + i * 12;
        out.push(u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]));
    }
    out
}

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
    let m = ext4::Mount::open(disk.clone()).unwrap();
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
    let inode0 = m.read_inode(n).unwrap();
    force_tree_external_maxes(&disk, &m.sb, n, inode0.generation, &inode0.i_block, m.sb.block_size, 4);

    let mut next_lb = 10u32;
    while ext4::parse_extent_header(&m.read_inode(n).unwrap().i_block).unwrap().depth < 3 {
        m.fallocate_inode(n, next_lb as u64 * bs as u64, bs as u64, true).unwrap();
        logicals.push(next_lb);
        let ino_cur = m.read_inode(n).unwrap();
        force_tree_external_maxes(&disk, &m.sb, n, ino_cur.generation, &ino_cur.i_block, m.sb.block_size, 4);
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
    // Force 5 non-contiguous extents by allocating + freeing
    // surrounding blocks between appends. Easiest path: alloc
    // a "spacer" block before each append so the next append's
    // alloc returns a non-contiguous LBA. After 5 successful
    // appends the inline tree must be depth=1.
    let payloads: std::vec::Vec<std::vec::Vec<u8>> = (0..5).map(|i| std::vec![i as u8; bs]).collect();
    for i in 0..5 {
        let _spacer = m.alloc_block(0).unwrap();
        m.append_block(n, &payloads[i]).unwrap();
    }
    let inode = m.read_inode(n).unwrap();
    let hdr = ext4::parse_extent_header(&inode.i_block).unwrap();
    assert!(hdr.depth >= 1, "5 non-contig extents promoted to depth=1");
    // Read each logical block back; they must match.
    for (i, want) in payloads.iter().enumerate() {
        let got = m.read_file_block(&inode, i as u32).unwrap();
        assert_eq!(&got[..], &want[..], "logical block {} round-trips", i);
    }
}

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

#[test]
fn append_survives_remount() {
    let disk = build_disk();
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let ino_n = m.lookup_path(b"/hello.txt").unwrap();
        let payload = std::vec![0x5A; m.sb.block_size as usize];
        m.append_block(ino_n, &payload).unwrap();
    }
    let m2 = ext4::Mount::open(disk).unwrap();
    let ino_n = m2.lookup_path(b"/hello.txt").unwrap();
    let inode = m2.read_inode(ino_n).unwrap();
    let blk = m2.read_file_block(&inode, 1).unwrap();
    assert_eq!(blk[0], 0x5A, "appended block survives close+reopen");
}
