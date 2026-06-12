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
    let n = m.create_file(2, b"wa.bin", 0o644).unwrap();
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
fn truncate_shrinks_and_frees_blocks() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"shrink.bin", 0o644).unwrap();
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
fn append_promotes_inline_to_depth1_when_full() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"deep.bin", 0o644).unwrap();
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
fn truncate_depth1_frees_tail_and_keeps_head() {
    // Regression: truncate_inode must work at depth>=1 (was DepthUnsupported,
    // so truncating ANY multi-extent file failed).
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"trunc_deep.bin", 0o644).unwrap();
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
    // The 4 tail data blocks were freed.
    assert!(m.state_free_blocks() >= pre_free + 4, "freed >=4 tail data blocks");
    // A truncated logical block no longer resolves.
    assert!(m.read_file_block(&inode2, 2).is_err(), "block past new EOF is gone");
}

#[test]
fn truncate_depth1_to_zero_resets_to_empty() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"trunc_zero.bin", 0o644).unwrap();
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
    let n = m.create_file(2, b"deeprmw.bin", 0o644).unwrap();
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
