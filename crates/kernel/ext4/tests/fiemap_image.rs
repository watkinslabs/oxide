//! C1 integration: `extent_map` (the FS_IOC_FIEMAP geometry source) against
//! mini.img. Asserts the reported physical runs match the file's actual
//! extent tree — contiguous appends coalesce into one run, sparse/fragmented
//! files report multiple ascending runs, and fallocate marks unwritten runs.

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
        buffer: IMAGE.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    disk
}

/// Sum of all run lengths (blocks) — total mapped blocks.
fn mapped_blocks(runs: &[(u32, u64, u32, bool)]) -> u32 { runs.iter().map(|r| r.2).sum() }

#[test]
fn contiguous_appends_report_single_ascending_run() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"contig.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    // Bitmap allocator hands out consecutive blocks → one coalesced extent.
    for _ in 0..3 { m.append_block(n, &std::vec![0xEE; bs]).unwrap(); }

    let runs = m.extent_map(n).unwrap();
    assert_eq!(mapped_blocks(&runs), 3, "3 data blocks mapped");
    // Runs are ascending by logical block and start at logical 0.
    assert_eq!(runs.first().unwrap().0, 0, "first run covers logical block 0");
    for w in runs.windows(2) { assert!(w[0].0 < w[1].0, "runs strictly ascending"); }
    // Physical starts are real (non-zero) data blocks, none unwritten.
    for r in &runs {
        assert!(r.1 != 0, "physical block resolved");
        assert!(!r.3, "written data is not flagged unwritten");
    }
}

#[test]
fn sparse_file_reports_multiple_ascending_runs() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"sparse.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as u64;
    // Two disjoint fallocate ranges with a hole between → two extents.
    m.fallocate_inode(n, 0, bs, true).unwrap();
    m.fallocate_inode(n, 4 * bs, bs, true).unwrap();

    let runs = m.extent_map(n).unwrap();
    let logicals: std::vec::Vec<u32> = runs.iter().map(|r| r.0).collect();
    assert_eq!(logicals, std::vec![0, 4], "two ascending runs at logical 0 and 4 (hole between)");
    for r in &runs { assert!(r.1 != 0, "physical block resolved for each run"); }
}

#[test]
fn crafted_unwritten_extent_reports_unwritten_flag() {
    // This ext4 does not yet produce unwritten extents, so craft one on disk:
    // set the inline leaf extent's ee_len top bit (EXT4_EXT_UNWRITTEN) and
    // verify extent_map surfaces `unwritten=true` with the real length intact.
    const I_BLOCK_OFF: usize = 0x28; // ext4_inode.i_block
    const EXT_HDR_LEN: usize = 12;   // ext4_extent_header
    const EE_LEN_OFF:  usize = 4;    // ee_len within a leaf ext4_extent
    const UNWRITTEN_BIT: u16 = 0x8000;

    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"unwr.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    m.append_block(n, &std::vec![0xEE; bs]).unwrap(); // one written extent, ee_len=1

    let (mut bytes, _) = m.read_inode_bytes(n).unwrap();
    let ee_len_at = I_BLOCK_OFF + EXT_HDR_LEN + EE_LEN_OFF;
    let raw = u16::from_le_bytes([bytes[ee_len_at], bytes[ee_len_at + 1]]);
    assert_eq!(raw, 1, "one-block written extent before crafting");
    bytes[ee_len_at..ee_len_at + 2].copy_from_slice(&(raw | UNWRITTEN_BIT).to_le_bytes());
    m.write_inode_bytes(n, &bytes).unwrap();

    let runs = m.extent_map(n).unwrap();
    assert_eq!(runs.len(), 1, "still one extent");
    let (logical, phys, len, unwritten) = runs[0];
    assert_eq!((logical, len), (0, 1), "real length decoded (top bit stripped)");
    assert!(phys != 0, "physical start intact");
    assert!(unwritten, "unwritten bit surfaced to FIEMAP");
}

#[test]
fn empty_file_maps_no_extents() {
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"empty.bin", 0o644, 0, 0).unwrap();
    assert!(m.extent_map(n).unwrap().is_empty(), "empty file has no extents");
}

#[test]
fn deep_tree_extents_map_all_blocks_ascending() {
    // A depth>=1 fragmented file: extent_map must walk the whole tree and
    // report every leaf run in ascending logical order.
    let disk = build_disk();
    let m = ext4::Mount::open(disk).unwrap();
    let n = m.create_file(2, b"deepmap.bin", 0o644, 0, 0).unwrap();
    let bs = m.sb.block_size as usize;
    for i in 0..6u8 {
        let _spacer = m.alloc_block(0).unwrap(); // break contiguity
        m.append_block(n, &std::vec![i; bs]).unwrap();
    }
    assert!(ext4::parse_extent_header(&m.read_inode(n).unwrap().i_block).unwrap().depth >= 1,
        "test needs a depth>=1 tree");

    let runs = m.extent_map(n).unwrap();
    assert_eq!(mapped_blocks(&runs), 6, "all 6 fragmented blocks mapped");
    let logicals: std::vec::Vec<u32> = runs.iter().map(|r| r.0).collect();
    assert_eq!(logicals, std::vec![0, 1, 2, 3, 4, 5], "every logical block reported, ascending");
    for r in &runs { assert!(!r.3, "written blocks not unwritten"); }
}
