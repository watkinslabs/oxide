//! End-to-end acceptance for the two fallocate range-shift modes against a
//! real metadata_csum image: COLLAPSE_RANGE removes a range and pulls the tail
//! down, INSERT_RANGE opens a hole and pushes the tail up. Both re-index every
//! extent past the range, so the checks are (a) the bytes land at their new
//! offsets, (b) `i_size` moves by exactly the range length, (c) the physical
//! blocks behave as the mode requires — freed by a collapse, untouched by an
//! insert — and (d) `e2fsck -fn` still calls the image clean afterwards.

extern crate alloc;
use alloc::sync::Arc;

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;

const MINI: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;
/// Blocks written into the fixture file before each shift.
const FILE_BLOCKS: u32 = 8;
/// Range start and length used by every shift here, in blocks.
const RANGE_START_BLOCKS: u64 = 2;
const RANGE_LEN_BLOCKS: u64 = 2;

fn build_disk(image: &[u8]) -> (Arc<dyn BlockDevice>, u64) {
    let cap = (image.len() as u64) / (SECTOR as u64);
    let disk: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: image.to_vec(), ..Default::default() };
    disk.submit_sync(&mut req).unwrap();
    (disk, cap)
}

fn dump_disk(disk: &Arc<dyn BlockDevice>, cap: u64) -> std::vec::Vec<u8> {
    let mut req = BlockRequest::new_read(0, cap as u32, SECTOR);
    disk.submit_sync(&mut req).unwrap();
    req.buffer
}

/// `e2fsck -fn` over the image bytes: `Some(true)` clean, `Some(false)` errors,
/// `None` when e2fsck is not installed (the caller then skips that assertion).
fn e2fsck_clean(bytes: &[u8]) -> Option<bool> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let uniq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(std::format!("oxide-ext4-shift-{}-{}.img", std::process::id(), uniq));
    {
        let mut f = std::fs::File::create(&path).ok()?;
        f.write_all(bytes).ok()?;
    }
    let out = std::process::Command::new("e2fsck").arg("-fn").arg(&path).output();
    let _ = std::fs::remove_file(&path);
    match out {
        Ok(o) => {
            if !o.status.success() {
                eprintln!("--- e2fsck stdout ---\n{}", String::from_utf8_lossy(&o.stdout));
                eprintln!("--- e2fsck stderr ---\n{}", String::from_utf8_lossy(&o.stderr));
            }
            Some(o.status.success())
        }
        Err(_) => None,
    }
}

/// A file of `FILE_BLOCKS` blocks whose block `i` is filled with the byte `i`,
/// so a shifted layout is readable straight off the block contents.
fn tagged_file(m: &ext4::Mount, name: &[u8]) -> (u32, usize) {
    let bs = m.sb.block_size as usize;
    let n = m.create_file(2, name, 0o644, 0, 0).unwrap();
    for i in 0..FILE_BLOCKS {
        m.write_at(n, i as u64 * bs as u64, &std::vec![i as u8; bs]).unwrap();
    }
    (n, bs)
}

fn block_tags(m: &ext4::Mount, ino: u32, count: u32) -> std::vec::Vec<u8> {
    let inode = m.read_inode(ino).unwrap();
    (0..count).map(|lb| m.read_file_block(&inode, lb).unwrap()[0]).collect()
}

/// Every physical block the file's extents currently own. # C: O(extents)
fn owned_blocks(m: &ext4::Mount, ino: u32) -> std::vec::Vec<u64> {
    let mut out = std::vec::Vec::new();
    for (_logical, phys, len, _unwritten) in m.extent_map(ino).unwrap() {
        for k in 0..len as u64 { out.push(phys + k); }
    }
    out.sort_unstable();
    out
}

#[test]
fn collapse_range_removes_the_range_and_pulls_the_tail_down() {
    let (disk, _cap) = build_disk(MINI);
    let m = ext4::Mount::open(disk).unwrap();
    let (n, bs) = tagged_file(&m, b"collapse.bin");
    let (off, len) = (RANGE_START_BLOCKS * bs as u64, RANGE_LEN_BLOCKS * bs as u64);

    let before = owned_blocks(&m, n);
    m.collapse_range_inode(n, off, len).unwrap();

    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, (FILE_BLOCKS as u64 - RANGE_LEN_BLOCKS) * bs as u64,
        "i_size shrinks by exactly the collapsed length");
    assert_eq!(block_tags(&m, n, FILE_BLOCKS - RANGE_LEN_BLOCKS as u32),
        std::vec![0, 1, 4, 5, 6, 7],
        "blocks 2 and 3 are gone and everything past them moved down two");

    let after = owned_blocks(&m, n);
    assert_eq!(after.len(), before.len() - RANGE_LEN_BLOCKS as usize,
        "the collapsed blocks are released, not merely unmapped");
    for b in &after { assert!(before.contains(b), "no surviving block was relocated"); }
}

#[test]
fn insert_range_opens_a_hole_and_pushes_the_tail_up() {
    let (disk, _cap) = build_disk(MINI);
    let m = ext4::Mount::open(disk).unwrap();
    let (n, bs) = tagged_file(&m, b"insert.bin");
    let (off, len) = (RANGE_START_BLOCKS * bs as u64, RANGE_LEN_BLOCKS * bs as u64);

    let before = owned_blocks(&m, n);
    m.insert_range_inode(n, off, len).unwrap();

    let inode = m.read_inode(n).unwrap();
    assert_eq!(inode.size, (FILE_BLOCKS as u64 + RANGE_LEN_BLOCKS) * bs as u64,
        "i_size grows by exactly the inserted length");
    assert_eq!(block_tags(&m, n, FILE_BLOCKS + RANGE_LEN_BLOCKS as u32),
        std::vec![0, 1, 0, 0, 2, 3, 4, 5, 6, 7],
        "a two-block hole reading as zeros opened at block 2");
    assert_eq!(owned_blocks(&m, n), before,
        "an insert allocates and frees nothing — only logical numbers move");
}

#[test]
fn a_collapse_that_lands_on_a_hole_still_moves_the_tail() {
    let (disk, _cap) = build_disk(MINI);
    let m = ext4::Mount::open(disk).unwrap();
    let (n, bs) = tagged_file(&m, b"punched.bin");
    // Punch first so the collapsed range is already unmapped: the shift must
    // work off the extent geometry, not off an assumption that the range maps.
    m.punch_hole_inode(n, RANGE_START_BLOCKS * bs as u64, RANGE_LEN_BLOCKS * bs as u64).unwrap();
    let before = owned_blocks(&m, n);

    m.collapse_range_inode(n, RANGE_START_BLOCKS * bs as u64, RANGE_LEN_BLOCKS * bs as u64).unwrap();

    assert_eq!(m.read_inode(n).unwrap().size, (FILE_BLOCKS as u64 - RANGE_LEN_BLOCKS) * bs as u64);
    assert_eq!(block_tags(&m, n, FILE_BLOCKS - RANGE_LEN_BLOCKS as u32), std::vec![0, 1, 4, 5, 6, 7]);
    assert_eq!(owned_blocks(&m, n), before, "a hole gives nothing back a second time");
}

#[test]
fn collapse_then_insert_of_the_same_range_restores_the_layout() {
    let (disk, _cap) = build_disk(MINI);
    let m = ext4::Mount::open(disk).unwrap();
    let (n, bs) = tagged_file(&m, b"roundtrip.bin");
    let (off, len) = (RANGE_START_BLOCKS * bs as u64, RANGE_LEN_BLOCKS * bs as u64);

    m.collapse_range_inode(n, off, len).unwrap();
    m.insert_range_inode(n, off, len).unwrap();

    assert_eq!(m.read_inode(n).unwrap().size, FILE_BLOCKS as u64 * bs as u64,
        "the two shifts are exact inverses in size");
    assert_eq!(block_tags(&m, n, FILE_BLOCKS), std::vec![0, 1, 0, 0, 4, 5, 6, 7],
        "the collapsed data is gone for good; its slot comes back as a hole");
}

#[test]
fn shifting_a_deep_extent_tree_keeps_every_block_readable() {
    let (disk, _cap) = build_disk(MINI);
    let m = ext4::Mount::open(disk).unwrap();
    let bs = m.sb.block_size as usize;
    let n = m.create_file(2, b"deepshift.bin", 0o644, 0, 0).unwrap();
    // A spacer held allocated between appends breaks contiguity, so the inline
    // root (4 records) overflows and the file gets an external extent tree —
    // the case where a shift must rebuild metadata nodes, not just edit i_block.
    let mut spacers = std::vec::Vec::new();
    let deep_blocks = 6u8;
    for i in 0..deep_blocks {
        spacers.push(m.alloc_block(0).unwrap());
        m.append_block(n, &std::vec![i; bs]).unwrap();
    }
    assert!(m.extent_map(n).unwrap().len() > 4, "fixture really has an external tree");
    for b in spacers { m.free_block(b).unwrap(); }

    m.insert_range_inode(n, bs as u64, bs as u64).unwrap();
    assert_eq!(block_tags(&m, n, deep_blocks as u32 + 1), std::vec![0, 0, 1, 2, 3, 4, 5]);

    m.collapse_range_inode(n, bs as u64, bs as u64).unwrap();
    assert_eq!(block_tags(&m, n, deep_blocks as u32), std::vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(m.read_inode(n).unwrap().size, deep_blocks as u64 * bs as u64);
}

#[test]
fn range_shifts_leave_an_e2fsck_clean_image() {
    let (disk, cap) = build_disk(MINI);
    {
        let m = ext4::Mount::open(disk.clone()).unwrap();
        let (c, bs) = tagged_file(&m, b"fsck_collapse.bin");
        m.collapse_range_inode(c, RANGE_START_BLOCKS * bs as u64, RANGE_LEN_BLOCKS * bs as u64).unwrap();
        let (i, _) = tagged_file(&m, b"fsck_insert.bin");
        m.insert_range_inode(i, RANGE_START_BLOCKS * bs as u64, RANGE_LEN_BLOCKS * bs as u64).unwrap();
    }
    match e2fsck_clean(&dump_disk(&disk, cap)) {
        Some(true)  => {}
        Some(false) => panic!("e2fsck reported errors after a range shift"),
        None        => eprintln!("e2fsck not available — skipped fsck assertion"),
    }
}
