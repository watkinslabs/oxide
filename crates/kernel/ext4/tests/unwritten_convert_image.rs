//! Writing one block into a `fallocate(2)` preallocation must cost one block of
//! device I/O and must leave the rest of the preallocation preallocated.
//!
//! A preallocated range is mapped UNWRITTEN: allocated, but reading as zeros
//! rather than the stale bytes still on the media. Making one block written can
//! be done two ways — zero the whole extent and clear its flag, or split the
//! extent so only that block is initialized. The first turns a journal-writer's
//! first log line into one device write per preallocated block.
//!
//! These drive the real write path over a real image and count device traffic.
//!
//! The fixture deliberately targets a block inside the LARGE extent: this
//! image's preallocation is fragmented (a 1-block extent, a 15-block extent,
//! then the rest), and a block landing in the 1-block extent costs the same
//! either way — a test written against it cannot fail.

extern crate alloc;
mod common;

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use block::{BlockDevice, BlockOp, BlockRequest, MemDisk};
use sync::TaskList;
use vfs::fs::FileSystem;

const IMAGE: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;
/// Preallocation size, and a target block well inside its largest extent.
const PREALLOC_BLOCKS: u64 = 256;
const TARGET_BLOCK: u64 = 64;

/// Passes every request through to a `MemDisk` while counting the sectors that
/// writes actually move — the amplification these tests bound.
struct CountingDisk {
    inner: Arc<MemDisk<TaskList>>,
    write_sectors: AtomicU64,
}

impl BlockDevice for CountingDisk {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit_sync(&self, req: &mut BlockRequest) -> block::KResult<()> {
        if matches!(req.op, BlockOp::Write) {
            self.write_sectors.fetch_add(req.len_blocks as u64, Ordering::Relaxed);
        }
        self.inner.submit_sync(req)
    }
    fn flush(&self) -> Result<(), block::BlockError> { self.inner.flush() }
}

fn build() -> Arc<CountingDisk> {
    let cap = (IMAGE.len() as u64) / (SECTOR as u64);
    let inner: Arc<MemDisk<TaskList>> = MemDisk::new(SECTOR, cap);
    let mut req = BlockRequest {
        op: BlockOp::Write, start_block: 0, len_blocks: cap as u32,
        buffer: IMAGE.to_vec(), ..Default::default() };
    inner.submit_sync(&mut req).unwrap();
    Arc::new(CountingDisk { inner, write_sectors: AtomicU64::new(0) })
}

struct Fixture {
    m: Arc<ext4::rootfs::Ext4Mount>,
    disk: Arc<CountingDisk>,
    ino: u32,
    bs: u64,
}

fn preallocated(name: &[u8]) -> Fixture {
    common::boot_hosted_pmm();
    let disk = build();
    let m = ext4::rootfs::Ext4Mount::open(disk.clone()).unwrap();
    let fs: Arc<dyn FileSystem> = m.clone();
    let root = fs.root();
    let _sb = common::realize_sb(fs.clone(), root, 0x5348_4654, String::from("ext4"));
    let bs = m.state().mount.sb.block_size as u64;
    let ino = m.state().mount.create_file(2, name, 0o644, 0, 0).unwrap();
    m.state().mount.fallocate_inode(ino, 0, PREALLOC_BLOCKS * bs, false).expect("fallocate");
    m.state().mount.commit_batch().expect("commit prealloc");
    Fixture { m, disk, ino, bs }
}

/// Blocks of the extent covering `lb`, and whether it is still unwritten.
fn extent_at(f: &Fixture, lb: u64) -> (u32, bool) {
    let map = f.m.state().mount.extent_map(f.ino).expect("extent_map");
    for (logical, _phys, blocks, unwritten) in map {
        if lb as u32 >= logical && (lb as u32) < logical + blocks { return (blocks, unwritten); }
    }
    panic!("no extent covers logical block {lb}");
}

/// The cost bound: converting one block must not drag its whole extent through
/// the device.
#[test]
fn one_block_write_does_not_move_its_whole_extent() {
    let f = preallocated(b"cost");
    let (extent_blocks, unwritten) = extent_at(&f, TARGET_BLOCK);
    assert!(unwritten, "fixture precondition: target block must start unwritten");
    assert!(extent_blocks > 32,
        "fixture precondition: target must sit in a large extent, got {extent_blocks} blocks");

    let sectors_per_block = f.bs / (SECTOR as u64);
    let before = f.disk.write_sectors.load(Ordering::Relaxed);
    f.m.state().mount.write_at(f.ino, TARGET_BLOCK * f.bs, &alloc::vec![0xABu8; f.bs as usize])
        .expect("write");
    f.m.state().mount.commit_batch().expect("commit");
    let moved = f.disk.write_sectors.load(Ordering::Relaxed) - before;

    let whole_extent = (extent_blocks as u64) * sectors_per_block;
    assert!(moved < whole_extent / 4,
        "writing 1 block moved {moved} sectors; its extent is {extent_blocks} blocks \
         ({whole_extent} sectors) — the extent is being converted wholesale");
}

/// The preallocation survives: only the written block becomes initialized, and
/// the remainder stays unwritten rather than being consumed by the first write.
#[test]
fn the_remainder_of_the_extent_stays_preallocated() {
    let f = preallocated(b"remainder");
    let (before_blocks, _) = extent_at(&f, TARGET_BLOCK);
    f.m.state().mount.write_at(f.ino, TARGET_BLOCK * f.bs, &alloc::vec![0xABu8; f.bs as usize])
        .expect("write");
    f.m.state().mount.commit_batch().expect("commit");

    let (hit_blocks, hit_unwritten) = extent_at(&f, TARGET_BLOCK);
    assert!(!hit_unwritten, "the written block must be initialized");
    assert_eq!(hit_blocks, 1, "only the written block should have been converted");

    let (_, before_unwritten) = extent_at(&f, TARGET_BLOCK - 1);
    let (_, after_unwritten) = extent_at(&f, TARGET_BLOCK + 1);
    assert!(before_unwritten && after_unwritten,
        "the untouched remainder on both sides must stay preallocated (unwritten), \
         not be initialized by a neighbouring write — it was {before_blocks} blocks");
}

/// The unwritten-read contract holds across the split: untouched blocks still
/// read as zeros, and the written block reads back its own bytes.
#[test]
fn untouched_blocks_still_read_as_zeros() {
    let f = preallocated(b"zeros");
    f.m.state().mount.write_at(f.ino, TARGET_BLOCK * f.bs, &alloc::vec![0xABu8; f.bs as usize])
        .expect("write");
    f.m.state().mount.commit_batch().expect("commit");

    let di = f.m.state().mount.read_inode(f.ino).unwrap();
    let written = f.m.state().mount.read_file_block(&di, TARGET_BLOCK as u32).expect("read written");
    assert!(written.iter().all(|&b| b == 0xAB), "the written block must read back its own bytes");

    for lb in [0u32, 17, 63, 65, 200] {
        let blk = f.m.state().mount.read_file_block(&di, lb).expect("read untouched");
        assert!(blk.iter().all(|&b| b == 0),
            "block {lb} was never written and must read as zeros, not stale media");
    }
}

/// A partial write into a preallocated block must not expose whatever the media
/// held under the rest of that block.
#[test]
fn a_partial_write_zeros_the_rest_of_its_block() {
    let f = preallocated(b"partial");
    let off = TARGET_BLOCK * f.bs;
    f.m.state().mount.write_at(f.ino, off + 4, &[0xCD; 4]).expect("partial write");
    f.m.state().mount.commit_batch().expect("commit");

    let di = f.m.state().mount.read_inode(f.ino).unwrap();
    let blk = f.m.state().mount.read_file_block(&di, TARGET_BLOCK as u32).expect("read");
    assert_eq!(&blk[4..8], &[0xCD; 4], "the written bytes must land");
    assert!(blk[0..4].iter().all(|&b| b == 0) && blk[8..].iter().all(|&b| b == 0),
        "the rest of a partially-written preallocated block must read as zeros");
}
