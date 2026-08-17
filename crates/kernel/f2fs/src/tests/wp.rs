//! Settling the drives' write pointers against the volume, at mount.
//!
//! Driven through a real block device that reports zones and records every
//! management command it is given, because that is the only thing the
//! decision modules cannot prove: whether the right command reaches the right
//! zone of the right drive.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::{BlockDevice, BlockError, BlockRequest, KResult as BlockResult, MemDisk,
            Zone as RawZone, ZoneCond as RawCond, ZoneMgmtOp, ZoneReport, ZoneType as RawType};
use sectors::MemImage;
use sync::{Spinlock, TaskList};

use crate::flags::FEATURE_BLKZONED;
use crate::mount::F2fs;
use crate::opts::Options;
use crate::test_image::{self, MAIN_BLKADDR, SEGMENT_COUNT, SEG_MAIN};
use crate::uapi::{BLKSIZE, BLKS_PER_SEG, NR_CURSEG_PERSIST_TYPE, NULL_SEGNO};
use crate::volume::Volume;

const BS: u32 = BLKSIZE as u32;
/// One zone per section, and this fixture's sections are one segment wide.
const ZONE_BLKS: u32 = BLKS_PER_SEG;

/// A drive that reports zones and remembers what it was asked to do to them.
struct ZonedDisk {
    inner: Arc<MemDisk<TaskList>>,
    zones: Vec<RawZone>,
    /// Whether the drive has a finish command at all. A drive without one is
    /// closed by writing its tail instead, which is a different code path and
    /// the only one that touches the medium.
    finishes: bool,
    ops: Spinlock<Vec<(ZoneMgmtOp, u64)>, TaskList>,
}

impl ZonedDisk {
    /// # C: O(1)
    fn new(inner: Arc<MemDisk<TaskList>>, zones: Vec<RawZone>, finishes: bool) -> Arc<Self> {
        Arc::new(Self { inner, zones, finishes, ops: Spinlock::new(Vec::new()) })
    }

    /// Every management command this drive was given, in order. # C: O(1)
    fn ops(&self) -> Vec<(ZoneMgmtOp, u64)> { self.ops.lock().clone() }
}

impl BlockDevice for ZonedDisk {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit_sync(&self, req: &mut BlockRequest) -> BlockResult<()> { self.inner.submit_sync(req) }
    fn flush(&self) -> BlockResult<()> { self.inner.flush() }
    fn zone_report(&self) -> Option<ZoneReport> {
        Some(ZoneReport {
            zone_blocks: u64::from(ZONE_BLKS),
            max_open_zones: None,
            max_active_zones: None,
            max_append_blocks: None,
            zones: self.zones.clone(),
        })
    }
    fn zone_mgmt(&self, op: ZoneMgmtOp, start_block: u64) -> BlockResult<()> {
        self.ops.lock().push((op, start_block));
        if op == ZoneMgmtOp::Finish && !self.finishes { return Err(BlockError::Eopnotsupp); }
        Ok(())
    }
}

/// The one member this fixture's volume names.
const DEV: &str = "/dev/zoned";

/// A zoned fixture image's bytes.
///
/// The member is NAMED so the probe mounts below — which go through a plain
/// image and so answer no zone report — can find the layout at all. A zoned
/// volume that names nothing relies on the mounted drive reporting its zones,
/// which is exactly what a probe does not do.
/// # C: O(image bytes)
fn image() -> Vec<u8> {
    let mut b = test_image::with_root().devices(&[(DEV, SEGMENT_COUNT)]);
    b.feature |= FEATURE_BLKZONED;
    let mut v = Volume::mount_with(MemImage::from_bytes(BS, b.finish()),
                                   Options::defaults(), true).expect("fixture mounts");
    // More than one segment's worth, so the data log FILLS a section and
    // opens another: without that every live section is one a log still
    // stands in, and the zone sweep — which leaves those to the curseg pass —
    // would have nothing to act on at all.
    let ino = v.create(test_image::ROOT_INO, b"big", &spec(), None).expect("create");
    let bytes = vec![0xA5u8; (BLKS_PER_SEG as usize + 1) * BLKSIZE];
    v.write_file(ino, 0, &bytes).expect("write");
    // Marked as a clean close, so the logs' recorded positions are ones a
    // mount may trust. A fixture written by an ordinary checkpoint would have
    // every log moved at every mount, which is correct behaviour and would
    // drown out what these tests are looking at.
    v.commit_with(crate::volume::commit::CpReason::Umount).expect("commit");
    v.into_source().snapshot()
}

/// # C: O(1)
fn spec() -> crate::volume::NewInode {
    crate::volume::NewInode {
        mode: crate::mode::S_IFREG | 0o644,
        uid: 0,
        gid: 0,
        rdev: 0,
        now: (1_800_000_000, 7),
    }
}

/// A device holding `bytes`. # C: O(image bytes)
fn disk(bytes: &[u8]) -> Arc<MemDisk<TaskList>> {
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes.to_vec());
    dev.submit_sync(&mut req).expect("device write");
    dev
}

/// Everything on the device now. # C: O(image bytes)
fn drain(dev: &Arc<MemDisk<TaskList>>) -> Vec<u8> {
    let blocks = dev.capacity_blocks();
    let mut req = BlockRequest::new_read(0, blocks as u32, BS);
    dev.submit_sync(&mut req).expect("device read");
    req.buffer
}

/// One sequential zone of the main area. # C: O(1)
fn zone(index: u32, wp: u64, cond: RawCond) -> RawZone {
    let start = u64::from(MAIN_BLKADDR + index * ZONE_BLKS);
    RawZone {
        start_block: start,
        len_blocks: u64::from(ZONE_BLKS),
        capacity_blocks: u64::from(ZONE_BLKS),
        kind: RawType::SeqWriteRequired,
        wp_block: Some(wp),
        cond,
    }
}

/// A report that agrees with the volume exactly: each zone's pointer is where
/// this filesystem's own account says the drive should have stopped.
///
/// Built by asking the volume rather than by assuming a layout: which section
/// holds live blocks and where each log stands are properties of the fixture,
/// and a report written from a guess would be testing the guess.
/// # C: O(main segments)
fn agreeing(bytes: &[u8]) -> Vec<RawZone> {
    let mut v = Volume::mount_with(MemImage::from_bytes(BS, bytes.to_vec()),
                                   Options::defaults(), false).expect("probe mount");
    v.load_segments().expect("segments");
    let mut out = Vec::with_capacity(SEG_MAIN as usize);
    for i in 0..SEG_MAIN {
        let start = u64::from(MAIN_BLKADDR + i * ZONE_BLKS);
        let log = (0..NR_CURSEG_PERSIST_TYPE).find(|&l| v.curseg_segno(l) == i);
        out.push(match log {
            // A log stands here: the drive stopped exactly where the log will
            // resume, which is what an orderly close leaves behind.
            Some(l) => {
                let off = u64::from(v.curseg_blkoff(l));
                let cond = if off == 0 { RawCond::Empty } else { RawCond::ImplicitOpen };
                zone(i, start + off, cond)
            }
            None if v.section_valid(i) == 0 => zone(i, start, RawCond::Empty),
            None => zone(i, start + u64::from(ZONE_BLKS), RawCond::Full),
        });
    }
    out
}

/// Mount `bytes` over a drive reporting `zones`. # C: O(image bytes)
fn mount(bytes: &[u8], zones: Vec<RawZone>, finishes: bool)
    -> (vfs::KResult<Arc<F2fs>>, Arc<ZonedDisk>) {
    let inner = disk(bytes);
    let dev = ZonedDisk::new(inner, zones, finishes);
    let fs = F2fs::open_with(dev.clone(), DEV, true, Options::defaults());
    (fs, dev)
}

/// The index of a zone whose section holds no live block, and one whose
/// section does. # C: O(main segments)
fn an_empty_and_a_live_zone(bytes: &[u8]) -> (u32, u32) {
    let mut v = Volume::mount_with(MemImage::from_bytes(BS, bytes.to_vec()),
                                   Options::defaults(), false).expect("probe mount");
    v.load_segments().expect("segments");
    let live = (0..SEG_MAIN)
        .find(|&i| {
            v.section_valid(i) > 0
                && !(0..NR_CURSEG_PERSIST_TYPE).any(|l| v.curseg_segno(l) == i)
        })
        .expect("a live section no log stands in");
    let empty = (0..SEG_MAIN)
        .find(|&i| {
            v.section_valid(i) == 0
                && !(0..NR_CURSEG_PERSIST_TYPE).any(|l| v.curseg_segno(l) == i)
        })
        .expect("an empty section no log stands in");
    (empty, live)
}

#[test]
fn a_drive_that_agrees_with_the_volume_is_not_touched() {
    // The whole point of the sweep is that it does nothing on a healthy
    // volume: a pass that reset zones it merely could not explain would
    // discard live data at every mount.
    let bytes = image();
    let zones = agreeing(&bytes);
    let (fs, dev) = mount(&bytes, zones, true);
    fs.expect("mounts");
    assert_eq!(dev.ops(), Vec::new());
}

#[test]
fn a_zone_with_no_live_block_and_a_pointer_that_moved_is_reset() {
    let bytes = image();
    let (empty, _) = an_empty_and_a_live_zone(&bytes);
    let mut zones = agreeing(&bytes);
    let start = zones[empty as usize].start_block;
    zones[empty as usize] = zone(empty, start + 3, RawCond::ImplicitOpen);
    let (fs, dev) = mount(&bytes, zones, true);
    fs.expect("mounts");
    assert_eq!(dev.ops(), vec![(ZoneMgmtOp::Reset, start)]);
}

#[test]
fn a_zone_with_live_blocks_and_the_wrong_pointer_is_finished() {
    // Nothing is discarded: the blocks are wanted, and the zone is closed so
    // that it stops being a candidate for allocation instead.
    let bytes = image();
    let (_, live) = an_empty_and_a_live_zone(&bytes);
    let mut zones = agreeing(&bytes);
    let start = zones[live as usize].start_block;
    zones[live as usize] = zone(live, start + 1, RawCond::ImplicitOpen);
    let (fs, dev) = mount(&bytes, zones, true);
    fs.expect("mounts");
    assert_eq!(dev.ops(), vec![(ZoneMgmtOp::Finish, start)]);
}

#[test]
fn a_drive_with_no_finish_command_has_its_zone_tail_written_out() {
    // The long way round, and the only repair that touches the medium. The
    // blocks written are past the drive's pointer, so they hold nothing it
    // has ever been given.
    let bytes = image();
    let (_, live) = an_empty_and_a_live_zone(&bytes);
    let mut zones = agreeing(&bytes);
    let start = zones[live as usize].start_block;
    let wp = start + 1;
    zones[live as usize] = zone(live, wp, RawCond::ImplicitOpen);
    let (fs, dev) = mount(&bytes, zones, false);
    fs.expect("mounts");
    assert_eq!(dev.ops(), vec![(ZoneMgmtOp::Finish, start)]);
    let after = drain(&dev.inner);
    let from = wp as usize * BLKSIZE;
    let to = (start as usize + ZONE_BLKS as usize) * BLKSIZE;
    assert!(after[from..to].iter().all(|&b| b == 0), "the tail past the pointer is written out");
    // And nothing before the pointer moved.
    assert_eq!(after[..from], bytes[..from], "nothing before the pointer is touched");
}

#[test]
fn a_zone_a_log_stands_in_is_left_to_the_curseg_pass() {
    // Reported as holding live blocks with a pointer at the start, which for
    // any other zone is a `Finish`. The log's own zone is settled against the
    // drive separately, and repairing it from both sides would close a zone
    // the log is about to write into.
    let bytes = image();
    let mut zones = agreeing(&bytes);
    let mut v = Volume::mount_with(MemImage::from_bytes(BS, bytes.to_vec()),
                                   Options::defaults(), false).expect("probe");
    v.load_segments().expect("segments");
    let log = (0..NR_CURSEG_PERSIST_TYPE)
        .find(|&l| v.curseg_segno(l) != NULL_SEGNO && v.section_valid(v.curseg_segno(l)) > 0)
        .expect("a log standing in a section with live blocks");
    let at = v.curseg_segno(log);
    let start = zones[at as usize].start_block;
    let off = u64::from(v.curseg_blkoff(log));
    drop(v);
    zones[at as usize] = zone(at, start + off, RawCond::ImplicitOpen);
    let (fs, dev) = mount(&bytes, zones, true);
    fs.expect("mounts");
    // The log agrees with the drive, so nothing at all happens to its zone.
    assert!(!dev.ops().iter().any(|&(_, b)| b == start), "{:?}", dev.ops());
}

#[test]
fn a_log_the_drive_has_run_ahead_of_is_moved_to_a_fresh_section() {
    // The drive has taken blocks this log does not account for. Appending
    // where the log believes it stopped would be refused by the drive, so the
    // log is opened somewhere the drive will certainly take.
    let bytes = image();
    let mut zones = agreeing(&bytes);
    let mut v = Volume::mount_with(MemImage::from_bytes(BS, bytes.to_vec()),
                                   Options::defaults(), false).expect("probe");
    v.load_segments().expect("segments");
    let log = (0..NR_CURSEG_PERSIST_TYPE)
        .find(|&l| v.curseg_segno(l) != NULL_SEGNO)
        .expect("a log");
    let at = v.curseg_segno(log);
    let before = at;
    drop(v);
    let start = zones[at as usize].start_block;
    zones[at as usize] = zone(at, start + 5, RawCond::ImplicitOpen);
    let (fs, _dev) = mount(&bytes, zones, true);
    let fs = fs.expect("mounts");
    let after = fs.volume.lock().curseg_segno(log);
    assert_ne!(after, before, "the log must not be left where the drive will refuse it");
    assert_ne!(after, NULL_SEGNO);
    assert_eq!(fs.volume.lock().curseg_blkoff(log), 0, "and it starts at the head of its zone");
}
