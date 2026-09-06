//! VFS fsync durability and request counts on a volatile-cache device.

extern crate alloc;
mod common;

use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use block::{BlockDevice, BlockError, BlockOp, BlockRequest, KResult};
use block::queue_limits::{QueueFeatures, QueueLimits};
use vfs::{Dentry, File, OpenFlags, SuperBlock};
use vfs::fs::FileSystem;

const IMAGE: &[u8] = include_bytes!("mini-j.img");
const NOJOURNAL: &[u8] = include_bytes!("mini.img");
const SECTOR: u32 = 512;
const MODE: u16 = 0o644;
const JSB_START: usize = 0x1c;
const WAIT_BOUND: Duration = Duration::from_secs(5);
const EARLY_RETURN_BOUND: Duration = Duration::from_millis(100);

struct Media { cache: Vec<u8>, stable: Vec<u8>, writes: Vec<(u64, u32)>, flushes: usize }
struct CountingDev {
    media: Mutex<Media>, fail_flush: AtomicBool,
    flush_pause: Mutex<Option<(Sender<()>, Receiver<()>)>>,
}

impl CountingDev {
    fn new(image: &[u8]) -> Arc<Self> {
        Arc::new(Self { media: Mutex::new(Media {
            cache: image.to_vec(), stable: image.to_vec(), writes: Vec::new(), flushes: 0,
        }), fail_flush: AtomicBool::new(false), flush_pause: Mutex::new(None) })
    }
    fn reset(&self) {
        let mut m = self.media.lock().unwrap();
        m.writes.clear(); m.flushes = 0;
    }
    fn crash_copy(&self) -> Arc<Self> { Self::new(&self.media.lock().unwrap().stable) }
    fn counts(&self) -> (usize, usize) {
        let m = self.media.lock().unwrap(); (m.writes.len(), m.flushes)
    }
    fn pause_flush(&self) -> (Receiver<()>, Sender<()>) {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        *self.flush_pause.lock().unwrap() = Some((entered_tx, release_rx));
        (entered_rx, release_tx)
    }
}

impl BlockDevice for CountingDev {
    fn block_size(&self) -> u32 { SECTOR }
    fn capacity_blocks(&self) -> u64 { self.media.lock().unwrap().cache.len() as u64 / SECTOR as u64 }
    fn queue_limits(&self) -> KResult<QueueLimits> {
        Ok(QueueLimits::for_logical_block_size(SECTOR)?.with_features(QueueFeatures::WRITE_CACHE))
    }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        if req.op == BlockOp::Flush { return self.flush(); }
        let mut m = self.media.lock().unwrap();
        let off = req.start_block as usize * SECTOR as usize;
        let len = req.len_blocks as usize * SECTOR as usize;
        if off + len > m.cache.len() { return Err(BlockError::Eio); }
        match req.op {
            BlockOp::Read => { req.buffer.resize(len, 0); req.buffer.copy_from_slice(&m.cache[off..off + len]); }
            BlockOp::Write => {
                m.cache[off..off + len].copy_from_slice(&req.buffer[..len]);
                m.writes.push((req.start_block, req.len_blocks));
            }
            _ => return Err(BlockError::Eopnotsupp),
        }
        Ok(())
    }
    fn flush(&self) -> KResult<()> {
        let pause = self.flush_pause.lock().unwrap().take();
        if let Some((entered, release)) = pause {
            entered.send(()).unwrap(); release.recv_timeout(WAIT_BOUND).unwrap();
        }
        if self.fail_flush.load(Ordering::Acquire) { return Err(BlockError::Eio); }
        let mut m = self.media.lock().unwrap();
        m.stable = m.cache.clone(); m.flushes += 1;
        Ok(())
    }
}

fn mount(dev: Arc<CountingDev>) -> (Arc<ext4::rootfs::Ext4Mount>, Arc<SuperBlock>) {
    common::boot_hosted_pmm();
    let m = ext4::rootfs::Ext4Mount::open_with_data(dev, None, "data=ordered").unwrap();
    let fs: Arc<dyn FileSystem> = m.clone();
    let sb = common::realize_sb(fs.clone(), fs.root(), 0, "ext4".into());
    (m, sb)
}

fn create(m: &ext4::rootfs::Ext4Mount, name: &[u8]) -> Arc<File> {
    let inode = m.state().create_at(name, MODE).unwrap();
    File::new(inode.clone(), Dentry::new_root(inode), OpenFlags::O_RDWR)
}

#[test]
fn clean_vfs_fsync_creates_no_transaction() {
    let dev = CountingDev::new(IMAGE);
    let (m, _sb) = mount(dev.clone());
    m.state().mount.begin_batch();
    let file = create(&m, b"/clean-fsync");
    file.vfs_fsync(false).unwrap();
    dev.reset();
    file.vfs_fsync(false).unwrap();
    assert_eq!(dev.counts(), (0, 0), "unchanged fsync must not emit another transaction or barrier");
}

#[test]
fn vfs_fsync_commits_journal_without_home_checkpoint_and_replays() {
    let dev = CountingDev::new(IMAGE);
    let (m, _sb) = mount(dev.clone());
    let fs = &m.state().mount;
    let bs = fs.sb.block_size as u64;
    let runs = fs.extent_map(fs.sb.journal_inum).unwrap();
    let jsb_sector = runs.iter().find(|r| r.0 == 0).unwrap().1 * bs / SECTOR as u64;
    fs.begin_batch();
    let file = create(&m, b"/journal-fsync");
    dev.reset();
    file.vfs_fsync(false).unwrap();
    let (writes, anchor) = {
        let media = dev.media.lock().unwrap();
        let start = jsb_sector as usize * SECTOR as usize + JSB_START;
        (media.writes.clone(), media.stable[start..start + 4].to_vec())
    };
    assert!(!writes.is_empty());
    assert!(writes.iter().all(|&(sector, len)| runs.iter().any(|&(_, phys, blocks, _)| {
        sector >= phys * bs / SECTOR as u64
            && sector + len as u64 <= (phys + blocks as u64) * bs / SECTOR as u64
    })), "metadata fsync must write the journal, leaving home blocks for checkpoint");
    assert_ne!(anchor, vec![0; 4], "durable recovery anchor remains published");
    // Snapshot stable media while the original mount is live: Drop must not
    // checkpoint anything into the crash image used by recovery.
    let crashed = dev.crash_copy();
    let (reopened, _reopened_sb) = mount(crashed);
    assert!(reopened.state().lookup_path(b"/journal-fsync").is_some());
}

#[test]
fn ordered_file_data_survives_fsync_without_checkpoint() {
    let dev = CountingDev::new(IMAGE);
    let (m, _sb) = mount(dev.clone());
    m.state().mount.begin_batch();
    let file = create(&m, b"/ordered-fsync");
    let data = vec![0x5a; 4096];
    assert_eq!(file.write(&data).unwrap(), data.len());
    file.vfs_fsync(false).unwrap();
    let (reopened, _sb2) = mount(dev.crash_copy());
    let inode = reopened.state().lookup_inode_any(b"/ordered-fsync").unwrap();
    let mut got = vec![0; data.len()];
    assert_eq!(inode.read(0, &mut got).unwrap(), data.len());
    assert_eq!(got, data);
}

#[test]
fn nojournal_fsync_flushes_direct_writes() {
    let dev = CountingDev::new(NOJOURNAL);
    let (m, _sb) = mount(dev.clone());
    m.state().mount.begin_batch();
    let file = create(&m, b"/direct-fsync");
    dev.reset();
    file.vfs_fsync(false).unwrap();
    assert_eq!(dev.counts().1, 1, "direct metadata needs exactly one durability barrier");
    let (reopened, _sb2) = mount(dev.crash_copy());
    assert!(reopened.state().lookup_path(b"/direct-fsync").is_some());
}

#[test]
fn failed_journal_barrier_does_not_report_fsync_success() {
    let dev = CountingDev::new(IMAGE);
    let (m, _sb) = mount(dev.clone());
    m.state().mount.begin_batch();
    let file = create(&m, b"/failed-fsync");
    dev.fail_flush.store(true, Ordering::Release);
    assert!(file.vfs_fsync(false).is_err());
    let before_commit = dev.crash_copy();
    dev.fail_flush.store(false, Ordering::Release);
    let (reopened, _sb2) = mount(before_commit);
    assert!(reopened.state().lookup_path(b"/failed-fsync").is_none());
}

#[test]
fn consecutive_commits_replay_with_the_oldest_anchor() {
    let dev = CountingDev::new(IMAGE);
    let (m, _sb) = mount(dev.clone());
    m.state().mount.begin_batch();
    create(&m, b"/first-commit").vfs_fsync(false).unwrap();
    create(&m, b"/second-commit").vfs_fsync(false).unwrap();
    let (reopened, _sb2) = mount(dev.crash_copy());
    assert!(reopened.state().lookup_path(b"/first-commit").is_some());
    assert!(reopened.state().lookup_path(b"/second-commit").is_some());
}

#[test]
fn nojournal_flush_failure_can_be_retried_after_metadata_commit() {
    let dev = CountingDev::new(NOJOURNAL);
    let (m, _sb) = mount(dev.clone());
    m.state().mount.begin_batch();
    let file = create(&m, b"/retry-direct");
    dev.fail_flush.store(true, Ordering::Release);
    assert!(file.vfs_fsync(false).is_err());
    dev.fail_flush.store(false, Ordering::Release);
    // Metadata is already committed in memory; the failed flush is still owed.
    // A deferred writeback error may also be reported once by the VFS.
    let _ = file.vfs_fsync(false);
    file.vfs_fsync(false).unwrap();
    let (reopened, _sb2) = mount(dev.crash_copy());
    assert!(reopened.state().lookup_path(b"/retry-direct").is_some());
}

#[test]
fn changed_timestamp_burst_is_preserved_by_fsync() {
    let dev = CountingDev::new(IMAGE);
    let (m, _sb) = mount(dev.clone());
    m.state().mount.begin_batch();
    let file = create(&m, b"/timestamp-fsync");
    file.vfs_fsync(false).unwrap();
    let first = vfs::Timespec64::from_clock_ns(1_000_000_000);
    let last = vfs::Timespec64::from_clock_ns(2_000_000_000);
    file.inode().update_time(first, vfs::S_MTIME).unwrap();
    file.inode().update_time(last, vfs::S_MTIME).unwrap();
    file.vfs_fsync(false).unwrap();
    let (reopened, _sb2) = mount(dev.crash_copy());
    let inode = reopened.state().lookup_inode_any(b"/timestamp-fsync").unwrap();
    assert_eq!(inode.mtime(), Some(last));
}

#[test]
fn concurrent_directory_fsync_waits_for_the_active_commit() {
    let dev = CountingDev::new(IMAGE);
    let (m, _sb) = mount(dev.clone());
    m.state().mount.begin_batch();
    let file = create(&m, b"/concurrent-fsync");
    let root = m.root().unwrap();
    let dir = File::new(root.clone(), Dentry::new_root(root), OpenFlags::O_RDONLY);
    let (entered, release) = dev.pause_flush();
    let writer = std::thread::spawn(move || file.vfs_fsync(false));
    entered.recv_timeout(WAIT_BOUND).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        done_tx.send(dir.vfs_fsync(false)).unwrap();
    });
    started_rx.recv_timeout(WAIT_BOUND).unwrap();
    let early = done_rx.recv_timeout(EARLY_RETURN_BOUND);
    release.send(()).unwrap();
    writer.join().unwrap().unwrap();
    waiter.join().unwrap();
    assert!(early.is_err(), "fsync returned while the required commit was not durable");
    done_rx.recv_timeout(WAIT_BOUND).unwrap().unwrap();
}

#[test]
fn directory_fsync_waits_for_an_active_metadata_handle() {
    let dev = CountingDev::new(IMAGE);
    let (m, _sb) = mount(dev);
    m.state().mount.begin_batch();
    create(&m, b"/handle-fsync");
    let fs = m.state().mount.clone();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let handle = std::thread::spawn(move || fs.run_journaled(|_| {
        entered_tx.send(()).unwrap();
        release_rx.recv_timeout(WAIT_BOUND).unwrap();
        Ok(())
    }));
    entered_rx.recv_timeout(WAIT_BOUND).unwrap();
    let root = m.root().unwrap();
    let dir = File::new(root.clone(), Dentry::new_root(root), OpenFlags::O_RDONLY);
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        started_tx.send(()).unwrap(); done_tx.send(dir.vfs_fsync(false)).unwrap();
    });
    started_rx.recv_timeout(WAIT_BOUND).unwrap();
    let early = done_rx.recv_timeout(EARLY_RETURN_BOUND);
    release_tx.send(()).unwrap();
    handle.join().unwrap().unwrap(); waiter.join().unwrap();
    assert!(early.is_err(), "fsync returned before the running handle completed");
    done_rx.recv_timeout(WAIT_BOUND).unwrap().unwrap();
}

#[test]
fn fsync_orders_both_dirty_inodes_in_the_committed_transaction() {
    let dev = CountingDev::new(IMAGE);
    let (m, _sb) = mount(dev.clone());
    m.state().mount.begin_batch();
    let a = create(&m, b"/ordered-a");
    let b = create(&m, b"/ordered-b");
    let a_data = vec![0x41; 4096];
    let b_data = vec![0x42; 4096];
    a.write(&a_data).unwrap(); b.write(&b_data).unwrap();
    a.vfs_fsync(false).unwrap();
    let (reopened, _sb2) = mount(dev.crash_copy());
    for (name, expected) in [(b"/ordered-a", a_data), (b"/ordered-b", b_data)] {
        let inode = reopened.state().lookup_inode_any(name).unwrap();
        let mut got = vec![0; expected.len()];
        assert_eq!(inode.read(0, &mut got).unwrap(), expected.len());
        assert_eq!(got, expected);
    }
}

#[test]
fn commit_error_releases_the_gate_for_another_fsync() {
    let dev = CountingDev::new(IMAGE);
    let (m, _sb) = mount(dev.clone());
    m.state().mount.begin_batch();
    let file = create(&m, b"/retry-journal");
    dev.fail_flush.store(true, Ordering::Release);
    assert!(file.vfs_fsync(false).is_err());
    dev.fail_flush.store(false, Ordering::Release);
    let root = m.root().unwrap();
    let dir = File::new(root.clone(), Dentry::new_root(root), OpenFlags::O_RDONLY);
    let (done_tx, done_rx) = mpsc::channel();
    let retry = std::thread::spawn(move || { done_tx.send(dir.vfs_fsync(false)).unwrap(); });
    done_rx.recv_timeout(WAIT_BOUND).expect("commit error leaked transaction gate").unwrap();
    retry.join().unwrap();
    let (reopened, _sb2) = mount(dev.crash_copy());
    assert!(reopened.state().lookup_path(b"/retry-journal").is_some());
}

#[test]
fn nojournal_in_place_data_fsync_is_durable() {
    let dev = CountingDev::new(NOJOURNAL);
    let (m, _sb) = mount(dev.clone());
    m.state().mount.begin_batch();
    let file = create(&m, b"/overwrite-direct");
    file.write(&vec![0x41; 4096]).unwrap();
    file.vfs_fsync(false).unwrap();
    // Existing extent and size; the byte write bypasses timestamp updates.
    let data = vec![0x42; 4096];
    file.inode().write(0, &data).unwrap();
    dev.reset();
    file.vfs_fsync(true).unwrap();
    assert_eq!(dev.counts().1, 1);
    let (reopened, _sb2) = mount(dev.crash_copy());
    let inode = reopened.state().lookup_inode_any(b"/overwrite-direct").unwrap();
    let mut got = vec![0; data.len()];
    assert_eq!(inode.read(0, &mut got).unwrap(), data.len());
    assert_eq!(got, data);
}
