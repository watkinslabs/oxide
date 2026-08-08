//! `SB_LAZYTIME` end to end (`inode_time_dirty_flag`,
//! `__mark_inode_dirty` / `__writeback_single_inode` /
//! `sync_lazytime`, mount(8) "lazytime").
//!
//! The failure mode of a lazytime implementation is SILENT DATA LOSS, so every
//! test here reads the timestamp BACK OUT OF THE BACKING STORE rather than
//! asserting a flag. `DiskFs` below is that store: a map the fixture can only
//! reach through the same `i_op->update_time` / `s_op->write_inode` hooks a real
//! filesystem persists through.
//!
//! Contract under test:
//!   * lazytime defers a PURE timestamp update (nothing reaches the store);
//!   * every forcing point Linux names — `fsync`, `sync`/`syncfs`, an explicit
//!     `setattr`, eviction of a still-linked inode, unmount, and the expiry
//!     interval — pushes it out;
//!   * `fdatasync` on an inode with no `I_DIRTY_DATASYNC` does NOT (Linux's
//!     `simple_fsync_noflush` gate: the caller asked not to pay for metadata);
//!   * without `SB_LAZYTIME` behaviour is unchanged — eager write-through;
//!   * `MS_LAZYTIME` flips both ways on remount.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::inode::{Inode, InodeRef, I_DIRTY_SYNC, I_DIRTY_TIME};
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps, SB_LAZYTIME};
use vfs::writeback::DIRTYTIME_EXPIRE_SECS;
use vfs::idmap::Idmap;
use vfs::setattr::{notify_change, ATTR_MTIME};
use vfs::{
    default_file_ops, mk_mode, Cred, Dentry, File, FileType, Iattr, InodeBuilder, InodeOps,
    KResult, OpenFlags, Timespec64, VfsError,
};

static SERIAL: Mutex<()> = Mutex::new(());

/// The wall clock every stamp in this file reads. Settable so the expiry test
/// can move time forward without sleeping.
static CLOCK_NS: AtomicU64 = AtomicU64::new(0);
const START_SEC: i64 = 1_700_000_000;
fn clock() -> u64 { CLOCK_NS.load(Ordering::Relaxed) }
fn set_clock_secs(sec: i64) { CLOCK_NS.store(sec as u64 * 1_000_000_000, Ordering::Relaxed); }

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    set_clock_secs(START_SEC);
    vfs::inode_times::set_realtime_provider(clock);
    g
}

// ---------------------------------------------------------------- backing store

/// The "on-disk" inode table. Only [`DiskInodeOps::update_time`] and
/// [`DiskOps::write_inode`] may write it — exactly the two hooks a real
/// filesystem persists timestamps through — so a test that reads a fresh atime
/// back out of it has proved the stamp actually left memory.
#[derive(Default)]
struct Disk {
    times:  Mutex<std::collections::BTreeMap<u64, (Timespec64, Timespec64, Timespec64)>>,
    writes: AtomicUsize,
}

impl Disk {
    fn persist(&self, inode: &Inode) {
        self.times.lock().unwrap().insert(inode.ino(), (
            inode.atime().unwrap_or(Timespec64::ZERO),
            inode.mtime().unwrap_or(Timespec64::ZERO),
            inode.ctime().unwrap_or(Timespec64::ZERO),
        ));
    }
    fn atime(&self, ino: u64) -> Timespec64 {
        self.times.lock().unwrap().get(&ino).map(|t| t.0).unwrap_or(Timespec64::ZERO)
    }
    fn mtime(&self, ino: u64) -> Timespec64 {
        self.times.lock().unwrap().get(&ino).map(|t| t.1).unwrap_or(Timespec64::ZERO)
    }
}

/// `i_op` shaped like ext4's: `update_time` applies the requested fields to the
/// in-core inode and then writes the whole timestamp triple THROUGH to the
/// store. An empty `S_*` selection is therefore a pure flush, which is what the
/// default `i_op->sync_lazytime` issues.
struct DiskInodeOps { disk: Arc<Disk> }
impl InodeOps for DiskInodeOps {
    fn lookup(&self, _i: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
    fn update_time(&self, inode: &Inode, now: Timespec64, flags: u32) -> KResult<()> {
        vfs::generic_update_time(inode, now, flags)?;
        self.disk.persist(inode);
        Ok(())
    }
    /// Shaped like `ext4_setattr`: apply the attributes, then write the inode.
    fn setattr(&self, inode: &Inode, idmap: &Idmap, ia: &vfs::Iattr) -> KResult<()> {
        vfs::setattr::simple_setattr(inode, idmap, ia)?;
        self.disk.persist(inode);
        Ok(())
    }
}

struct DiskOps { disk: Arc<Disk> }
impl SuperOps for DiskOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn write_inode(&self, inode: &Inode, _wait: bool) -> KResult<()> {
        self.disk.writes.fetch_add(1, Ordering::SeqCst);
        self.disk.persist(inode);
        Ok(())
    }
}

struct DiskType;
impl FileSystemType for DiskType {
    fn name(&self) -> &str { "diskfs" }
    fn mount(&self, _s: Option<&str>, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

/// A superblock over a fresh store, optionally mounted `-o lazytime`.
fn build(lazytime: bool) -> (Arc<SuperBlock>, Arc<Disk>) {
    let disk = Arc::new(Disk::default());
    let sb = SuperBlock::new(Arc::new(DiskType), Arc::new(DiskOps { disk: disk.clone() }),
        0xD15C, 7, 4096, "diskfs".into(), Arc::new(()));
    if lazytime { sb.set_s_flags(SB_LAZYTIME, 0); }
    (sb, disk)
}

/// A regular file resident on `sb`, with its CURRENT (stale) timestamps already
/// on disk — the state an inode read in from a real filesystem is in.
fn file_inode(sb: &Arc<SuperBlock>, disk: &Arc<Disk>, ino: u64, nlink: u32) -> InodeRef {
    let stale = Timespec64::from_secs(START_SEC - 10_000);
    let i = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
            Arc::new(DiskInodeOps { disk: disk.clone() }), default_file_ops())
        .sb(Arc::downgrade(sb)).nlink(nlink)
        .times(stale, stale, stale)
        .build();
    disk.persist(&i);
    sb.iget(ino, || i)
}

/// Read this file, i.e. stamp atime the way `read(2)` does. `mnt_id == 0` is an
/// internal vfsmount (`mnt_flags == 0` ⇒ strictatime), so the relatime ladder
/// never suppresses the stamp and each test observes the deferral itself.
fn read_file(inode: &InodeRef) { vfs::touch_atime(0, inode); }

fn now() -> Timespec64 { Timespec64::from_secs(START_SEC) }

// ------------------------------------------------------------------- deferral

/// Without `SB_LAZYTIME` a timestamp update is written THROUGH immediately —
/// the behaviour that predates the deferral, pinned here so the lazytime work
/// cannot silently change the default mount.
#[test]
fn eager_mount_persists_the_stamp_immediately() {
    let _g = guard();
    let (sb, disk) = build(false);
    let i = file_inode(&sb, &disk, 21, 1);
    read_file(&i);
    assert_eq!(disk.atime(21), now(), "non-lazytime mount writes atime through at once");
    assert_eq!(i.i_state() & (I_DIRTY_TIME | I_DIRTY_SYNC), 0,
        "nothing deferred, so no dirty bit is latched");
}

/// With `SB_LAZYTIME` the same read moves the IN-CORE atime and leaves the store
/// untouched, recording the debt as `I_DIRTY_TIME` and pinning the inode on the
/// superblock's writeback list so it cannot be reclaimed while it owes a stamp.
#[test]
fn lazytime_mount_defers_the_stamp() {
    let _g = guard();
    let (sb, disk) = build(true);
    let i = file_inode(&sb, &disk, 22, 1);
    let before = disk.atime(22);
    read_file(&i);
    assert_eq!(i.atime().unwrap(), now(), "in-core atime advanced");
    assert_eq!(disk.atime(22), before, "on-disk atime NOT written");
    assert_eq!(i.i_state() & I_DIRTY_TIME, I_DIRTY_TIME, "recorded as a lazy debt");
    assert_eq!(sb.nr_dirty_inodes(), 1, "pinned on the writeback list");
    assert_ne!(i.dirtied_time_when(), 0, "expiry clock started");
}

// ------------------------------------------------------------ forcing points

/// `sync`/`syncfs` (`sync_filesystem`) is a data-integrity pass: it converts
/// every deferral regardless of age and leaves the inode clean and unpinned.
#[test]
fn sync_filesystem_forces_the_deferred_stamp_to_disk() {
    let _g = guard();
    let (sb, disk) = build(true);
    let i = file_inode(&sb, &disk, 23, 1);
    read_file(&i);
    assert_ne!(disk.atime(23), now(), "still deferred before the sync");

    sb.sync_filesystem().expect("sync");

    assert_eq!(disk.atime(23), now(), "sync wrote the deferred atime out");
    assert_eq!(i.i_state() & (I_DIRTY_TIME | I_DIRTY_SYNC), 0, "inode is clean afterwards");
    assert_eq!(sb.nr_dirty_inodes(), 0, "writeback pin released");
}

/// `fsync(2)`: the metadata half of a generic `->fsync` runs the same
/// data-integrity writeback for this one inode.
#[test]
fn fsync_forces_the_deferred_stamp_to_disk() {
    let _g = guard();
    let (sb, disk) = build(true);
    let i = file_inode(&sb, &disk, 24, 1);
    read_file(&i);
    let f = File::new(i.clone(), Dentry::new_root(i.clone()), OpenFlags::O_RDONLY);
    f.vfs_fsync(false).expect("fsync");
    assert_eq!(disk.atime(24), now(), "fsync wrote the deferred atime out");
    assert_eq!(i.i_state() & I_DIRTY_TIME, 0, "no deferral left pending");
}

/// `fdatasync(2)` on an inode whose only dirt is a timestamp does NOT force it:
/// the caller asked for the DATA to be durable and explicitly not to pay for a
/// metadata write. Linux gates on `I_DIRTY_DATASYNC` for exactly this.
#[test]
fn fdatasync_leaves_a_timestamp_only_deferral_pending() {
    let _g = guard();
    let (sb, disk) = build(true);
    let i = file_inode(&sb, &disk, 25, 1);
    read_file(&i);
    let f = File::new(i.clone(), Dentry::new_root(i.clone()), OpenFlags::O_RDONLY);
    f.vfs_fsync(true).expect("fdatasync");
    assert_ne!(disk.atime(25), now(), "fdatasync does not flush a pure timestamp");
    assert_eq!(i.i_state() & I_DIRTY_TIME, I_DIRTY_TIME, "the debt is still recorded");
    // ...and it is not lost: the next full fsync pays it.
    f.vfs_fsync(false).expect("fsync");
    assert_eq!(disk.atime(25), now(), "the deferred stamp survived to the next fsync");
}

/// Eviction of a STILL-LINKED inode. This is the case that loses data if the
/// forcing point is missing: the last reference goes, the state is torn down,
/// and an unforced stamp would simply cease to exist.
#[test]
fn eviction_of_a_linked_inode_persists_the_deferred_stamp() {
    let _g = guard();
    let (sb, disk) = build(true);
    let i = file_inode(&sb, &disk, 26, 1);
    read_file(&i);
    sb.iput(i.clone()); // last reference (iget built it at i_count 1)
    assert_eq!(disk.atime(26), now(), "iput wrote the deferred atime out");
    assert_eq!(i.i_state() & I_DIRTY_TIME, 0, "deferral resolved, not discarded");
}

/// An UNLINKED inode is the deliberate exception: it is about to cease to
/// exist, so Linux spends no I/O persisting the timestamps of a deleted file.
#[test]
fn eviction_of_an_unlinked_inode_spends_no_io_on_timestamps() {
    let _g = guard();
    let (sb, disk) = build(true);
    let i = file_inode(&sb, &disk, 27, 1);
    read_file(&i);
    i.set_nlink(0);
    let before = disk.atime(27);
    sb.iput(i.clone());
    assert_eq!(disk.atime(27), before, "no timestamp write for a file being deleted");
}

/// Unmount (`generic_shutdown_super` → `sync_filesystem`) drains the deferrals
/// before the superblock's inodes are evicted.
#[test]
fn unmount_forces_the_deferred_stamp_to_disk() {
    let _g = guard();
    let (sb, disk) = build(true);
    let i = file_inode(&sb, &disk, 28, 1);
    read_file(&i);
    drop(i); // only the writeback pin keeps it resident now
    sb.generic_shutdown_super();
    assert_eq!(disk.atime(28), now(), "unmount wrote the deferred atime out");
}

/// An explicit `setattr` is a forcing point because the inode is being written
/// for a reason unrelated to timestamps: `I_DIRTY_INODE` supersedes
/// `I_DIRTY_TIME`, and the pending stamp rides along with the change.
#[test]
fn setattr_supersedes_and_persists_the_deferred_stamp() {
    let _g = guard();
    let (sb, disk) = build(true);
    let i = file_inode(&sb, &disk, 29, 1);
    read_file(&i);
    assert_eq!(i.i_state() & I_DIRTY_TIME, I_DIRTY_TIME, "deferred before the setattr");

    // A pure mtime setattr (utimes-shaped): the backend writes the whole
    // timestamp triple, so the deferred atime lands with it.
    let mtime = Timespec64::from_secs(START_SEC + 5);
    let mut ia = Iattr { valid: ATTR_MTIME, mtime, ..Default::default() };
    notify_change(&Idmap::identity(), &i, &mut ia, &Cred::root()).expect("setattr");

    assert_eq!(i.i_state() & I_DIRTY_TIME, 0, "I_DIRTY_INODE superseded the lazy debt");
    assert_eq!(disk.mtime(29), mtime, "the explicit change is on disk");
    assert_eq!(disk.atime(29), now(), "and the deferred atime rode along");
}

// ------------------------------------------------------------------- expiry

/// A background pass leaves a FRESH deferral alone — deferring is the whole
/// point, and a sweep that flushed everything would make lazytime a no-op.
#[test]
fn background_pass_leaves_a_fresh_deferral_alone() {
    let _g = guard();
    let (sb, disk) = build(true);
    let i = file_inode(&sb, &disk, 30, 1);
    read_file(&i);
    let before = disk.atime(30);
    sb.wb_flush_expired_dirtytime(clock() + 3600 * 1_000_000_000)
        .expect("background pass");
    assert_eq!(disk.atime(30), before, "one hour in, the deferral still stands");
    assert_eq!(i.i_state() & I_DIRTY_TIME, I_DIRTY_TIME, "and is still recorded");
}

/// Once the deferral outlives the expire interval the background pass forces it
/// out, so no lazily-stamped inode can sit unwritten indefinitely.
#[test]
fn background_pass_forces_an_expired_deferral() {
    let _g = guard();
    let (sb, disk) = build(true);
    let i = file_inode(&sb, &disk, 31, 1);
    read_file(&i);
    let expired = clock() + (DIRTYTIME_EXPIRE_SECS + 1) * 1_000_000_000;
    sb.wb_flush_expired_dirtytime(expired).expect("background pass");
    assert_eq!(disk.atime(31), now(), "expired deferral written out");
    assert_eq!(i.i_state() & I_DIRTY_TIME, 0, "deferral resolved");
}

// ------------------------------------------------------------------ remount

/// `MS_LAZYTIME` flips both ways on a live superblock: clearing it returns the
/// mount to eager write-through, setting it starts deferring again. Anything
/// already deferred stays recorded across the flip and is paid at the next
/// forcing point — a policy change must not drop a debt already owed.
#[test]
fn remount_flips_lazytime_in_both_directions() {
    let _g = guard();
    let (sb, disk) = build(true);
    let i = file_inode(&sb, &disk, 32, 1);
    read_file(&i);
    assert_eq!(i.i_state() & I_DIRTY_TIME, I_DIRTY_TIME, "deferred while lazytime");

    // -o remount,nolazytime. The flip is a POLICY change, not a flush: Linux
    // leaves an already-deferred stamp on the writeback list, and it must stay
    // owed rather than be dropped with the option.
    let deferred = disk.atime(32);
    sb.reconfigure_super(0, SB_LAZYTIME, "").expect("remount nolazytime");
    assert!(!sb.is_lazytime());
    assert_eq!(disk.atime(32), deferred, "the flip itself writes nothing");
    assert_eq!(i.i_state() & I_DIRTY_TIME, I_DIRTY_TIME, "the debt survives the flip");

    // A later stamp is now eager again — and the write-through pays the debt
    // the flip left outstanding, so no bit is stranded.
    set_clock_secs(START_SEC + 100);
    read_file(&i);
    assert_eq!(disk.atime(32), Timespec64::from_secs(START_SEC + 100),
        "nolazytime writes through");
    assert_eq!(i.i_state() & I_DIRTY_TIME, 0, "nothing deferred under nolazytime");

    // -o remount,lazytime
    sb.reconfigure_super(SB_LAZYTIME, 0, "").expect("remount lazytime");
    set_clock_secs(START_SEC + 200);
    read_file(&i);
    assert_eq!(disk.atime(32), Timespec64::from_secs(START_SEC + 100),
        "deferring again after the flip back");
    assert_eq!(i.i_state() & I_DIRTY_TIME, I_DIRTY_TIME, "recorded as a lazy debt again");
}

// ------------------------------------------------- write_inode is really called

/// The prerequisite this whole lane rests on: the sync path calls
/// `s_op->write_inode` for a dirty inode. Before it did, the pass cleared
/// `I_DIRTY` with no backend call at all, which is why deferring a stamp would
/// have DISCARDED it.
#[test]
fn sync_calls_write_inode_for_a_dirty_inode() {
    let _g = guard();
    let (sb, disk) = build(false);
    let i = file_inode(&sb, &disk, 33, 1);
    sb.mark_inode_dirty(33, I_DIRTY_SYNC);
    assert_eq!(disk.writes.load(Ordering::SeqCst), 0, "not written yet");

    sb.sync_filesystem().expect("sync");

    assert!(disk.writes.load(Ordering::SeqCst) >= 1, "s_op->write_inode ran");
    assert_eq!(i.i_state() & I_DIRTY_SYNC, 0, "and the dirty bit cleared after it, not before");
}
