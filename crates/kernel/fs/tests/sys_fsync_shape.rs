//! `fsync(2)` / `fdatasync(2)` work-fn — Linux `vfs_fsync_range` returns
//! `EINVAL` for every description whose `f_op` has no `fsync` slot. That set is
//! not a taste call: pipes and FIFOs (`pipefifo_fops`), sockets
//! (`socket_file_ops`), the anon-inode fds, and character devices
//! (`memory_fops`, `tty_fops`) genuinely lack one, while regular files,
//! directories, and block devices have it. A no-op success for a socket would
//! be a data-integrity lie in the other direction: it would report durability
//! for a descriptor that has no backing store at all.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use fs::sync::vfs_fsync;
use syscall::errno::Errno;
use vfs::{default_file_ops, default_inode_ops, mk_mode, Dentry, File, FileType, InodeBuilder,
          InodeRef, OpenFlags};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7400);

/// Fixture superblock identity — values are arbitrary but must be stable.
const TEST_MAGIC: u64 = 0x7400_5346;
const TEST_DEV: u64 = 0x7400;
const TEST_BLOCKSIZE: u32 = 4096;

struct NamedType;
impl vfs::FileSystemType for NamedType {
    fn name(&self) -> &str { "counting" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> vfs::KResult<Arc<vfs::SuperBlock>> {
        Err(vfs::VfsError::Enodev)
    }
}

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

fn description(ft: FileType) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(ft, 0o644), default_inode_ops(), default_file_ops()).build();
    File::new(Arc::clone(&ino), Dentry::new_root(ino), OpenFlags::O_RDWR)
}

#[test]
fn byte_addressable_descriptions_sync_successfully() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for ft in [FileType::Regular, FileType::Directory, FileType::BlockDev] {
        assert_eq!(vfs_fsync(&description(ft), false), 0, "fsync must succeed for {ft:?}");
        assert_eq!(vfs_fsync(&description(ft), true), 0, "fdatasync must succeed for {ft:?}");
    }
}

#[test]
fn stream_and_anon_descriptions_are_einval() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // FIFO covers pipe(2)/eventfd, CharDev covers epoll/timerfd/signalfd and
    // the real character devices, Socket covers every socket family.
    for ft in [FileType::Fifo, FileType::Socket, FileType::CharDev] {
        assert_eq!(vfs_fsync(&description(ft), false), einval(),
            "fsync on {ft:?} has no f_op->fsync and must be EINVAL, never a silent success");
        assert_eq!(vfs_fsync(&description(ft), true), einval(),
            "fdatasync on {ft:?} must be EINVAL too");
    }
}

/// A backend that installs its own `fsync` slot overrides the generic answer —
/// the decision belongs to `f_op`, not to a list kept by the syscall layer.
struct SyncableCharDevOps;
impl vfs::FileOps for SyncableCharDevOps {
    fn fsync(&self, _file: &File, _datasync: bool) -> vfs::KResult<()> { Ok(()) }
}

#[test]
fn a_backend_that_installs_fsync_overrides_the_generic_gate() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::CharDev, 0o644), default_inode_ops(), Arc::new(SyncableCharDevOps)).build();
    let file = File::new(Arc::clone(&ino), Dentry::new_root(ino), OpenFlags::O_RDWR);
    assert_eq!(vfs_fsync(&file, false), 0);
}

/// Counts how many times the whole-filesystem `sync_fs` pass is invoked.
static SYNCFS_CALLS: AtomicU64 = AtomicU64::new(0);
/// Counts `f_op->fsync` dispatches — the per-inode path Linux actually uses.
static FOP_FSYNC_CALLS: AtomicU64 = AtomicU64::new(0);

struct CountingSuperOps;
impl vfs::SuperOps for CountingSuperOps {
    fn statfs(&self) -> vfs::KResult<vfs::SbStatFs> { Err(vfs::VfsError::Enosys) }
    fn sync_fs(&self, _wait: bool) -> vfs::KResult<()> {
        SYNCFS_CALLS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct CountingFileOps;
impl vfs::FileOps for CountingFileOps {
    fn fsync(&self, _file: &File, _datasync: bool) -> vfs::KResult<()> {
        FOP_FSYNC_CALLS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// B1440 causality test. `fsync(2)` must reach the backend through
/// `f_op->fsync` (Linux `ext4_sync_file`) and must NOT invoke
/// `super_operations->sync_fs`, which is the whole-filesystem pass behind
/// `sync(2)`/`syncfs(2)`. Promoting every `fsync` to a `syncfs` writes back
/// every dirty page on the mount and issues a device flush per call — a boot
/// that fsyncs constantly pays that cost every time. Reverting the fix makes
/// the `sync_fs` assertion below fail.
#[test]
fn fsync_uses_the_per_inode_slot_and_never_the_whole_fs_pass() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sb = vfs::SuperBlock::new(Arc::new(NamedType), Arc::new(CountingSuperOps),
        TEST_MAGIC, TEST_DEV, TEST_BLOCKSIZE, String::from("counting"), Arc::new(()));
    let ino: InodeRef = InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(CountingFileOps))
        .sb(Arc::downgrade(&sb)).build();
    let file = File::new(Arc::clone(&ino), Dentry::new_root(ino), OpenFlags::O_RDWR);

    SYNCFS_CALLS.store(0, Ordering::Relaxed);
    FOP_FSYNC_CALLS.store(0, Ordering::Relaxed);
    assert_eq!(vfs_fsync(&file, false), 0);
    assert_eq!(vfs_fsync(&file, true), 0);

    assert_eq!(FOP_FSYNC_CALLS.load(Ordering::Relaxed), 2,
        "both fsync and fdatasync must dispatch through f_op->fsync");
    assert_eq!(SYNCFS_CALLS.load(Ordering::Relaxed), 0,
        "fsync must NOT run the whole-filesystem sync_fs pass (that is sync(2)/syncfs(2))");
}
