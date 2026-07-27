//! `fsync(2)` / `fdatasync(2)` work-fn — Linux `vfs_fsync_range` returns
//! `EINVAL` for every description whose `f_op` has no `fsync` slot. That set is
//! not a taste call: pipes and FIFOs (`pipefifo_fops`), sockets
//! (`socket_file_ops`), the anon-inode fds, and character devices
//! (`memory_fops`, `tty_fops`) genuinely lack one, while regular files,
//! directories, and block devices have it. A no-op success for a socket would
//! be a data-integrity lie in the other direction: it would report durability
//! for a descriptor that has no backing store at all.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use fs::sync::vfs_fsync;
use syscall::errno::Errno;
use vfs::{default_file_ops, default_inode_ops, mk_mode, Dentry, File, FileType, InodeBuilder,
          InodeRef, OpenFlags};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7400);

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
