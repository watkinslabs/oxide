//! Writeback failures that nobody is waiting on must be LATCHED, not dropped.
//!
//! Three paths discover a metadata write failure with no caller to return it to:
//! the background dirtytime sweep, a whole-system sync pass, and the eviction of
//! an inode whose last reference just went. All three must record the failure in
//! BOTH latches — the inode's own, so a later `fsync` on that file reports it,
//! and the filesystem's, so a later `syncfs` reports it even after the inode has
//! been evicted.
//!
//! The failure modes pinned here are asymmetries, and each was real: the
//! eviction path discarded the error entirely, and the background sweep recorded
//! only the filesystem half — leaving `fsync` on the very file that failed
//! returning success.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use vfs::inode::{Inode, InodeBuilder, InodeRef, I_DIRTY_SYNC};
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps, SB_LAZYTIME};
use vfs::writeback::DIRTYTIME_EXPIRE_SECS;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, KResult, VfsError};

const EIO: u32 = VfsError::Eio as u32;

/// A backend whose inode writes fail, and which evicts on the last reference
/// whatever the link count — the `generic_delete_inode` shape, so the eviction
/// path's metadata write is actually reached.
struct FailOps { fail: AtomicBool }
impl SuperOps for FailOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn write_inode(&self, _inode: &Inode, _wait: bool) -> KResult<()> {
        if self.fail.load(Ordering::SeqCst) { Err(VfsError::Eio) } else { Ok(()) }
    }
    fn drop_inode(&self, _inode: &Inode) -> bool { true }
}

struct Ty;
impl FileSystemType for Ty {
    fn name(&self) -> &str { "wberr" }
    fn mount(&self, _s: Option<&str>, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

fn build() -> (Arc<SuperBlock>, Arc<FailOps>) {
    let ops = Arc::new(FailOps { fail: AtomicBool::new(true) });
    let sb = SuperBlock::new(Arc::new(Ty), ops.clone(), 0xB1E7, 0, 4096, "wberr".into(), Arc::new(()));
    (sb, ops)
}

/// A file resident on `sb`, BOUND to it — the state an inode read in from a real
/// filesystem is in, and the binding `mapping_set_error` follows to reach the
/// filesystem-wide latch.
fn file(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    let i = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).nlink(1).build();
    sb.iget(ino, || i)
}

/// What an `fsync` on this file would report, and what a `syncfs` on this
/// filesystem would report — each exactly once, from a subscriber that predates
/// the failure.
fn latched(sb: &Arc<SuperBlock>, i: &InodeRef) -> (Option<u32>, Option<u32>) {
    let mut fd_inode = 0u32; // the epoch: an fd opened before anything failed
    let mut fd_sb = 0u32;
    (i.wb_err().check_and_advance(&mut fd_inode), sb.s_wb_err.check_and_advance(&mut fd_sb))
}

/// A whole-filesystem writeback pass that fails records BOTH halves.
#[test]
fn sync_pass_latches_the_failure_on_the_inode_and_the_filesystem() {
    let (sb, _ops) = build();
    let i = file(&sb, 41);
    sb.mark_inode_dirty(41, I_DIRTY_SYNC);

    assert!(sb.wb_writeback_pass(true, 0).is_err(), "the backend refused the write");
    assert_eq!(latched(&sb, &i), (Some(EIO), Some(EIO)),
        "fsync on the file AND syncfs on the filesystem each report it");
}

/// EVERY failing inode is latched, not merely the one whose error the pass
/// happens to return. A caller waiting on the pass learns about one; the second
/// file's own `fsync` must still learn about its own.
#[test]
fn every_failing_inode_gets_its_own_latch() {
    let (sb, _ops) = build();
    let a = file(&sb, 42);
    let b = file(&sb, 43);
    sb.mark_inode_dirty(42, I_DIRTY_SYNC);
    sb.mark_inode_dirty(43, I_DIRTY_SYNC);

    assert!(sb.wb_writeback_pass(true, 0).is_err());

    let mut fd_a = 0u32;
    let mut fd_b = 0u32;
    assert_eq!(a.wb_err().check_and_advance(&mut fd_a), Some(EIO));
    assert_eq!(b.wb_err().check_and_advance(&mut fd_b), Some(EIO),
        "the inode whose error the pass did not return is latched too");
}

/// The BACKGROUND sweep. Its whole purpose is that nobody is waiting on it, so
/// dropping the per-inode half here is exactly how an `fsync` on the failing
/// file comes to return success.
#[test]
fn background_dirtytime_pass_latches_the_inode_half_too() {
    let (sb, _ops) = build();
    sb.set_s_flags(SB_LAZYTIME, 0);
    let i = file(&sb, 44);
    sb.mark_inode_dirty(44, I_DIRTY_SYNC);

    let expired = (DIRTYTIME_EXPIRE_SECS + 1) * 1_000_000_000;
    assert!(sb.wb_flush_expired_dirtytime(expired).is_err());
    assert_eq!(latched(&sb, &i), (Some(EIO), Some(EIO)),
        "a background failure is reportable by both fsync and syncfs");
}

/// EVICTION. The inode's last reference is going and its metadata write fails;
/// with no latch the failure ceases to exist along with the inode, and the next
/// `syncfs` reports success for metadata that never reached the backend.
#[test]
fn eviction_latches_a_failed_metadata_write() {
    let (sb, _ops) = build();
    let i = file(&sb, 45);
    sb.mark_inode_dirty(45, I_DIRTY_SYNC);

    sb.iput(i.clone()); // last reference: iput_final writes the inode out, and fails

    assert_eq!(latched(&sb, &i), (Some(EIO), Some(EIO)),
        "the eviction-time failure survives the inode leaving the cache");
}

/// The filesystem-wide latch outlives the inode entirely — which is the reason
/// the eviction path must record it before the inode is gone.
#[test]
fn the_filesystem_latch_survives_the_evicted_inode() {
    let (sb, _ops) = build();
    let i = file(&sb, 46);
    sb.mark_inode_dirty(46, I_DIRTY_SYNC);
    sb.iput(i.clone());
    drop(i);
    assert!(sb.ilookup(46).is_none(), "the inode is gone from the cache");

    let mut fd_sb = 0u32;
    assert_eq!(sb.s_wb_err.check_and_advance(&mut fd_sb), Some(EIO),
        "syncfs still reports the failure of an inode that no longer exists");
}

/// A successful pass latches nothing — the latch must not manufacture errors.
#[test]
fn a_clean_pass_records_no_error() {
    let (sb, ops) = build();
    ops.fail.store(false, Ordering::SeqCst);
    let i = file(&sb, 47);
    sb.mark_inode_dirty(47, I_DIRTY_SYNC);

    sb.wb_writeback_pass(true, 0).expect("clean pass");
    assert_eq!(latched(&sb, &i), (None, None));
}
