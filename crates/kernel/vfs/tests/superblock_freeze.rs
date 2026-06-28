//! superblock-D27 (freeze half): a `SuperBlock` carries the Linux
//! `s_writers.frozen` freeze state machine. `freeze_super` ratchets
//! UNFROZEN → FREEZE_COMPLETE (blocking new `sb_start_write` writers and
//! invoking `s_op->freeze_fs`); `thaw_super` resumes via `s_op->thaw_fs`.
//! Re-freeze is `EBUSY`, thaw-while-thawed is `EINVAL`. None of this existed
//! before — the `SuperOps` trait had no freeze/thaw and the SB no frozen
//! state, so FIFREEZE could not quiesce a fs for a consistent snapshot.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use vfs::fs::FileSystem;
use vfs::superblock::{
    next_anon_dev, SB_FREEZE_COMPLETE, SB_UNFROZEN,
};
use vfs::{SbStatFs, SuperBlock, SuperOps, VfsError};

/// A `SuperOps` that counts freeze/thaw/sync calls and can be told to fail
/// `freeze_fs` (the unwind path).
struct CountingOps {
    freezes: AtomicU32,
    thaws:   AtomicU32,
    syncs:   AtomicU32,
    fail_freeze: bool,
}
impl SuperOps for CountingOps {
    fn statfs(&self) -> vfs::KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn sync_fs(&self, _wait: bool) -> vfs::KResult<()> {
        self.syncs.fetch_add(1, Ordering::Relaxed); Ok(())
    }
    fn freeze_fs(&self) -> vfs::KResult<()> {
        self.freezes.fetch_add(1, Ordering::Relaxed);
        if self.fail_freeze { Err(VfsError::Eio) } else { Ok(()) }
    }
    fn thaw_fs(&self) -> vfs::KResult<()> {
        self.thaws.fetch_add(1, Ordering::Relaxed); Ok(())
    }
}

/// Backend exposing the counting `SuperOps` as its `s_op`.
struct FreezeFs { ops: Arc<CountingOps> }
impl FileSystem for FreezeFs {
    fn name(&self) -> &str { "freezefs" }
    fn magic(&self) -> u64 { 0xF00D }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(self.ops.clone()) }
}

fn build(fail_freeze: bool) -> (Arc<SuperBlock>, Arc<CountingOps>) {
    let ops = Arc::new(CountingOps {
        freezes: AtomicU32::new(0), thaws: AtomicU32::new(0),
        syncs: AtomicU32::new(0), fail_freeze,
    });
    let fs = Arc::new(FreezeFs { ops: ops.clone() });
    // No root inode → skip d_make_root; we exercise the SB freeze API directly.
    let sb = SuperBlock::for_backend(fs, None, next_anon_dev(), String::from("freezefs"));
    (sb, ops)
}

#[test]
fn fresh_sb_is_unfrozen_and_admits_writers() {
    let (sb, _ops) = build(false);
    assert_eq!(sb.sb_freeze_level(), SB_UNFROZEN);
    assert!(!sb.is_frozen());
    assert!(sb.sb_start_write(), "unfrozen sb admits a writer");
    assert_eq!(sb.sb_writers(), 1);
    sb.sb_end_write();
    assert_eq!(sb.sb_writers(), 0);
}

#[test]
fn freeze_blocks_writers_and_calls_freeze_fs() {
    let (sb, ops) = build(false);
    sb.freeze_super().expect("freeze_super");
    assert_eq!(sb.sb_freeze_level(), SB_FREEZE_COMPLETE);
    assert!(sb.is_frozen());
    assert_eq!(ops.freezes.load(Ordering::Relaxed), 1, "freeze_fs invoked once");
    assert!(ops.syncs.load(Ordering::Relaxed) >= 1, "dirty state synced before freeze_fs");
    // A frozen sb rejects new writers (the snapshot quiesce).
    assert!(!sb.sb_start_write(), "frozen sb refuses a writer");
    assert_eq!(sb.sb_writers(), 0, "rejected writer leaves no leaked count");
}

#[test]
fn double_freeze_is_ebusy() {
    let (sb, ops) = build(false);
    sb.freeze_super().expect("first freeze");
    assert_eq!(sb.freeze_super(), Err(VfsError::Ebusy), "re-freeze is EBUSY");
    assert_eq!(ops.freezes.load(Ordering::Relaxed), 1, "freeze_fs not re-invoked");
}

#[test]
fn thaw_resumes_writers_and_calls_thaw_fs() {
    let (sb, ops) = build(false);
    sb.freeze_super().expect("freeze");
    sb.thaw_super().expect("thaw_super");
    assert_eq!(sb.sb_freeze_level(), SB_UNFROZEN);
    assert!(!sb.is_frozen());
    assert_eq!(ops.thaws.load(Ordering::Relaxed), 1, "thaw_fs invoked once");
    assert!(sb.sb_start_write(), "thawed sb admits writers again");
    sb.sb_end_write();
}

#[test]
fn thaw_without_freeze_is_einval() {
    let (sb, ops) = build(false);
    assert_eq!(sb.thaw_super(), Err(VfsError::Einval), "thaw of an unfrozen sb is EINVAL");
    assert_eq!(ops.thaws.load(Ordering::Relaxed), 0, "thaw_fs not invoked");
}

#[test]
fn freeze_fs_error_unwinds_to_unfrozen() {
    let (sb, ops) = build(true); // freeze_fs returns EIO
    assert_eq!(sb.freeze_super(), Err(VfsError::Eio), "freeze_fs error propagates");
    assert_eq!(sb.sb_freeze_level(), SB_UNFROZEN, "level unwound on freeze_fs failure");
    assert_eq!(ops.freezes.load(Ordering::Relaxed), 1);
    assert!(sb.sb_start_write(), "writers re-admitted after failed freeze");
    sb.sb_end_write();
}
