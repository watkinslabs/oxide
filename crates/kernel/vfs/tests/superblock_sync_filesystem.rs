//! superblock `sync_filesystem` two-phase flush + per-sb `drop_caches`
//! (Linux fs/sync.c `sync_filesystem`, fs/inode.c `invalidate_inodes`,
//! fs/drop_caches.c). `sync_filesystem` must issue `sync_fs` in the canonical
//! async-then-wait order (`wait=0` then `wait=1`), short-circuit on a read-only
//! SB, and abort before the wait pass if the async pass errors. `drop_caches`
//! must reclaim only CLEAN, UNREFERENCED icache slots — busy (still-referenced)
//! and dirty/in-flight slots are retained. Before this the teardown synced with
//! a single `sync_fs(true)` pass and there was NO per-sb clean-inode invalidate.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use vfs::fs::FileSystem;
use vfs::inode::{InodeBuilder, I_DIRTY_SYNC};
use vfs::superblock::next_anon_dev;
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeRef, KResult, SbStatFs, SuperBlock, SuperOps, VfsError};

/// `SuperOps` recording each `sync_fs` wait flag in call order, optionally
/// failing the async (`wait=false`) pass so the abort-before-wait path shows.
struct SyncOps { waits: Mutex<Vec<bool>>, fail_async: AtomicBool }
impl SuperOps for SyncOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn sync_fs(&self, wait: bool) -> KResult<()> {
        self.waits.lock().unwrap().push(wait);
        if !wait && self.fail_async.load(Ordering::Relaxed) { return Err(VfsError::Eio); }
        Ok(())
    }
}

struct SyncFs { ops: Arc<SyncOps> }
impl FileSystem for SyncFs {
    fn name(&self) -> &str { "syncfs" }
    fn magic(&self) -> u64 { 0x5717 }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(self.ops.clone()) }
}

fn make_ramfile(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn build() -> (Arc<SuperBlock>, Arc<SyncOps>) {
    let ops = Arc::new(SyncOps { waits: Mutex::new(Vec::new()), fail_async: AtomicBool::new(false) });
    let fs = Arc::new(SyncFs { ops: ops.clone() });
    let sb = SuperBlock::for_backend(fs, None, next_anon_dev(), String::from("syncfs"));
    (sb, ops)
}

#[test]
fn sync_filesystem_runs_async_then_wait_pass() {
    let (sb, ops) = build();
    sb.sync_filesystem().expect("clean sync");
    assert_eq!(&*ops.waits.lock().unwrap(), &[false, true],
        "sync_fs issued async (wait=0) then blocking (wait=1)");
}

#[test]
fn sync_filesystem_readonly_short_circuits() {
    let (sb, ops) = build();
    sb.set_readonly(true);
    sb.sync_filesystem().expect("rdonly sync is a no-op Ok");
    assert!(ops.waits.lock().unwrap().is_empty(),
        "read-only SB has nothing to flush — sync_fs never called");
}

#[test]
fn sync_filesystem_aborts_before_wait_on_async_error() {
    let (sb, ops) = build();
    ops.fail_async.store(true, Ordering::Relaxed);
    assert!(sb.sync_filesystem().is_err(), "async-pass error propagates");
    assert_eq!(&*ops.waits.lock().unwrap(), &[false],
        "wait pass skipped after the async pass failed");
}

#[test]
fn drop_caches_reclaims_clean_keeps_busy_and_dirty() {
    let (sb, _ops) = build();
    // held: clean + referenced → busy, retained.
    let held: InodeRef = sb.iget(11, || make_ramfile(11));
    // clean + unreferenced → reclaimable.
    drop(sb.iget(12, || make_ramfile(12)));
    // dirty + unreferenced → retained (writeback still owes it).
    drop(sb.iget(13, || make_ramfile(13)));
    sb.mark_inode_dirty(13, I_DIRTY_SYNC);

    assert_eq!(sb.drop_caches(), 1, "only the clean idle ino 12 dropped");
    assert!(sb.ilookup(11).is_some(), "busy inode kept");
    assert!(sb.ilookup(12).is_none(), "clean idle inode slot reclaimed");
    assert_eq!(sb.i_state(13) & I_DIRTY_SYNC, I_DIRTY_SYNC, "dirty slot retained");

    // Once the dirty bit clears and the busy ref drops, both reclaim.
    sb.i_set_state(13, 0, I_DIRTY_SYNC);
    drop(held);
    assert_eq!(sb.drop_caches(), 2, "now-clean idle 11 and 13 both reclaimed");
}
