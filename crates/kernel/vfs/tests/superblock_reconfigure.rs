//! superblock: classic `super_operations.remount_fs` hook + sb-level
//! `reconfigure_super` (Linux fs/super.c). A flag-delta remount applied to a
//! LIVE superblock: on RW→RO the dirty state is synced FIRST, the backend
//! `remount_fs(proposed_flags)` hook runs, and `s_flags` are rewritten ONLY on
//! its success. A hook error aborts with the old flags intact. None of this
//! existed — `SuperOps` had no `remount_fs` and the SB no in-place reconfigure,
//! so an MS_REMOUNT could not flip `SB_RDONLY` at the fs level or consult the
//! backend.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use vfs::fs::FileSystem;
use vfs::superblock::{next_anon_dev, SB_RDONLY};
use vfs::{SbStatFs, SuperBlock, SuperOps, VfsError};

/// A `SuperOps` that records the last `remount_fs(sb_flags)` it saw, counts
/// remount + sync calls, and can be told to refuse the remount.
struct RemountOps {
    remounts:   AtomicU32,
    syncs:      AtomicU32,
    last_flags: AtomicU64,
    fail:       bool,
}
impl SuperOps for RemountOps {
    fn statfs(&self) -> vfs::KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn sync_fs(&self, _wait: bool) -> vfs::KResult<()> {
        self.syncs.fetch_add(1, Ordering::Relaxed); Ok(())
    }
    fn remount_fs(&self, sb_flags: u64) -> vfs::KResult<()> {
        self.remounts.fetch_add(1, Ordering::Relaxed);
        self.last_flags.store(sb_flags, Ordering::Relaxed);
        if self.fail { Err(VfsError::Eacces) } else { Ok(()) }
    }
}

struct RemountFs { ops: Arc<RemountOps> }
impl FileSystem for RemountFs {
    fn name(&self) -> &str { "remountfs" }
    fn magic(&self) -> u64 { 0xBEEF }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(self.ops.clone()) }
}

fn build(fail: bool) -> (Arc<SuperBlock>, Arc<RemountOps>) {
    let ops = Arc::new(RemountOps {
        remounts: AtomicU32::new(0), syncs: AtomicU32::new(0),
        last_flags: AtomicU64::new(0), fail,
    });
    let fs = Arc::new(RemountFs { ops: ops.clone() });
    let sb = SuperBlock::for_backend(fs, None, next_anon_dev(), String::from("remountfs"));
    (sb, ops)
}

#[test]
fn remount_ro_syncs_first_then_calls_hook_and_sets_flag() {
    let (sb, ops) = build(false);
    assert!(!sb.is_readonly(), "fresh SB is RW");
    assert!(sb.sb_start_write(), "RW sb admits a writer before remount");
    sb.sb_end_write();

    sb.reconfigure_super(SB_RDONLY, 0).expect("RW→RO remount");

    assert!(sb.is_readonly(), "SB_RDONLY now set on the live SB");
    assert_eq!(ops.remounts.load(Ordering::Relaxed), 1, "backend remount_fs hook ran once");
    assert!(ops.syncs.load(Ordering::Relaxed) >= 1, "dirty state synced before sealing RO");
    assert_eq!(ops.last_flags.load(Ordering::Relaxed) & SB_RDONLY, SB_RDONLY,
        "hook saw the PROPOSED flags including SB_RDONLY");
    assert!(!sb.sb_start_write(), "a read-only sb refuses new writers (EROFS)");
}

#[test]
fn remount_rw_clears_rdonly_without_pre_sync() {
    let (sb, ops) = build(false);
    sb.set_readonly(true);
    assert!(sb.is_readonly());
    let syncs_before = ops.syncs.load(Ordering::Relaxed);

    sb.reconfigure_super(0, SB_RDONLY).expect("RO→RW remount");

    assert!(!sb.is_readonly(), "SB_RDONLY cleared");
    assert_eq!(ops.remounts.load(Ordering::Relaxed), 1, "hook ran");
    assert_eq!(ops.syncs.load(Ordering::Relaxed), syncs_before,
        "RO→RW does not pre-sync (only RW→RO seals after a flush)");
    assert!(sb.sb_start_write(), "writers re-admitted after RO→RW");
    sb.sb_end_write();
}

#[test]
fn hook_error_aborts_with_flags_unchanged() {
    let (sb, ops) = build(true); // backend refuses every remount
    assert!(!sb.is_readonly());

    let r = sb.reconfigure_super(SB_RDONLY, 0);
    assert_eq!(r, Err(VfsError::Eacces), "remount returns the backend's error");
    assert!(!sb.is_readonly(), "a refused remount leaves s_flags untouched");
    assert_eq!(ops.remounts.load(Ordering::Relaxed), 1, "hook was consulted");
    assert!(sb.sb_start_write(), "still writable — the RO flip never landed");
    sb.sb_end_write();
}

#[test]
fn idempotent_reapply_keeps_flag() {
    let (sb, _ops) = build(false);
    sb.reconfigure_super(SB_RDONLY, 0).expect("first RO");
    sb.reconfigure_super(SB_RDONLY, 0).expect("re-apply RO is idempotent");
    assert!(sb.is_readonly());
}

#[test]
fn default_super_ops_remount_is_noop_ok() {
    // A backend with NO custom SuperOps falls to the generic adapter whose
    // default remount_fs is a no-op Ok — a pseudo-fs flag-only remount succeeds.
    struct Plain;
    impl FileSystem for Plain { fn name(&self) -> &str { "plain" } }
    let sb = SuperBlock::for_backend(Arc::new(Plain), None, next_anon_dev(), String::from("plain"));
    sb.reconfigure_super(SB_RDONLY, 0).expect("default remount_fs is a no-op Ok");
    assert!(sb.is_readonly());
}
