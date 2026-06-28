//! superblock-D6 (s_active refcount): a `SuperBlock` carries the Linux
//! `super_block.s_active` active-reference count. A fresh `for_backend`/`new`
//! SB starts at 1; `grab_active` (`atomic_inc_not_zero`) takes an extra ref
//! IFF still live; `deactivate_super` (`atomic_dec_and_test`) drops one and the
//! LAST drop (1→0) runs `generic_shutdown_super` (sync_filesystem + put_super)
//! exactly once. None of this existed before — last-umount teardown relied on
//! mount.rs's O(N) `Arc::ptr_eq` scan with no refcount, so sb sharing (sget
//! reuse / bind clone) had no way to keep a shared instance alive across umounts.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use vfs::fs::FileSystem;
use vfs::superblock::next_anon_dev;
use vfs::{SbStatFs, SuperBlock, SuperOps};

/// `SuperOps` counting `put_super` (the last-active teardown) and `sync_fs`
/// (which `generic_shutdown_super` must run before `put_super`).
struct TeardownOps { puts: AtomicU32, syncs: AtomicU32 }
impl SuperOps for TeardownOps {
    fn statfs(&self) -> vfs::KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn sync_fs(&self, _wait: bool) -> vfs::KResult<()> {
        self.syncs.fetch_add(1, Ordering::Relaxed); Ok(())
    }
    fn put_super(&self) { self.puts.fetch_add(1, Ordering::Relaxed); }
}

struct ActiveFs { ops: Arc<TeardownOps> }
impl FileSystem for ActiveFs {
    fn name(&self) -> &str { "activefs" }
    fn magic(&self) -> u64 { 0xAC71 }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(self.ops.clone()) }
}

fn build() -> (Arc<SuperBlock>, Arc<TeardownOps>) {
    let ops = Arc::new(TeardownOps { puts: AtomicU32::new(0), syncs: AtomicU32::new(0) });
    let fs = Arc::new(ActiveFs { ops: ops.clone() });
    let sb = SuperBlock::for_backend(fs, None, next_anon_dev(), String::from("activefs"));
    (sb, ops)
}

#[test]
fn fresh_sb_has_one_active_ref() {
    let (sb, _ops) = build();
    assert_eq!(sb.s_active(), 1, "a filled+mounted SB starts with one active ref");
}

#[test]
fn last_deactivate_runs_shutdown_once() {
    let (sb, ops) = build();
    // The single mount's active ref is the last → teardown fires.
    assert!(sb.deactivate_super(), "last deactivate (1→0) reports shutdown ran");
    assert_eq!(sb.s_active(), 0);
    assert_eq!(ops.puts.load(Ordering::Relaxed), 1, "put_super invoked exactly once");
    assert!(ops.syncs.load(Ordering::Relaxed) >= 1, "sync_filesystem ran before put_super");
}

#[test]
fn non_last_deactivate_does_not_shutdown() {
    let (sb, ops) = build();
    assert!(sb.grab_active(), "live SB hands out an extra active ref");
    assert_eq!(sb.s_active(), 2);
    // First drop is NOT the last (2→1): no teardown.
    assert!(!sb.deactivate_super(), "non-last deactivate reports no shutdown");
    assert_eq!(sb.s_active(), 1);
    assert_eq!(ops.puts.load(Ordering::Relaxed), 0, "put_super NOT called while a ref remains");
    // Second drop is the last (1→0): teardown.
    assert!(sb.deactivate_super(), "final deactivate runs shutdown");
    assert_eq!(ops.puts.load(Ordering::Relaxed), 1);
}

#[test]
fn grab_active_fails_after_teardown() {
    let (sb, ops) = build();
    assert!(sb.deactivate_super(), "drop the last ref → torn down");
    // sget reuse must NOT resurrect a dead instance.
    assert!(!sb.grab_active(), "grab_active on a count==0 SB returns false");
    assert_eq!(sb.s_active(), 0, "a refused grab leaves no leaked count");
    // A redundant deactivate at 0 is an idempotent no-op (no unsigned underflow,
    // no second teardown), so generic_shutdown_super fires exactly once.
    assert!(!sb.deactivate_super(), "deactivate at 0 is a no-op");
    assert_eq!(sb.s_active(), 0, "no u32 underflow to u32::MAX");
    assert_eq!(ops.puts.load(Ordering::Relaxed), 1, "put_super still only ran once");
}
