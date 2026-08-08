//! `iterate_supers` — the whole-system superblock sweep `sync(2)` walks.
//!
//! The behaviour this pins is the one a mount-table walk cannot express: a
//! superblock whose last mount has been lazily detached is still LIVE while file
//! descriptions remain open on it, still holds dirty state, and still owes its
//! backend a flush. Sweeping the mount table skips exactly that instance, so its
//! dirty metadata is never written by `sync(2)` at all.
//!
//! The complementary half is what the sweep must NOT touch: an instance that is
//! being torn down, or one that was never published, has backend state under
//! dismantling or not yet built, and flushing into it is at best wasted work.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use vfs::inode::InodeBuilder;
use vfs::superblock::{iterate_supers, register_super, sb_iterable, next_anon_dev, SB_ACTIVE};
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileSystemType, FileType, InodeRef,
    KResult, SbStatFs, SuperBlock, SuperOps, VfsError};

/// The registry is process-global, so the sweeps in this file run one at a time
/// and each counts only the instances it built (matched by `s_id`).
static SERIAL: Mutex<()> = Mutex::new(());

const MAGIC: u64 = 0x1737;

struct Ops { syncs: AtomicUsize }
impl SuperOps for Ops {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn sync_fs(&self, _wait: bool) -> KResult<()> { self.syncs.fetch_add(1, Ordering::SeqCst); Ok(()) }
}

struct Ty;
impl FileSystemType for Ty {
    fn name(&self) -> &str { "itersupers" }
    fn mount(&self, _s: Option<&str>, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

fn root_inode(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), default_inode_ops(), default_file_ops()).build()
}

/// A PUBLISHED instance: filled, rooted, and in the registry — but attached to
/// no mount, which is the state a lazily-detached filesystem is left in.
fn published(id: &str, ino: u64) -> (Arc<SuperBlock>, Arc<Ops>) {
    let ops = Arc::new(Ops { syncs: AtomicUsize::new(0) });
    let sb = SuperBlock::from_ops(Arc::new(Ty), ops.clone(), Some(root_inode(ino)),
        MAGIC, next_anon_dev(), 4096, id.into(), Arc::new(()));
    register_super(&sb);
    (sb, ops)
}

/// Which of this test's own instances the sweep visited.
fn visited(want: &str) -> usize {
    let n = AtomicUsize::new(0);
    iterate_supers(|sb| if sb.s_id == want { n.fetch_add(1, Ordering::SeqCst); });
    n.load(Ordering::SeqCst)
}

/// The gap itself: a live, registered, dirty-capable superblock that no mount
/// points at is still swept. Walking mounts instead of the registry loses it.
#[test]
fn sweep_reaches_a_registered_superblock_with_no_mount() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (sb, ops) = published("iter-unmounted", 0x2001);
    assert_eq!(visited("iter-unmounted"), 1, "an unmounted live instance is swept");

    iterate_supers(|s| if s.s_id == "iter-unmounted" { let _ = s.sync_fs(true); });
    assert_eq!(ops.syncs.load(Ordering::SeqCst), 1, "and its backend flush actually ran");
    drop(sb);
}

/// An instance already past `generic_shutdown_super`'s point of no return —
/// the mounted flag cleared, backend teardown under way — is skipped.
#[test]
fn sweep_skips_a_superblock_being_torn_down() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (sb, _ops) = published("iter-dying", 0x2002);
    assert_eq!(visited("iter-dying"), 1, "visible while live");

    sb.set_s_flags(0, SB_ACTIVE);
    assert_eq!(visited("iter-dying"), 0, "not swept once teardown has begun");
}

/// An instance with no root dentry was never published — fill-super has not
/// finished — so the sweep must not reach into it.
#[test]
fn sweep_skips_an_unpublished_superblock() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let ops = Arc::new(Ops { syncs: AtomicUsize::new(0) });
    let sb = SuperBlock::new(Arc::new(Ty), ops.clone(), MAGIC, next_anon_dev(), 4096,
        "iter-unrooted".into(), Arc::new(()));
    register_super(&sb);
    assert_eq!(visited("iter-unrooted"), 0, "no root dentry ⇒ not yet publishable");
    assert_eq!(ops.syncs.load(Ordering::SeqCst), 0);
}

/// An instance whose last reference is gone leaves the registry behind it: the
/// registry pins nothing, so a dropped superblock cannot be resurrected by a
/// sweep.
#[test]
fn sweep_skips_a_dropped_superblock() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (sb, _ops) = published("iter-dropped", 0x2003);
    assert_eq!(visited("iter-dropped"), 1);
    drop(sb);
    assert_eq!(visited("iter-dropped"), 0, "a freed instance is not swept");
}

/// The predicate on its own, so the two skip conditions are pinned independently
/// of how a fixture happens to reach them.
#[test]
fn only_a_published_and_live_instance_is_iterable() {
    assert!(sb_iterable(true, true));
    assert!(!sb_iterable(false, true), "torn down");
    assert!(!sb_iterable(true, false), "never published");
    assert!(!sb_iterable(false, false));
}
