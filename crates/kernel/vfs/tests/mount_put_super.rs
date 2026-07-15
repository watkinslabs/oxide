//! D6 last-umount teardown via the `SuperBlock` `s_active` refcount, exercised
//! through the REAL global mount engine (not the SB unit test). `put_super_if_last`
//! now calls `SuperBlock::deactivate_super` (Linux `mntput`) instead of the old
//! O(N) `Arc::ptr_eq` mount-table scan, and the SB-sharing clone path
//! (`copy_mnt_ns`, Linux `clone_mnt`) grabs an extra active ref so a shared
//! instance survives until its LAST mount drops. `reap_ns` (Linux `free_mnt_ns`)
//! now `mntput`s each reaped mount, so a ns-private SB runs `put_super`.
//!
//! Regressions guarded:
//!  - missing `grab_active` in `copy_mnt_ns` ⇒ unmounting ONE of two ns mounts
//!    would tear the shared SB down early (intermediate `puts==0` assert).
//!  - missing `put_super_if_last` in `reap_ns` ⇒ a ns-private SB never runs
//!    `put_super` on last-task exit (`puts==1` after reap).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, SbStatFs, SuperOps, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::install();
    g
}

fn set_namespace(namespace: &vfs::mntns::MntNamespaceRef) {
    common::set_current_namespace(namespace.clone());
}

/// `SuperOps` counting the `generic_shutdown_super` calls (`put_super` +
/// the preceding `sync_filesystem`).
struct CountOps { puts: AtomicU32, syncs: AtomicU32 }
impl SuperOps for CountOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn sync_fs(&self, _wait: bool) -> KResult<()> { self.syncs.fetch_add(1, Ordering::Relaxed); Ok(()) }
    fn put_super(&self) { self.puts.fetch_add(1, Ordering::Relaxed); }
}

struct CDirOps;
impl vfs::InodeOps for CDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn cdir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(CDirOps), vfs::default_file_ops()).build()
}

struct CountFs { ops: Arc<CountOps>, root_ino: u64, magic: u64 }
impl FileSystem for CountFs {
    fn name(&self) -> &str { "countfs" }
    fn magic(&self) -> u64 { self.magic }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(self.ops.clone()) }
    fn root(&self) -> Option<InodeRef> { Some(cdir(self.root_ino)) }
}

static NEXT_MAGIC: AtomicU64 = AtomicU64::new(0xC0FFEE00);

/// A counting fs + its shared put_super counter.
fn count_fs(root_ino: u64) -> (Arc<dyn FileSystem>, Arc<CountOps>) {
    let ops = Arc::new(CountOps { puts: AtomicU32::new(0), syncs: AtomicU32::new(0) });
    let magic = NEXT_MAGIC.fetch_add(1, Ordering::Relaxed);
    (Arc::new(CountFs { ops: ops.clone(), root_ino, magic }), ops)
}

/// A plain (uncounted) fs for the ns root mount.
struct PlainFs { root_ino: u64 }
impl FileSystem for PlainFs {
    fn name(&self) -> &str { "plainfs" }
    fn root(&self) -> Option<InodeRef> { Some(cdir(self.root_ino)) }
}
fn plain_fs(root_ino: u64) -> Arc<dyn FileSystem> { Arc::new(PlainFs { root_ino }) }

// (1) A single mount's last umount drops s_active 1→0 → put_super fires once.
#[test]
fn single_mount_last_umount_puts_super() {
    let _g = guard();
    let namespace = common::namespace_for_key(0xD61);
    set_namespace(&namespace);
    common::register("/", plain_fs(0x1)).expect("root");
    let (fs, ops) = count_fs(0x2);
    common::register("/data", fs).expect("data");
    let sb = common::mount_at_path_exact("/data").unwrap().sb().clone();
    assert_eq!(sb.s_active(), 1, "a freshly mounted SB has one active ref");
    assert_eq!(ops.puts.load(Ordering::Relaxed), 0, "no teardown while mounted");

    common::unregister("/data");
    assert_eq!(sb.s_active(), 0, "last umount drops the active ref to zero");
    assert_eq!(ops.puts.load(Ordering::Relaxed), 1, "put_super ran exactly once");
    assert!(ops.syncs.load(Ordering::Relaxed) >= 1, "sync_filesystem ran before put_super");
}

// (2) A SHARED SB (copy_mnt_ns clone) survives until its LAST mount drops:
// unmounting ONE of the two ns mounts must NOT run put_super. Guards the
// `grab_active` added to copy_mnt_ns — without it the first umount would hit
// 1→0 and tear the still-mounted peer's SB down.
#[test]
fn shared_sb_survives_until_last_mount() {
    let _g = guard();
    let parent = common::namespace_for_key(0xD62);
    set_namespace(&parent);
    common::register("/", plain_fs(0x1)).expect("root");
    let (fs, ops) = count_fs(0x2);
    common::register("/data", fs).expect("data");
    let sb = common::mount_at_path_exact("/data").unwrap().sb().clone();

    let child = vfs::mntns::allocate(parent.owner_user_namespace()).unwrap();
    vfs::mount::copy_mnt_ns(&parent, &child).unwrap();
    assert_eq!(sb.s_active(), 2, "two mounts now share the SB → two active refs");

    // Unmount the clone in the child ns: 2→1, NO teardown.
    set_namespace(&child);
    common::unregister("/data");
    assert_eq!(sb.s_active(), 1, "one mount still holds the shared SB");
    assert_eq!(ops.puts.load(Ordering::Relaxed), 0, "shared SB not torn down early");

    // Unmount the original in the parent ns: 1→0 → put_super.
    set_namespace(&parent);
    common::unregister("/data");
    assert_eq!(sb.s_active(), 0, "last mount gone → SB inactive");
    assert_eq!(ops.puts.load(Ordering::Relaxed), 1, "put_super ran once, on the LAST drop");
}

// (3) reap_ns (free_mnt_ns at last-task exit) mntputs each reaped mount: a
// ns-PRIVATE SB runs put_super, a SB still shared with the parent ns does not.
#[test]
fn reap_ns_puts_private_sb_keeps_shared() {
    let _g = guard();
    let parent = common::namespace_for_key(0xD63);
    set_namespace(&parent);
    common::register("/", plain_fs(0x1)).expect("root");
    let (shared, shared_ops) = count_fs(0x2);
    common::register("/shared", shared).expect("shared");
    let shared_sb = common::mount_at_path_exact("/shared").unwrap().sb().clone();

    // Child ns gets a clone of /shared (shared SB, grab_active → s_active 2).
    let child = vfs::mntns::allocate(parent.owner_user_namespace()).unwrap();
    vfs::mount::copy_mnt_ns(&parent, &child).unwrap();
    set_namespace(&child);
    // A child-PRIVATE mount with its own SB.
    let (priv_fs, priv_ops) = count_fs(0x3);
    common::register("/priv", priv_fs).expect("priv");
    let priv_sb = common::mount_at_path_exact("/priv").unwrap().sb().clone();
    assert_eq!(shared_sb.s_active(), 2, "shared SB held by both ns");
    assert_eq!(priv_sb.s_active(), 1, "private SB held only by the child");

    // Last task of the child ns exits → reap.
    set_namespace(&parent);
    drop(child);
    assert_eq!(priv_ops.puts.load(Ordering::Relaxed), 1, "ns-private SB torn down on reap");
    assert_eq!(priv_sb.s_active(), 0, "private SB inactive after reap");
    assert_eq!(shared_ops.puts.load(Ordering::Relaxed), 0, "shared SB survives reap");
    assert_eq!(shared_sb.s_active(), 1, "parent ns still holds the shared SB");
}
