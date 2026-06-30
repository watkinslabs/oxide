//! BIG-REWRITE-2 sub-round 2a groundwork (NON-hot-path). Pins the new mount
//! structures the 2b hot-path flip will read, while the path walk still crosses
//! via the legacy per-ns `dentry.mounted_mounts` map:
//!
//!   * MOUNT_HASH re-keyed to `(parent_mnt_id, dentry_ptr)` — `ns` dropped from
//!     the key (`parent_mnt_id` is ns-private). `__lookup_mnt(parent, d)` is the
//!     new crossing primitive.
//!   * [D9] an OVERMOUNT's parent is the UNDERLAY mount (not the shared
//!     underlay dentry's parent), so `__lookup_mnt(underlay, underlay_root)`
//!     resolves the overmount top deterministically.
//!   * `D_MOUNTED` is a REFCOUNTED hint (Linux `d_set_mounted`/`__put_mountpoint`)
//!     set on the mountpoint's `m_count` 0→1 and cleared on the last drop —
//!     including across `copy_mnt_ns` clones.
//!
//! Process-global mount tables ⇒ SERIAL-guarded; each test uses UNIQUE paths /
//! namespaces so leftover state cannot bleed across tests in this binary.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{default_file_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> { SERIAL.lock().unwrap_or_else(|e| e.into_inner()) }

static CUR_NS: AtomicU64 = AtomicU64::new(0);
fn cur_ns() -> u64 { CUR_NS.load(Ordering::Acquire) }
fn set_ns(n: u64) { CUR_NS.store(n, Ordering::Release); }

// Directory-factory backend: any name resolves to a fresh child dir, so a
// mountpoint path materialises on demand (mount routing keys on dentry IDENTITY,
// deduped by the dcache, so fresh inodes are fine).
static INO: AtomicU64 = AtomicU64::new(0x5000);
fn next_ino() -> u64 { INO.fetch_add(1, Ordering::Relaxed) }
struct FacOps;
impl InodeOps for FacOps {
    fn lookup(&self, _i: &Inode, _n: &str) -> KResult<InodeRef> { Ok(facdir(next_ino())) }
}
fn facdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(FacOps), default_file_ops()).build()
}

// Static child-table dir for the named-fs roots (kept distinct from the factory).
struct DirData { kids: BTreeMap<String, InodeRef> }
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        inode.private::<DirData>().ok_or(VfsError::Enotdir)?
            .kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn sdir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops())
        .private(Arc::new(DirData { kids: m })).build()
}

struct NamedFs { n: &'static str, root: InodeRef }
impl FileSystem for NamedFs {
    fn name(&self) -> &str { self.n }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
}

static ROOT: OnceLock<Arc<Dentry>> = OnceLock::new();
static ROOT_INODE: OnceLock<InodeRef> = OnceLock::new();
fn root_provider() -> Option<Arc<Dentry>> { ROOT.get().cloned() }

/// Install the fixture + register the ns-root mount for `host`, returning the
/// global root dentry. The provider root inode and the root mount share ONE
/// inode (exactly the boot / sandbox-test wiring).
fn install(host: u64) -> Arc<Dentry> {
    vfs::mount::set_current_ns_provider(cur_ns);
    set_ns(host);
    let root_inode = ROOT_INODE.get_or_init(|| facdir(2)).clone();
    let root = ROOT.get_or_init(|| Dentry::new_root(root_inode.clone())).clone();
    vfs::set_root_dentry_provider(root_provider);
    vfs::mount::register(None, Arc::new(NamedFs { n: "rootfs", root: root_inode })).expect("ns root mount");
    root
}

fn lookup_d(root: &Arc<Dentry>, p: &str) -> Arc<Dentry> {
    vfs::path_lookup(root.clone(), root.clone(), p, LookupFlags::default()).expect("lookup").1
}

// ---- A) MOUNT_HASH re-key: __lookup_mnt resolves by (parent, dentry) ----------
#[test]
fn hash_rekey_lookup_mnt_resolves_by_parent_dentry() {
    let _g = guard();
    const H: u64 = 0x2A_0001;
    let root = install(H);

    // Underlay mountpoint dentry, captured BEFORE the mount so it is the
    // underlay (not the mounted-fs root the post-mount walk would cross to).
    let mp = lookup_d(&root, "/a/x");
    vfs::mount::register(Some(mp.clone()), Arc::new(NamedFs { n: "axfs", root: facdir(0x100) }))
        .expect("mount /a/x");

    let m = vfs::mount::mount_at_path_exact(&mp).expect("mount at /a/x");
    let parent = vfs::mount::containing_mount_id(H, &mp);
    // The new crossing primitive resolves the mount under the TRUE containing
    // parent (= the mount the walk is in at `mp`).
    assert_eq!(vfs::mount::__lookup_mnt(parent, &mp).map(|m| m.mnt_id), Some(m.mnt_id),
        "__lookup_mnt(containing parent, mp) resolves the mounted fs");
    // A bogus parent id finds nothing — the key really is (parent, dentry).
    assert!(vfs::mount::__lookup_mnt(0xDEAD_BEEF, &mp).is_none(),
        "wrong parent_mnt_id must not resolve (parent IS part of the key)");
    // Recorded parent == the containing mount.
    assert_eq!(vfs::mount::parent_mnt_id(&m), parent);

    assert_eq!(vfs::mount::unregister(&mp), 1);
}

// ---- B) [D9] overmount stack top-resolution via __lookup_mnt + LIFO reveal ----
// This codebase represents an overmount as a Vec stack on the shared underlay
// mountpoint dentry (the caller hands the engine the underlay dentry; any fs
// root is `is_global_root`-filtered to the ns-root path). The 2a contract: the
// new `(parent, dentry)` hash resolves the TOP deterministically and pops to the
// underlay on umount. (The is-root [D9] parent re-computation is exercised on
// the rebuild/move paths by the sandbox/executor integration tests, which fail
// without it.)
#[test]
fn overmount_stack_lookup_mnt_resolves_top_and_reveals_underlay() {
    let _g = guard();
    const H: u64 = 0x2A_0002;
    let root = install(H);

    // Underlay mountpoint dentry; both mounts stack on THIS same dentry.
    let mp = lookup_d(&root, "/ov");
    let parent = vfs::mount::containing_mount_id(H, &mp);

    vfs::mount::register(Some(mp.clone()), Arc::new(NamedFs { n: "underfs", root: facdir(0x200) }))
        .expect("underlay mount /ov");
    let a_id = vfs::mount::mount_at_path_exact(&mp).expect("underlay").mnt_id;

    vfs::mount::register(Some(mp.clone()), Arc::new(NamedFs { n: "overfs", root: facdir(0x201) }))
        .expect("overmount on /ov");
    let b_id = vfs::mount::mount_at_path_exact(&mp).expect("overmount top").mnt_id;
    assert_ne!(a_id, b_id);

    // Both stack under the SAME containing parent on the SAME dentry; the new
    // crossing primitive returns the LAST attached (top) deterministically.
    assert_eq!(vfs::mount::parent_mnt_id(&vfs::mount::mount_by_id(b_id).unwrap()), parent);
    assert_eq!(vfs::mount::__lookup_mnt(parent, &mp).map(|m| m.mnt_id), Some(b_id),
        "__lookup_mnt resolves the overmount TOP (last attached)");

    // Pop the top → the underlay is revealed (LIFO), and __lookup_mnt agrees.
    assert_eq!(vfs::mount::unregister(&mp), 1);
    assert_eq!(vfs::mount::__lookup_mnt(parent, &mp).map(|m| m.mnt_id), Some(a_id),
        "umount of the top reveals the underlay via the new hash");
    assert!(mp.is_mounted(), "underlay still mounted → flag stays");

    // Pop the underlay → empty position, flag clears.
    assert_eq!(vfs::mount::unregister(&mp), 1);
    assert!(vfs::mount::__lookup_mnt(parent, &mp).is_none());
    assert!(!mp.is_mounted());
}

// ---- C) D_MOUNTED refcount: set on first mount, clear on the LAST umount ------
#[test]
fn d_mounted_set_on_mount_and_cleared_on_last_umount() {
    let _g = guard();
    const H: u64 = 0x2A_0003;
    let root = install(H);

    let mp = lookup_d(&root, "/m");
    assert!(!mp.is_mounted(), "bare dentry is not a mountpoint");

    vfs::mount::register(Some(mp.clone()), Arc::new(NamedFs { n: "m1", root: facdir(0x300) }))
        .expect("first mount");
    assert!(mp.is_mounted(), "D_MOUNTED set on the m_count 0->1 create path");

    // Second mount on the SAME underlay dentry (Vec-stack overmount): refcount 2.
    vfs::mount::register(Some(mp.clone()), Arc::new(NamedFs { n: "m2", root: facdir(0x301) }))
        .expect("stacked mount");
    assert!(mp.is_mounted());

    // First umount pops the top — one mount remains, flag MUST stay set.
    assert_eq!(vfs::mount::unregister(&mp), 1);
    assert!(mp.is_mounted(), "one mount remains → D_MOUNTED stays set (refcounted)");

    // Last umount clears the flag (m_count 1->0).
    assert_eq!(vfs::mount::unregister(&mp), 1);
    assert!(!mp.is_mounted(), "last umount clears D_MOUNTED");
}

// ---- D) copy_mnt_ns keeps the D_MOUNTED refcount correct across namespaces ----
#[test]
fn copy_mnt_ns_keeps_d_mounted_refcount() {
    let _g = guard();
    const H: u64 = 0x2A_0004;
    const S: u64 = 0x2A_0005;
    let root = install(H);

    // Underlay mountpoint dentry captured before the mount; mount a pseudo-fs.
    let mp = lookup_d(&root, "/proc");
    vfs::mount::register(Some(mp.clone()), Arc::new(NamedFs { n: "proc", root: sdir(0x400, &[]) }))
        .expect("mount /proc in host");
    assert!(mp.is_mounted());

    // Clone the host ns into a private ns: the clone REUSES the same mountpoint
    // dentry, so the D_MOUNTED refcount must rise to 2 (the 2a copy_mnt_ns fix).
    vfs::mount::copy_mnt_ns(H, S);
    assert!(mp.is_mounted(), "clone registered the crossing → flag still set");
    assert!(vfs::mount::__lookup_mnt(vfs::mount::containing_mount_id(S, &mp), &mp).is_some(),
        "clone wired the crossing in S (strict hash, ns-private parent)");

    // Umount in the host ns: the clone in S still pins the mountpoint, so the
    // refcounted flag MUST survive (this is exactly what the per-ns map alone
    // could not express → the 203/226 class of bugs).
    set_ns(H);
    assert_eq!(vfs::mount::unregister(&mp), 1);
    assert!(mp.is_mounted(), "S clone still holds the mountpoint → D_MOUNTED stays");
    assert!(vfs::mount::__lookup_mnt(vfs::mount::containing_mount_id(H, &mp), &mp).is_none(),
        "host crossing gone");
    assert!(vfs::mount::__lookup_mnt(vfs::mount::containing_mount_id(S, &mp), &mp).is_some(),
        "S crossing intact");

    // Umount in the private ns: now the LAST holder drops → flag clears.
    set_ns(S);
    assert_eq!(vfs::mount::unregister(&mp), 1);
    assert!(!mp.is_mounted(), "last umount across all namespaces clears D_MOUNTED");
}
