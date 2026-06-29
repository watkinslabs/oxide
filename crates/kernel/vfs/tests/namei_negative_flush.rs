//! D5/D6 (INSERT side) — the path walk CACHES a confirmed lookup miss as a
//! NEGATIVE dentry, so a repeated stat/lookup of a missing name is served from
//! the dcache WITHOUT re-invoking the slow-path `i_op->lookup` (Linux
//! `d_add_negative`). Two correctness contracts are locked here:
//!
//!   1. SAFETY — caching is gated to filesystems whose namespace mutates only
//!      through the flushed VFS create/unlink/rename syscalls (`neg_cache_ok`:
//!      ext4/tmpfs/ramfs). On a pseudo-fs (e.g. procfs) a miss is NOT cached, so
//!      a dynamically-appearing entry (`/proc/<pid>`, `/sys` hotplug, devpts) is
//!      never masked forever. (`pseudo_fs_miss_is_not_cached`)
//!
//!   2. NO-MASK — on a cacheable fs, after a miss caches a negative, a later
//!      "create" that materialises the name and FLUSHES the leaf negative (what
//!      `pathresolve::d_drop_path` does in the create handlers, simulated here
//!      with `d_drop`) makes the file VISIBLE: the negative did not mask the
//!      created file. Without the flush, the negative WOULD mask it — proving the
//!      create-handler flush is load-bearing. (`create_after_miss_is_visible`)
//!
//!   3. SERVED-FROM-CACHE — a second lookup of the still-missing name is answered
//!      by the cached negative; `i_op->lookup` is not consulted again.
//!      (`second_lookup_of_miss_served_from_cache`)
//!
//! Drives the REAL `vfs::path_lookup` over a synthetic inode tree attached to a
//! real `SuperBlock` (the fs-type name is the `neg_cache_ok` discriminator).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use vfs::inode::Inode;
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder,
          InodeOps, InodeRef, KResult, LookupFlags, VfsError};

// The global DENTRY_HASHTABLE + the counter below are process-wide: serialize.
static SERIAL: Mutex<()> = Mutex::new(());
// `i_op->lookup` invocation counter — bumps ONLY when the slow path runs, so a
// short-circuited (cached-negative) component leaves it untouched.
static LOOKUPS: AtomicUsize = AtomicUsize::new(0);

/// fs-type whose `name()` drives `neg_cache_ok`. `"ext4"` is cacheable; a
/// pseudo name (`"procfs"`) is not.
struct NamedType(&'static str);
impl FileSystemType for NamedType {
    fn name(&self) -> &str { self.0 }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

struct NullOps;
impl SuperOps for NullOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}

fn sb_named(name: &'static str, dev: u64) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(NamedType(name)), Arc::new(NullOps), 0x1234, dev, 4096,
        name.into(), Arc::new(()))
}

/// Mutable directory: `lookup` consults a live child table and bumps `LOOKUPS`
/// every time the slow path runs (so a cached-negative short-circuit is visible
/// as a flat counter). A miss returns `Enoent` — the walk then caches it.
struct MutDirData { kids: Mutex<BTreeMap<String, InodeRef>> }
struct MutDirOps;
impl InodeOps for MutDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        LOOKUPS.fetch_add(1, Ordering::SeqCst);
        let d = inode.private::<MutDirData>().ok_or(VfsError::Enotdir)?;
        d.kids.lock().unwrap().get(name).cloned().ok_or(VfsError::Enoent)
    }
}

fn mut_dir(ino: u64, sb: &Arc<SuperBlock>) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(MutDirOps), default_file_ops())
        .sb(Arc::downgrade(sb))
        .private(Arc::new(MutDirData { kids: Mutex::new(BTreeMap::new()) }))
        .build()
}
fn leaf(ino: u64, sb: &Arc<SuperBlock>) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb)).build()
}

/// Add `name → ino` to the live dir table (the backend half of a create).
fn insert_child(dir: &InodeRef, sb: &Arc<SuperBlock>, name: &str, ino: u64) {
    let d = dir.private::<MutDirData>().unwrap();
    d.kids.lock().unwrap().insert(name.to_string(), leaf(ino, sb));
}

// On a cacheable fs (name "ext4") a miss is cached as a negative, and a SECOND
// lookup of the same missing name is served from the dcache — `i_op->lookup` is
// NOT consulted again (the counter stays at 1).
#[test]
fn second_lookup_of_miss_served_from_cache() {
    let _g = SERIAL.lock().unwrap();
    LOOKUPS.store(0, Ordering::SeqCst);
    let sb = sb_named("ext4", 0x501);
    let root_inode = mut_dir(2, &sb);
    let root = vfs::d_make_root(root_inode, &sb);

    // First lookup of a missing name: slow path runs once → Enoent, negative cached.
    assert_eq!(vfs::path_lookup(root.clone(), root.clone(), "/ghost", LookupFlags::default()).err(),
        Some(VfsError::Enoent), "miss returns ENOENT");
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 1, "first miss consulted i_op->lookup once");
    let neg = vfs::d_lookup(&root, "ghost").expect("miss cached a dentry on a cacheable fs");
    assert!(neg.is_negative(), "the cached dentry is NEGATIVE");

    // Second lookup is served from the cached negative — no further fs consult.
    assert_eq!(vfs::path_lookup(root.clone(), root.clone(), "/ghost", LookupFlags::default()).err(),
        Some(VfsError::Enoent), "second miss still ENOENT");
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 1, "negative served from cache; no extra fs lookup");
}

// THE no-mask guarantee: a name stat'd while missing caches a negative; once it
// is CREATED and the leaf negative is FLUSHED (what the create handlers do via
// pathresolve::d_drop_path), the file is visible. The same flow WITHOUT the
// flush leaves the file masked — proving the flush is load-bearing.
#[test]
fn create_after_miss_is_visible() {
    let _g = SERIAL.lock().unwrap();
    LOOKUPS.store(0, Ordering::SeqCst);
    let sb = sb_named("ext4", 0x502);
    let root_inode = mut_dir(2, &sb);
    let root = vfs::d_make_root(root_inode.clone(), &sb);

    // 1) stat the not-yet-existing name → caches a negative.
    assert_eq!(vfs::path_lookup(root.clone(), root.clone(), "/new", LookupFlags::default()).err(),
        Some(VfsError::Enoent), "pre-create stat is ENOENT");
    assert!(vfs::d_lookup(&root, "new").expect("negative cached").is_negative());

    // 2) backend create WITHOUT a flush → the stale negative still MASKS it.
    insert_child(&root_inode, &sb, "new", 0x900);
    assert_eq!(vfs::path_lookup(root.clone(), root.clone(), "/new", LookupFlags::default()).err(),
        Some(VfsError::Enoent), "un-flushed negative masks the created file (flush IS load-bearing)");

    // 3) flush the leaf negative (== pathresolve::d_drop_path) → file visible.
    vfs::d_drop(&vfs::d_lookup(&root, "new").expect("negative still present"));
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/new", LookupFlags::default())
        .expect("after flush the created file resolves");
    assert_eq!(i.ino(), 0x900, "resolved the freshly-created inode, not masked by the negative");
}

// SAFETY gate: on a pseudo-fs (name "procfs") a miss is NOT cached — so a
// dynamically-appearing entry that materialises WITHOUT a create syscall is
// never masked by a stale negative. The second lookup re-walks the slow path.
#[test]
fn pseudo_fs_miss_is_not_cached() {
    let _g = SERIAL.lock().unwrap();
    LOOKUPS.store(0, Ordering::SeqCst);
    let sb = sb_named("procfs", 0x503);
    let root_inode = mut_dir(2, &sb);
    let root = vfs::d_make_root(root_inode, &sb);

    assert_eq!(vfs::path_lookup(root.clone(), root.clone(), "/1234", LookupFlags::default()).err(),
        Some(VfsError::Enoent), "pseudo-fs miss is ENOENT");
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 1, "first miss consulted i_op->lookup");
    assert!(vfs::d_lookup(&root, "1234").is_none(),
        "a pseudo-fs miss is NOT cached as a negative (would mask /proc/<pid> forever)");

    // Second lookup re-walks the slow path (no cached negative to short-circuit).
    assert_eq!(vfs::path_lookup(root.clone(), root.clone(), "/1234", LookupFlags::default()).err(),
        Some(VfsError::Enoent), "pseudo-fs miss still ENOENT");
    assert_eq!(LOOKUPS.load(Ordering::SeqCst), 2, "pseudo-fs re-consults i_op->lookup (uncached)");
}
