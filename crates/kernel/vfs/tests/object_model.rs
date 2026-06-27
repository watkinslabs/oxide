//! WP1 acceptance: the Linux VFS object model (super_block / dentry /
//! inode) + dcache primitives, proved against a real in-memory ramfs
//! SuperBlock with PER-COMPONENT `i_op->lookup` and NO global path→dentry
//! map. Mirrors the spec test matrix T1-T9 (`16§2`/`16§4`).
//!
//! Resolution here is purely `d_lookup(parent,name)` → `i_op->lookup` →
//! `d_add(parent,name,inode)`. There is no whole-path string anywhere.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use vfs::inode::Inode;
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{Dentry, FileType, InodeRef, KResult, VfsError};

// ---- ramfs backend: a real SuperBlock with per-component lookup ----

struct RamFsType;
impl FileSystemType for RamFsType {
    fn name(&self) -> &str { "ramfs" }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> { Ok(mount_ramfs(0x858458f6)) }
}

struct RamFsOps { magic: u64 }
impl SuperOps for RamFsOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_type: self.magic, f_bsize: 4096, ..Default::default() }) }
}

/// In-memory directory inode. `lookup` is PER-COMPONENT and counts its
/// invocations so a test can prove the dcache shortcut fired.
struct RamDir {
    ino:    u64,
    sb:     Weak<SuperBlock>,
    kids:   Mutex<BTreeMap<String, InodeRef>>,
    lookups: Arc<AtomicUsize>,
}
impl Inode for RamDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        self.kids.lock().unwrap().get(name).cloned().ok_or(VfsError::Enoent)
    }
}

struct RamFile { ino: u64, sb: Weak<SuperBlock> }
impl Inode for RamFile {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

fn dir(sb: &Arc<SuperBlock>, ino: u64, lookups: &Arc<AtomicUsize>) -> Arc<RamDir> {
    Arc::new(RamDir { ino, sb: Arc::downgrade(sb), kids: Mutex::new(BTreeMap::new()), lookups: lookups.clone() })
}
fn file(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef { Arc::new(RamFile { ino, sb: Arc::downgrade(sb) }) }
fn link(parent: &Arc<RamDir>, name: &str, child: InodeRef) { parent.kids.lock().unwrap().insert(name.into(), child); }

/// Build a ramfs SuperBlock with a root inode + `s_root` dentry.
fn mount_ramfs(s_dev: u64) -> Arc<SuperBlock> {
    let magic = 0x858458f6u64;
    let sb = SuperBlock::new(
        Arc::new(RamFsType),
        Arc::new(RamFsOps { magic }),
        magic, s_dev, 4096, "ramfs".into(), Arc::new(()),
    );
    let lookups = Arc::new(AtomicUsize::new(0));
    let root_inode = dir(&sb, 2, &lookups);
    vfs::d_make_root(root_inode, &sb); // sets sb.s_root
    sb
}

// ---- a component walker that uses ONLY d_lookup / i_op->lookup / d_add ----

fn walk(root: &Arc<Dentry>, path: &str) -> Result<Arc<Dentry>, VfsError> {
    let mut cur = root.clone();
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        let child = match vfs::d_lookup(&cur, comp) {
            Some(d) if !d.is_negative() => d,           // dcache fast path
            Some(_neg) => return Err(VfsError::Enoent),  // cached miss: no i_op->lookup
            None => {
                let inode = cur.inode().ok_or(VfsError::Enotdir)?;
                match inode.lookup(comp) {
                    Ok(ci) => vfs::d_add(&cur, comp, ci),  // slow path → cache
                    Err(_) => { vfs::d_add_negative(&cur, comp); return Err(VfsError::Enoent); }
                }
            }
        };
        cur = child;
    }
    Ok(cur)
}

// ----------------------------- T1-T9 -----------------------------

#[test]
fn t1_d_alloc_is_negative() {
    let sb = mount_ramfs(1);
    let root = sb.s_root().unwrap();
    let neg = vfs::d_alloc(&root, "x");
    assert!(neg.is_negative(), "d_alloc yields a negative dentry");
    assert!(neg.inode().is_none(), "negative dentry has no inode");
    assert!(neg.flags() & vfs::D_NEGATIVE != 0, "D_NEGATIVE set");
    // d_alloc does NOT hash: parent has no cached child yet.
    assert!(vfs::d_lookup(&root, "x").is_none(), "d_alloc is unhashed");
}

#[test]
fn t2_miss_then_lookup_then_positive_shared_arc() {
    let sb = mount_ramfs(1);
    let lk = Arc::new(AtomicUsize::new(0));
    let r = dir(&sb, 2, &lk);
    link(&r, "f", file(&sb, 11));
    // Instrumented root inode so the i_op->lookup is observable.
    let rootd = Dentry::new_root_in_sb(r, &sb);

    assert!(vfs::d_lookup(&rootd, "f").is_none(), "cold cache: miss");
    let i = rootd.inode().unwrap().lookup("f").expect("i_op->lookup");
    let d1 = vfs::d_add(&rootd, "f", i);
    assert!(!d1.is_negative(), "d_add → positive");
    let d2 = vfs::d_lookup(&rootd, "f").expect("now cached");
    assert!(Arc::ptr_eq(&d1, &d2), "one dentry per (parent,name)");
    assert_eq!(d1.inode().unwrap().ino(), 11);
}

#[test]
fn t3_negative_caching_skips_inode_lookup() {
    let sb = mount_ramfs(1);
    let lk = Arc::new(AtomicUsize::new(0));
    let r = dir(&sb, 2, &lk);            // empty dir: every name absent
    let rootd = Dentry::new_root_in_sb(r, &sb);

    // First resolve: miss → i_op->lookup (count 1) → cache negative.
    assert_eq!(walk(&rootd, "ghost").err(), Some(VfsError::Enoent));
    assert_eq!(lk.load(Ordering::SeqCst), 1, "one i_op->lookup on cold miss");
    // Second resolve: d_lookup hits the cached negative; i_op->lookup NOT called.
    assert_eq!(walk(&rootd, "ghost").err(), Some(VfsError::Enoent));
    assert_eq!(lk.load(Ordering::SeqCst), 1, "negative dentry served the second miss");
}

#[test]
fn t4_per_sb_hashing_same_name_two_sbs() {
    let sb_a = mount_ramfs(0xa);
    let sb_b = mount_ramfs(0xb);
    let ra = sb_a.s_root().unwrap();
    let rb = sb_b.s_root().unwrap();
    let da = vfs::d_add(&ra, "etc", file(&sb_a, 100));
    let db = vfs::d_add(&rb, "etc", file(&sb_b, 200));
    assert!(!Arc::ptr_eq(&da, &db), "same name in two SBs = two distinct dentries");
    let sa = da.d_sb().expect("d_sb A");
    let sb = db.d_sb().expect("d_sb B");
    assert!(!Arc::ptr_eq(&sa, &sb), "the two dentries upgrade to different superblocks");
    assert_eq!(sa.s_dev, 0xa);
    assert_eq!(sb.s_dev, 0xb);
    // Inode fsid derives from i_sb().s_dev (no hardcoded value).
    assert_eq!(da.inode().unwrap().fsid(), 0xa);
    assert_eq!(db.inode().unwrap().fsid(), 0xb);
}

#[test]
fn t5_dget_dput_refcount() {
    let sb = mount_ramfs(1);
    let root = sb.s_root().unwrap();
    let d = vfs::d_add(&root, "f", file(&sb, 11));
    let before = Arc::strong_count(&d);
    let g = vfs::dget(&d);
    assert_eq!(Arc::strong_count(&d), before + 1, "dget increments refcount");
    vfs::dput(g);
    assert_eq!(Arc::strong_count(&d), before, "dput restores refcount");
}

#[test]
fn t6_d_move_rehomes_by_parent_name() {
    let sb = mount_ramfs(1);
    let root = sb.s_root().unwrap();
    let a = vfs::d_add(&root, "a", Arc::new(RamDir { ino: 3, sb: Arc::downgrade(&sb), kids: Mutex::new(BTreeMap::new()), lookups: Arc::new(AtomicUsize::new(0)) }));
    let b = vfs::d_add(&root, "b", Arc::new(RamDir { ino: 4, sb: Arc::downgrade(&sb), kids: Mutex::new(BTreeMap::new()), lookups: Arc::new(AtomicUsize::new(0)) }));
    let old = vfs::d_add(&a, "old", file(&sb, 11));
    assert!(vfs::d_lookup(&a, "old").is_some());

    let moved = vfs::d_move(&old, &b, "new");
    assert!(vfs::d_lookup(&a, "old").is_none(), "unhashed from old parent");
    let got = vfs::d_lookup(&b, "new").expect("hashed under new parent");
    assert!(Arc::ptr_eq(&got, &moved));
    assert_eq!(moved.name(), "new", "name updated");
    assert!(Arc::ptr_eq(moved.parent().unwrap(), &b), "parent reparented");
    assert_eq!(moved.inode().unwrap().ino(), 11, "inode carried across");
}

#[test]
fn t7_component_walk_no_global_path_map() {
    let sb = mount_ramfs(1);
    let lk = Arc::new(AtomicUsize::new(0));
    // /usr/share/zoneinfo/UTC built as a per-component ramfs tree.
    let utc = file(&sb, 21);
    let zone = dir(&sb, 22, &lk); link(&zone, "UTC", utc);
    let share = dir(&sb, 23, &lk); link(&share, "zoneinfo", zone);
    let usr = dir(&sb, 24, &lk); link(&usr, "share", share);
    let root = dir(&sb, 2, &lk); link(&root, "usr", usr);
    let rootd = Dentry::new_root_in_sb(root, &sb);

    let leaf = walk(&rootd, "/usr/share/zoneinfo/UTC").expect("per-component resolve");
    assert_eq!(leaf.inode().unwrap().ino(), 21);
    // Second walk is fully dcache-served: zero new i_op->lookup calls.
    let after_first = lk.load(Ordering::SeqCst);
    let _ = walk(&rootd, "/usr/share/zoneinfo/UTC").unwrap();
    assert_eq!(lk.load(Ordering::SeqCst), after_first, "dcache served the repeat walk");
    // Each component dentry is parent-linked (no flat path key).
    assert_eq!(leaf.name(), "UTC");
    assert_eq!(leaf.parent().unwrap().name(), "zoneinfo");
}

#[test]
fn t8_d_make_root_s_root_positive_parentless() {
    let sb = mount_ramfs(0x1234);
    let root = sb.s_root().expect("s_root installed by d_make_root");
    assert!(!root.is_negative(), "root is positive");
    assert!(root.parent().is_none(), "root is parentless");
    assert!(root.is_root(), "D_ROOT set");
    assert_eq!(root.name(), "", "root has empty name");
    let rsb = root.d_sb().expect("root d_sb upgrades");
    assert!(Arc::ptr_eq(&rsb, &sb), "root.d_sb == its superblock");
    assert_eq!(sb.statfs().unwrap().f_type, sb.s_magic);
}

#[test]
fn t9_unlink_flips_positive_to_negative() {
    let sb = mount_ramfs(1);
    let root = sb.s_root().unwrap();
    let d = vfs::d_add(&root, "f", file(&sb, 11));
    assert!(!d.is_negative(), "created positive");
    // unlink: drop the inode (Linux d_delete → negative).
    vfs::d_instantiate(&d, file(&sb, 11)); // sanity: instantiate keeps positive
    assert!(!d.is_negative());
    d.set_inode(None);                      // the unlink transition
    assert!(d.is_negative(), "post-unlink: negative dentry");
    assert!(d.flags() & vfs::D_NEGATIVE != 0, "D_NEGATIVE re-set");
    // A re-stat through the dcache now reports Enoent (the Info-ZIP guard).
    assert_eq!(walk(&root, "f").err(), Some(VfsError::Enoent));
}
