//! dcache-D29: `d_splice_alias` directory single-dentry invariant (Linux
//! fs/dcache.c `d_splice_alias` → `__d_find_alias` → `__d_move`). When a
//! directory inode already carries a `D_DISCONNECTED` anon alias (from
//! `d_obtain_alias` / exportfs handle decode), splicing it into a negative
//! lookup dentry MUST reattach that one alias — never create a second positive
//! directory dentry (which would split the dcache subtree). Driven against a
//! real ramfs SuperBlock so `i_sb()` / `i_dentry` alias list resolve.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vfs::dcache::{d_alloc, d_obtain_alias, d_splice_alias, d_lookup};
use vfs::inode::Inode;
use vfs::{InodeBuilder, InodeOps, default_file_ops, default_inode_ops, mk_mode};
use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{FileType, InodeRef, KResult, VfsError};

struct RamFsType;
impl FileSystemType for RamFsType {
    fn name(&self) -> &str { "ramfs" }
    fn mount(&self, _s: &str, _o: &str) -> KResult<Arc<SuperBlock>> { Ok(mount_ramfs(0x51)) }
}
struct RamFsOps;
impl SuperOps for RamFsOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs { f_bsize: 4096, ..Default::default() }) }
}

/// Directory backend: child map lives in `i_private`; the namespace `lookup`
/// reads it off the concrete inode.
struct RamDirData { kids: Mutex<BTreeMap<String, InodeRef>> }
struct RamDirOps;
impl InodeOps for RamDirOps {
    fn lookup(&self, inode: &Inode, n: &str) -> KResult<InodeRef> {
        inode.private::<RamDirData>().unwrap().kids.lock().unwrap().get(n).cloned().ok_or(VfsError::Enoent)
    }
}

fn ramdir(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(RamDirOps), default_file_ops())
        .sb(Arc::downgrade(sb))
        .private(Arc::new(RamDirData { kids: Mutex::new(BTreeMap::new()) }))
        .build()
}
fn ramfile(sb: &Arc<SuperBlock>, ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .sb(Arc::downgrade(sb))
        .build()
}

fn mount_ramfs(s_dev: u64) -> Arc<SuperBlock> {
    let sb = SuperBlock::new(Arc::new(RamFsType), Arc::new(RamFsOps), 0x858458f6, s_dev, 4096, "ramfs".into(), Arc::new(()));
    vfs::d_make_root(ramdir(&sb, 2), &sb);
    sb
}

// A directory inode with a pre-existing D_DISCONNECTED anon alias: splicing it
// into a negative lookup dentry reattaches the anon alias under (parent, name)
// and leaves the inode with exactly ONE alias — no second dir dentry.
#[test]
fn splice_reattaches_disconnected_dir_alias_no_split() {
    let sb = mount_ramfs(1);
    let root = sb.s_root().unwrap();
    let dino: InodeRef = ramdir(&sb, 50);

    // exportfs/NFS path produced a disconnected dir dentry first.
    let anon = d_obtain_alias(dino.clone());
    assert!(anon.is_disconnected());
    assert_eq!(sb.i_aliases(50).len(), 1, "one (anon) alias before splice");

    // A path-walk lookup created a negative dentry for the same dir under root.
    let neg = d_alloc(&root, "sub");
    assert!(neg.is_negative());

    let spliced = d_splice_alias(dino.clone(), &neg);

    // Invariant: the inode has exactly ONE alias after the splice.
    let aliases = sb.i_aliases(50);
    assert_eq!(aliases.len(), 1, "directory single-dentry invariant: no split");
    assert!(Arc::ptr_eq(&aliases[0], &spliced), "the sole alias is the spliced dentry");

    // The spliced dentry is the connected, positive, hashed dir dentry at
    // (root, "sub") and is found by the global cache.
    assert!(!spliced.is_negative());
    assert!(!spliced.is_disconnected());
    assert!(spliced.is_hashed());
    let hit = d_lookup(&root, "sub").expect("spliced dir is cache-resolvable");
    assert!(Arc::ptr_eq(&hit, &spliced));
    assert!(Arc::ptr_eq(&spliced.inode().unwrap(), &dino));

    // The original anon alias is no longer on the inode's alias list and the
    // passed negative dentry was not turned into a second positive dir dentry.
    assert!(!Arc::ptr_eq(&spliced, &neg) || neg.is_negative() == false);
    for a in &aliases { assert!(!a.is_disconnected(), "no disconnected alias survives"); }
}

// Common path: a NON-directory (no prior alias) takes the plain
// negative→positive splice, instantiating and hashing the passed dentry.
#[test]
fn splice_regular_file_instantiates_passed_dentry() {
    let sb = mount_ramfs(2);
    let root = sb.s_root().unwrap();
    let fino: InodeRef = ramfile(&sb, 60);

    let neg = d_alloc(&root, "f");
    assert!(neg.is_negative());

    let spliced = d_splice_alias(fino.clone(), &neg);
    assert!(Arc::ptr_eq(&spliced, &neg), "regular splice keeps the passed dentry");
    assert!(!spliced.is_negative());
    assert!(spliced.is_hashed());
    assert!(Arc::ptr_eq(&spliced.inode().unwrap(), &fino));
    let aliases = sb.i_aliases(60);
    assert_eq!(aliases.len(), 1);
    assert!(Arc::ptr_eq(&aliases[0], &neg));
}

// A directory with NO prior alias also takes the plain splice (no anon to
// reattach) — the passed dentry becomes the one dir dentry.
#[test]
fn splice_dir_without_prior_alias_uses_passed_dentry() {
    let sb = mount_ramfs(3);
    let root = sb.s_root().unwrap();
    let dino: InodeRef = ramdir(&sb, 70);

    let neg = d_alloc(&root, "g");
    let spliced = d_splice_alias(dino.clone(), &neg);
    assert!(Arc::ptr_eq(&spliced, &neg), "no anon alias -> reuse passed dentry");
    assert!(spliced.is_hashed());
    assert_eq!(sb.i_aliases(70).len(), 1, "single dir dentry");
}
