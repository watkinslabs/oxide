//! `get_tree_*` superblock-sharing helpers (Linux `fs/super.c`). A backend's
//! `get_tree` op calls `get_tree_nodev` (fresh SB per mount), `get_tree_single`
//! (one SB for the whole fs_type), or `get_tree_keyed` (SB shared by a key)
//! instead of hand-allocating. Fails-before: only the legacy `->mount` path
//! existed; there was no `sget`-style sharing, so two mounts of a
//! single-instance pseudo-fs each built a divergent SB. These prove nodev never
//! shares, single collapses to one SB (fill_super runs once), keyed shares by
//! key, and the user `sb_flags` slice is stamped on the freshly built SB.
//!
//! SERIAL: the shared-super registry is one global list. Each test uses UNIQUE
//! fs-type names so disjoint registrants never interleave on the shared state.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use vfs::fs::{get_tree_keyed, get_tree_nodev, get_tree_single, FileSystem};
use vfs::fs::fs_context::FsContext;
use vfs::superblock::{next_anon_dev, FileSystemType, SuperBlock, SB_RDONLY};
use vfs::{FileType, InodeBuilder, InodeRef, KResult, VfsError,
          default_file_ops, default_inode_ops, mk_mode};

fn tdir() -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Directory, 0), default_inode_ops(), default_file_ops()).build()
}

struct TFs { nm: &'static str }
impl FileSystem for TFs {
    fn name(&self) -> &str { self.nm }
    fn root(&self) -> Option<InodeRef> { Some(tdir()) }
}

struct Ty { nm: &'static str }
impl FileSystemType for Ty {
    fn name(&self) -> &str { self.nm }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

/// A fill_super closure factory: builds a real SB over a fresh root and counts
/// how many times fill actually ran (Linux only runs fill_super on a cache miss).
fn filler(nm: &'static str, calls: Arc<AtomicU32>)
    -> impl FnOnce(&mut FsContext) -> KResult<Arc<SuperBlock>> {
    move |_fc| {
        calls.fetch_add(1, Ordering::SeqCst);
        let fs: Arc<dyn FileSystem> = Arc::new(TFs { nm });
        Ok(SuperBlock::for_backend(fs.clone(), TFs { nm }.root(), next_anon_dev(), nm.to_string()))
    }
}

#[test]
fn nodev_builds_a_fresh_sb_every_call() {
    let ty: Arc<dyn FileSystemType> = Arc::new(Ty { nm: "gt_nodev" });
    let calls = Arc::new(AtomicU32::new(0));

    let mut fc1 = FsContext::for_mount(ty.clone(), 0);
    let a = get_tree_nodev(&mut fc1, filler("gt_nodev", calls.clone())).unwrap();
    let mut fc2 = FsContext::for_mount(ty, 0);
    let b = get_tree_nodev(&mut fc2, filler("gt_nodev", calls.clone())).unwrap();

    assert!(!Arc::ptr_eq(&a, &b), "nodev never shares — two distinct superblocks");
    assert_ne!(a.s_dev, b.s_dev, "each nodev mount gets its own anon dev");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "fill_super ran for both");
}

#[test]
fn single_collapses_to_one_sb_and_fills_once() {
    let ty: Arc<dyn FileSystemType> = Arc::new(Ty { nm: "gt_single" });
    let calls = Arc::new(AtomicU32::new(0));

    let mut fc1 = FsContext::for_mount(ty.clone(), 0);
    let a = get_tree_single(&mut fc1, filler("gt_single", calls.clone())).unwrap();
    let mut fc2 = FsContext::for_mount(ty, 0);
    let b = get_tree_single(&mut fc2, filler("gt_single", calls.clone())).unwrap();

    assert!(Arc::ptr_eq(&a, &b), "single shares ONE sb across mounts of the fs_type");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "fill_super ran once (cache hit on 2nd)");
    assert!(a.s_active() >= 2, "shared reuse bumped s_active");
}

#[test]
fn keyed_shares_within_a_key_and_separates_across_keys() {
    let ty: Arc<dyn FileSystemType> = Arc::new(Ty { nm: "gt_keyed" });
    let calls = Arc::new(AtomicU32::new(0));

    let mut fc1 = FsContext::for_mount(ty.clone(), 0);
    let k1a = get_tree_keyed(&mut fc1, "netns-7", filler("gt_keyed", calls.clone())).unwrap();
    let mut fc2 = FsContext::for_mount(ty.clone(), 0);
    let k1b = get_tree_keyed(&mut fc2, "netns-7", filler("gt_keyed", calls.clone())).unwrap();
    let mut fc3 = FsContext::for_mount(ty, 0);
    let k2 = get_tree_keyed(&mut fc3, "netns-9", filler("gt_keyed", calls.clone())).unwrap();

    assert!(Arc::ptr_eq(&k1a, &k1b), "same key shares the superblock");
    assert!(!Arc::ptr_eq(&k1a, &k2), "different key → distinct superblock");
    assert_eq!(calls.load(Ordering::SeqCst), 2, "fill ran once per distinct key");
}

#[test]
fn sb_flags_stamped_on_freshly_built_sb() {
    let ty: Arc<dyn FileSystemType> = Arc::new(Ty { nm: "gt_flags" });
    let calls = Arc::new(AtomicU32::new(0));

    let mut ro = FsContext::for_mount(ty.clone(), SB_RDONLY);
    let sb = get_tree_nodev(&mut ro, filler("gt_flags", calls.clone())).unwrap();
    assert!(sb.is_readonly(), "SB_RDONLY in fc->sb_flags stamped onto the sb");

    let mut rw = FsContext::for_mount(ty, 0);
    let sb2 = get_tree_nodev(&mut rw, filler("gt_flags", calls)).unwrap();
    assert!(!sb2.is_readonly(), "no SB_RDONLY → writable sb");
}
