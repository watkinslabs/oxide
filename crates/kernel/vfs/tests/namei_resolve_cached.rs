//! RESOLVE_CACHED (`openat2(2)`): the walk resolves ONLY from the dcache and
//! NEVER calls a filesystem `i_op->lookup`. A dcache miss that would take the
//! (possibly blocking) slow path is `EAGAIN`; once the path is warm in the
//! dcache the same `cached` resolve succeeds. Drives the real `vfs::path_lookup`
//! walker over a synthetic inode tree.
//!
//! Fails-before: pre-fix the `cached` flag did not exist / was unenforced, so a
//! cold `cached` resolve took the slow path and SUCCEEDED instead of `EAGAIN`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, LookupFlags, VfsError};

// Global dcache is process-wide; serialise so concurrent tests in this binary
// cannot warm each other's cache entries by racing.
static SERIAL: Mutex<()> = Mutex::new(());

struct DirData { kids: BTreeMap<String, InodeRef> }
struct DirOps;
impl vfs::InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> vfs::KResult<InodeRef> {
        inode.private::<DirData>().unwrap().kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}


fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755),
        Arc::new(DirOps), vfs::default_file_ops())
        .private(Arc::new(DirData { kids: m })).build()
}
fn file(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644),
        vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

// /a/b/c (file ino 0xC), all per-component.
fn build_root() -> Arc<Dentry> {
    let c = file(0xC);
    let b = dir(0xB, &[("c", c)]);
    let a = dir(0xA, &[("b", b)]);
    Dentry::new_root(dir(2, &[("a", a)]))
}

fn cached() -> LookupFlags { let mut f = LookupFlags::default(); f.cached = true; f }

// Cold dcache: `cached` resolution refuses with EAGAIN rather than calling
// `i_op->lookup` (the slow path). The very FIRST component (`a`) is not cached,
// so the walk bails immediately.
#[test]
fn cold_cache_eagain() {
    let _g = SERIAL.lock().unwrap();
    let root = build_root();
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), "/a/b/c", cached()).err(),
        Some(VfsError::Eagain),
        "RESOLVE_CACHED on a cold dcache must EAGAIN, not walk the fs",
    );
}

// After a normal (non-cached) resolve warms every (parent,name) edge into the
// dcache, the SAME `cached` resolve is served entirely from cache → success.
#[test]
fn warm_cache_succeeds() {
    let _g = SERIAL.lock().unwrap();
    let root = build_root();
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/a/b/c", LookupFlags::default())
        .expect("warm the dcache via a normal resolve");
    assert_eq!(i.ino(), 0xC);
    let (j, _) = vfs::path_lookup(root.clone(), root.clone(), "/a/b/c", cached())
        .expect("cached resolve served from the warm dcache");
    assert_eq!(j.ino(), 0xC, "RESOLVE_CACHED succeeds once the path is cached");
}

// Partial warmth: only the PREFIX is cached. The cached walk gets past the warm
// components, then EAGAINs at the first cold edge (deeper than what was warmed).
#[test]
fn partial_cache_eagain_at_cold_edge() {
    let _g = SERIAL.lock().unwrap();
    let root = build_root();
    // Warm only `/a` (and its dentry), leaving `/a/b` and `/a/b/c` cold.
    let _ = vfs::path_lookup(root.clone(), root.clone(), "/a", LookupFlags::default())
        .expect("warm just /a");
    assert_eq!(
        vfs::path_lookup(root.clone(), root.clone(), "/a/b/c", cached()).err(),
        Some(VfsError::Eagain),
        "cached walk advances through warm /a then EAGAINs at the cold /a/b edge",
    );
}
