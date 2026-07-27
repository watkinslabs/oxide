//! `link_path_walk` `!d_can_lookup` → ENOTDIR + may_lookup ordering (docs/16§3).
//! A path component is resolved WITHIN the current inode, which must be a
//! directory — this includes the PARENT of a LOOKUP_PARENT leaf
//! (`mknod("/a/file/leaf")`). The walker must reject a non-directory parent
//! with ENOTDIR, and must enforce `may_lookup` (MAY_EXEC) search permission on
//! that parent BEFORE returning it (Linux calls `may_lookup` at the top of
//! every component iteration, the final parent included).

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, LookupFlags, VfsError};

struct DirData { kids: BTreeMap<String, InodeRef> }
struct DirOps;
impl vfs::InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> vfs::KResult<InodeRef> {
        inode.private::<DirData>().unwrap().kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}

// A regular file that DELIBERATELY mis-reports its lookup as Enoent (not
// Enotdir) — proving the WALKER enforces ENOTDIR itself, not the fs op.
struct FOps;
impl vfs::InodeOps for FOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> vfs::KResult<InodeRef> { Err(VfsError::Enoent) }
}

fn dir(ino: u64, perm: Option<u16>, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, perm.unwrap_or(0o755)),
        Arc::new(DirOps), vfs::default_file_ops())
        .private(Arc::new(DirData { kids: m })).build()
}
fn file(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644),
        Arc::new(FOps), vfs::default_file_ops()).build()
}

fn parent_flags() -> LookupFlags { let mut f = LookupFlags::default(); f.parent = true; f }

fn nonroot() -> vfs::namei::Cred {
    vfs::namei::Cred {
        uid: 1000, gid: 1000, cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}

// Build:  /dir(0755)/file(regular)   plus  /priv(0600)/leaf? (no exec bit)
fn build() -> Arc<Dentry> {
    let f = file(11);
    let d = dir(10, Some(0o755), &[("file", f)]);
    let priv_d = dir(20, Some(0o600), &[]); // no search/exec bit
    let root = dir(2, Some(0o755), &[("dir", d), ("priv", priv_d)]);
    Dentry::new_root(root)
}

// Full (non-parent) lookup through a regular file mid-path → ENOTDIR, enforced
// by the walker even though `F::lookup` returns Enoent.
#[test]
fn nondir_intermediate_is_enotdir() {
    let root = build();
    let r = vfs::path_lookup_path(root.clone(), root, "/dir/file/leaf", LookupFlags::default());
    assert_eq!(r.err(), Some(VfsError::Enotdir),
        "a non-directory path prefix is ENOTDIR (walker-enforced, not fs-op)");
}

// LOOKUP_PARENT whose PARENT is a regular file → ENOTDIR. Before the fix the
// walker stopped at the leaf and returned the non-directory `file` as the
// parent (Ok), letting mknod/rename/create operate inside a non-directory.
#[test]
fn parent_must_be_directory() {
    let root = build();
    let r = vfs::path_lookup_path(root.clone(), root, "/dir/file/leaf", parent_flags());
    assert_eq!(r.err(), Some(VfsError::Enotdir),
        "LOOKUP_PARENT parent that is a regular file is ENOTDIR");
}

// LOOKUP_PARENT must enforce search permission on the parent directory BEFORE
// stopping. /priv is 0600 (no exec bit); a non-root create there is EACCES.
// Before the fix the parent-stop ran ahead of may_lookup, so this returned Ok.
#[test]
fn parent_requires_search_permission() {
    let root = build();
    let r = vfs::namei::path_lookup_cred(root.clone(), root, "/priv/newfile", parent_flags(), nonroot());
    assert_eq!(r.err(), Some(VfsError::Eacces),
        "LOOKUP_PARENT enforces MAY_EXEC on the parent dir");
}

// Sanity: a valid LOOKUP_PARENT in a searchable dir still returns parent+leaf.
#[test]
fn valid_parent_still_resolves() {
    let root = build();
    let p = vfs::path_lookup_path(root.clone(), root, "/dir/newfile", parent_flags()).expect("parent walk");
    assert_eq!(p.inode.ino(), 10, "parent is /dir");
    assert_eq!(p.last_component.as_deref(), Some("newfile"), "leaf carried out");
}
