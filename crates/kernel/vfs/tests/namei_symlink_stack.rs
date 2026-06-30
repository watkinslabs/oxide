//! D1/D12 — the symlink saved-link STACK in `Nameidata::walk` (Linux
//! `nd->stack` + `put_link`). Following a symlink suspends the active path
//! frame's remainder, resolves the link target as a new frame, then RESUMES the
//! suspended remainder once the target is consumed — replacing the old
//! splice-and-restart (`queue.extend(remainder); idx = 0`). These tests lock the
//! observable contract that structure must preserve:
//!   1. a symlink with a TRAILING remainder (`/lnk/leaf`, lnk→dir) resolves the
//!      remainder under the link target (the suspended frame resumes);
//!   2. a NESTED symlink (a link whose target itself contains a link) resolves
//!      through both levels;
//!   3. nesting + remainder together (`/a/extra`, a→"b/c", c→dir) resumes the
//!      OUTER remainder after the inner nested link is consumed;
//!   4. a symlink loop reached THROUGH nesting still hits the total-link cap
//!      (ELOOP at MAXSYMLINKS), so the per-frame stack does not defeat the limit.
//! Drives the real `vfs::path_lookup` over a synthetic inode tree.

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags, VfsError};

struct DirData { kids: BTreeMap<String, InodeRef> }
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DirData>().ok_or(VfsError::Enotdir)?;
        d.kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(DirOps), default_file_ops())
        .private(Arc::new(DirData { kids: m })).build()
}
fn file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}
fn sym(ino: u64, t: &str) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777), default_inode_ops(), default_file_ops())
        .size(t.len() as u64).link(t.as_bytes().to_vec().into_boxed_slice()).build()
}
fn look(root: &Arc<Dentry>, path: &str) -> KResult<(InodeRef, Arc<Dentry>)> {
    vfs::path_lookup(root.clone(), root.clone(), path, LookupFlags::default())
}

// `/lnk/leaf` where `lnk -> real` (relative symlink to a DIR): the trailing
// `leaf` must resolve UNDER `real` (the suspended remainder resumes).
#[test]
fn symlink_with_trailing_remainder() {
    let leaf = file(0xF1);
    let real = dir(0x20, &[("leaf", leaf)]);
    let root = Dentry::new_root(dir(2, &[("real", real), ("lnk", sym(0x30, "real"))]));
    let (i, _) = look(&root, "/lnk/leaf").expect("lnk/leaf resolves through the link target");
    assert_eq!(i.ino(), 0xF1, "remainder `leaf` resolved under the link target `real`");
}

// `/a` where `a -> "b/c"` and `c -> "d"` (c is a symlink INSIDE b): both link
// levels are followed (nested link), landing on `d`.
#[test]
fn nested_symlink_resolves_through_both_levels() {
    let d_file = file(0xD1);
    let b = dir(0x40, &[("c", sym(0x41, "d")), ("d", d_file)]);
    let root = Dentry::new_root(dir(2, &[("a", sym(0x42, "b/c")), ("b", b)]));
    let (i, _) = look(&root, "/a").expect("a -> b/c -> d");
    assert_eq!(i.ino(), 0xD1, "nested link a→b/c, c→d resolved to d");
}

// `/a/extra` where `a -> "b/c"`, `c -> "e"` (a DIR): the OUTER remainder
// `extra` must resume after the inner nested link `c` is consumed, resolving
// under `e`.
#[test]
fn nested_symlink_with_outer_remainder() {
    let g = file(0xA1);
    let e = dir(0x50, &[("extra", g)]);
    let b = dir(0x51, &[("c", sym(0x52, "e")), ("e", e)]);
    let root = Dentry::new_root(dir(2, &[("a", sym(0x53, "b/c")), ("b", b)]));
    let (i, _) = look(&root, "/a/extra").expect("a/extra → (b/c→e)/extra");
    assert_eq!(i.ino(), 0xA1, "outer remainder `extra` resumed under the nested target `e`");
}

// A loop reached THROUGH nesting (`a -> "b/c"`, `c -> "a"`) still exhausts the
// total-link budget → ELOOP. The per-frame stack must not defeat MAXSYMLINKS.
#[test]
fn nested_symlink_loop_is_eloop() {
    let b = dir(0x60, &[("c", sym(0x61, "/a"))]);
    let root = Dentry::new_root(dir(2, &[("a", sym(0x62, "b/c")), ("b", b)]));
    assert_eq!(look(&root, "/a").err(), Some(VfsError::Eloop),
        "nested symlink loop a→b/c→a is ELOOP at the total-link cap");
}
