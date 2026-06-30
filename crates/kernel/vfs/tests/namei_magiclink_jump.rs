//! namei D13 / file D34 — in-walk magic-link `nd_jump_link`. A MAGIC link
//! (`/proc/<pid>/fd/<n>`-class) inode's `i_op->get_link` returns a resolved
//! JUMP target — a `(mnt,dentry,inode)` — and the walk RESETS its current
//! position to it (Linux `nd_jump_link`) instead of splicing a path string.
//! These tests lock the observable contract over a synthetic inode tree (no
//! procfs / no QEMU):
//!   1. a walk THROUGH a magic link (`/magic/leaf`) jumps to the link's target
//!      and resolves the remaining component UNDER it;
//!   2. `readlink`/`get_link` (the bytes accessor readlink(2) uses) returns the
//!      link TEXT — the jump target is NOT stringified;
//!   3. RESOLVE_NO_MAGICLINKS makes a magic link followed in the walk ELOOP;
//!   4. an ordinary (non-magic) symlink is unaffected — still follows its body.

use std::collections::BTreeMap;
use std::sync::Arc;

use vfs::inode::Inode;
use vfs::{default_file_ops, default_inode_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Dentry, FileType, InodeRef, KResult, LinkTarget, LookupFlags, VfsError, VfsPath};

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

/// `i_private` of a synthetic MAGIC link: the resolved jump target + the
/// readlink TEXT (the two views Linux keeps distinct for a magic symlink).
struct MagicData { dentry: Arc<Dentry>, inode: InodeRef, text: Vec<u8> }
struct MagicOps;
impl InodeOps for MagicOps {
    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        Ok(inode.private::<MagicData>().unwrap().text.clone())
    }
    fn get_link(&self, inode: &Inode) -> KResult<LinkTarget> {
        let d = inode.private::<MagicData>().unwrap();
        Ok(LinkTarget::Jump(VfsPath {
            mnt_id: 0, dentry: d.dentry.clone(), inode: d.inode.clone(), last_component: None,
        }))
    }
}
/// A magic-link inode (FileType::Symlink) whose `get_link` jumps to
/// `(target_dentry,target_inode)`; `readlink` returns `text`.
fn magic(ino: u64, target_dentry: Arc<Dentry>, target_inode: InodeRef, text: &str) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777), Arc::new(MagicOps), default_file_ops())
        .size(text.len() as u64)
        .private(Arc::new(MagicData { dentry: target_dentry, inode: target_inode, text: text.as_bytes().to_vec() }))
        .build()
}

fn look_flags(root: &Arc<Dentry>, path: &str, f: LookupFlags) -> KResult<(InodeRef, Arc<Dentry>)> {
    vfs::path_lookup(root.clone(), root.clone(), path, f)
}
fn look(root: &Arc<Dentry>, path: &str) -> KResult<(InodeRef, Arc<Dentry>)> {
    look_flags(root, path, LookupFlags::default())
}

// Build a tree with `magic` → JUMP to a `real` dir holding `leaf`.
fn tree() -> (Arc<Dentry>, InodeRef) {
    let leaf = file(0xF1);
    let real = dir(0x20, &[("leaf", leaf)]);
    let real_dentry = Dentry::new_root(real.clone());
    let m = magic(0x30, real_dentry, real, "/some/open/file");
    let root = Dentry::new_root(dir(2, &[("magic", m), ("plain", sym(0x40, "magic"))]));
    (root, file(0xF1))
}

// `/magic/leaf`: the walk follows the magic link via `nd_jump_link` to the
// jump target dir, then resolves the remaining `leaf` UNDER it.
#[test]
fn walk_through_magic_link_jumps_to_target() {
    let (root, _) = tree();
    let (i, _) = look(&root, "/magic/leaf").expect("magic jump resolves /magic/leaf");
    assert_eq!(i.ino(), 0xF1, "remainder `leaf` resolved under the jump target");
}

// stat-class follow of the magic link as the FINAL component lands on the
// jump target inode (the dir), not the link inode.
#[test]
fn walk_final_magic_link_lands_on_target() {
    let (root, _) = tree();
    let (i, _) = look(&root, "/magic").expect("magic resolves to its jump target");
    assert_eq!(i.ino(), 0x20, "final magic link followed → jump target dir inode");
}

// readlink(2)'s bytes accessor returns the link TEXT — the jump target is NOT
// stringified into a path.
#[test]
fn readlink_shows_text_not_jump() {
    let leaf = file(0xF1);
    let real = dir(0x20, &[("leaf", leaf)]);
    let m = magic(0x30, Dentry::new_root(real.clone()), real, "/some/open/file");
    assert_eq!(m.get_link().unwrap(), b"/some/open/file");
    assert_eq!(m.readlink().unwrap(), b"/some/open/file");
    // The follow-path (walk) takes the JUMP arm, distinct from the text bytes.
    assert!(matches!(m.follow_link().unwrap(), LinkTarget::Jump(_)));
}

// RESOLVE_NO_MAGICLINKS: a magic link followed in the walk → ELOOP (Linux
// `nd_jump_link` under LOOKUP_NO_MAGICLINKS).
#[test]
fn no_magiclinks_walk_is_eloop() {
    let (root, _) = tree();
    let f = LookupFlags { no_magiclinks: true, ..Default::default() };
    assert_eq!(look_flags(&root, "/magic/leaf", f).err(), Some(VfsError::Eloop),
        "magic link followed under RESOLVE_NO_MAGICLINKS is ELOOP");
}

// An ordinary (non-magic) symlink is unaffected: `plain` → "magic", which is
// itself the magic link, so `/plain/leaf` still resolves through both.
#[test]
fn ordinary_symlink_still_follows_body() {
    let (root, _) = tree();
    let (i, _) = look(&root, "/plain/leaf").expect("plain symlink follows its body");
    assert_eq!(i.ino(), 0xF1, "ordinary symlink body splice unaffected by jump support");
}
