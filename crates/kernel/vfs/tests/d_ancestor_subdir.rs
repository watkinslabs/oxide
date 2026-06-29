//! dentry-D28: `d_ancestor`/`is_subdir_of` parent-chain ancestry (Linux
//! `fs/dcache.c`). The rename keystone loop check (`do_rename` returns
//! `-EINVAL` when a directory would move into its own descendant) and
//! `is_path_reachable` both ask "does A lie inside B's subtree?". Pre-change
//! neither primitive existed (compile failure); this proves the semantics.

use std::sync::Arc;

use vfs::{Dentry, FileType, InodeRef};

fn dir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

// Build the tree  root -> a -> b -> c  plus a sibling  a -> s.
fn tree() -> (Arc<Dentry>, Arc<Dentry>, Arc<Dentry>, Arc<Dentry>, Arc<Dentry>) {
    let root = Dentry::new_root(dir(1));
    let a = Dentry::new_child(&root, "a", Some(dir(2)));
    let b = Dentry::new_child(&a, "b", Some(dir(3)));
    let c = Dentry::new_child(&b, "c", Some(dir(4)));
    let s = Dentry::new_child(&a, "s", Some(dir(5)));
    (root, a, b, c, s)
}

#[test]
fn d_ancestor_returns_child_on_path_to_descendant() {
    // Linux `d_ancestor(p1, p2)` returns the direct child of p1 that lies on
    // the chain down to p2.
    let (root, a, b, c, _s) = tree();
    assert!(Arc::ptr_eq(&root.d_ancestor(&c).unwrap(), &a), "root's child toward c is a");
    assert!(Arc::ptr_eq(&a.d_ancestor(&c).unwrap(), &b), "a's child toward c is b");
    assert!(Arc::ptr_eq(&b.d_ancestor(&c).unwrap(), &c), "b's child toward c is c");
}

#[test]
fn d_ancestor_is_strict_and_directional() {
    let (root, a, _b, c, _s) = tree();
    assert!(c.d_ancestor(&c).is_none(), "self is not a strict ancestor of self");
    assert!(c.d_ancestor(&a).is_none(), "a is above c, so c is not an ancestor of a");
    assert!(c.d_ancestor(&root).is_none(), "root is above c");
}

#[test]
fn is_subdir_of_includes_self() {
    // Linux `is_subdir(new, old)` is true when new == old.
    let (_root, a, _b, c, _s) = tree();
    assert!(c.is_subdir_of(&c), "a dentry is a subdir of itself");
    assert!(a.is_subdir_of(&a));
}

#[test]
fn is_subdir_of_true_for_descendant() {
    let (root, a, b, c, _s) = tree();
    assert!(c.is_subdir_of(&b), "c is under b");
    assert!(c.is_subdir_of(&a), "c is under a");
    assert!(c.is_subdir_of(&root), "c is under root");
    assert!(b.is_subdir_of(&root));
}

#[test]
fn is_subdir_of_false_upward_and_sideways() {
    // The rename loop check relies on these being false: a is NOT a subdir of
    // its own descendant c, and siblings are unrelated.
    let (_root, a, b, c, s) = tree();
    assert!(!a.is_subdir_of(&c), "ancestor is not a subdir of its descendant (the -EINVAL guard)");
    assert!(!b.is_subdir_of(&c));
    assert!(!s.is_subdir_of(&c), "sibling subtrees are unrelated");
    assert!(!c.is_subdir_of(&s));
}

#[test]
fn is_subdir_of_across_separate_trees_is_false() {
    let (_root, _a, _b, c, _s) = tree();
    let (other_root, _oa, _ob, _oc, _os) = tree();
    assert!(!c.is_subdir_of(&other_root), "a dentry in one tree is not under another tree's root");
}
