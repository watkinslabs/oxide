// dcache: filesystem-internal path reconstruction (Linux `__dentry_path` /
// `dentry_path_raw`, fs/d_path.c). Asserts the d_parent walk to a stop root,
// the root-renders-as-"/" rule, the explicit-root truncation, and the
// " (deleted)" suffix for unlinked-but-open and anonymous-disconnected
// dentries. This is the within-superblock reconstructor `getcwd`,
// `/proc/<pid>/fd/N` readlink, and the `/proc/<pid>/maps` path column need.

use std::sync::Arc;

use vfs::{Dentry, FileType, InodeRef};

/// Minimal directory inode whose `lookup` is never exercised (the test builds
/// the dentry tree by hand). A fresh ino per node keeps identities distinct.
fn dir(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, 0o755), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}
/// Minimal regular-file inode for the unlinked-but-open case.
fn reg(ino: u64) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Regular, 0o644), vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

/// Build /usr/bin, hashing every node so none reads as "unlinked".
fn tree() -> (Arc<Dentry>, Arc<Dentry>, Arc<Dentry>) {
    let root = Dentry::new_root(dir(2));
    let usr = Dentry::new_child(&root, "usr", Some(dir(0x10)));
    let bin = Dentry::new_child(&usr, "bin", Some(dir(0x11)));
    usr.set_hashed(true);
    bin.set_hashed(true);
    (root, usr, bin)
}

#[test]
fn nested_walks_to_global_root() {
    let (_root, _usr, bin) = tree();
    assert_eq!(bin.dentry_path(None), "/usr/bin");
}

#[test]
fn root_renders_single_slash() {
    let (root, _usr, _bin) = tree();
    assert_eq!(root.dentry_path(None), "/");
}

#[test]
fn explicit_root_truncates_prefix() {
    let (root, usr, bin) = tree();
    // Stop at `usr`: its own name is not prepended, the leading slash stands in.
    assert_eq!(bin.dentry_path(Some(&usr)), "/bin");
    // Stop at the filesystem root explicitly — same as the implicit walk.
    assert_eq!(bin.dentry_path(Some(&root)), "/usr/bin");
    // Querying the stop dentry itself is the root case.
    assert_eq!(bin.dentry_path(Some(&bin)), "/");
}

#[test]
fn unlinked_open_file_marked_deleted() {
    let (_root, usr, _bin) = tree();
    // A removed-but-open file keeps its parent link but is dropped from the
    // hash (`is_unlinked`): path reconstructs to its old location + " (deleted)".
    let f = Dentry::new_child(&usr, "tmp.log", Some(reg(0x20)));
    assert!(f.is_unlinked(), "fresh unhashed non-root child is d_unlinked");
    assert_eq!(f.dentry_path(None), "/usr/tmp.log (deleted)");
}

#[test]
fn anonymous_disconnected_marked_deleted() {
    // `d_obtain_alias` anon dentry: parentless, D_DISCONNECTED, unreachable.
    let anon = Dentry::new_anon(reg(0x30));
    assert!(anon.is_disconnected());
    assert_eq!(anon.dentry_path(None), "/ (deleted)");
}

#[test]
fn hashed_child_not_marked_deleted() {
    // Regression guard: a properly hashed, reachable dentry gets NO marker —
    // the suffix is reserved for genuinely unreachable dentries.
    let (_root, _usr, bin) = tree();
    assert!(!bin.is_unlinked());
    assert!(!bin.dentry_path(None).contains("(deleted)"));
}
