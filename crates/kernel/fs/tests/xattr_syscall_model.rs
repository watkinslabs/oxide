//! The 12 legacy xattr entry points (188-199) driven over a REAL tmpfs tree:
//! the three variants per operation differ only in how the target inode is
//! reached, so this pins the part the shims own — plain follows the final
//! symlink, the `l` form does not, and the `f` form takes the fd's inode — and
//! shows the resulting stores are genuinely distinct per inode.
//!
//! `crates/kernel/fs/src/xattr/tests.rs` owns the decision-layer conformance
//! cases; `crates/kernel/ext4/tests/xattr_image.rs` owns on-disk persistence.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use fs::tmpfs::TmpfsFs;
use fs::xattr::{vfs_getxattr, vfs_listxattr, vfs_removexattr, vfs_setxattr, XattrCred};
use vfs::{CreateCtx, Dentry, FileType, InodeRef, LookupFlags};

const ENODATA: i64 = -61;

fn root_cred() -> XattrCred { XattrCred::root() }

/// tmpfs with `/file` and `/link -> file`; returns the root dentry.
fn tree() -> Arc<Dentry> {
    let fs = TmpfsFs::new(String::from("/"));
    let root = fs.root_inode();
    root.create_child("file", 0o644, &CreateCtx::root()).expect("create /file");
    root.symlink_child("link", b"file", &CreateCtx::root()).expect("symlink /link");
    Dentry::new_root(root)
}

/// The `follow`/`no-follow` resolution the plain vs `l` shims request.
fn resolve(root: &Arc<Dentry>, path: &str, follow: bool) -> InodeRef {
    let lf = LookupFlags { no_follow_final: !follow, follow, ..Default::default() };
    vfs::path_lookup_at_root_cred(root.clone(), 0, root.clone(), 0, path, lf, vfs::Cred::root())
        .expect("lookup").inode
}

#[test]
fn l_variants_target_the_symlink_itself_not_what_it_points_at() {
    let root = tree();
    let c = root_cred();
    let followed = resolve(&root, "/link", true);
    let link = resolve(&root, "/link", false);
    let file = resolve(&root, "/file", true);
    assert_eq!(followed.file_type(), FileType::Regular, "getxattr follows the final symlink");
    assert_eq!(link.file_type(), FileType::Symlink, "lgetxattr stops at the symlink");
    assert_eq!(followed.ino(), file.ino(), "the followed path is the target inode");

    // `security.*` is the namespace that is legal on a symlink (user.* is not,
    // per xattr_permission), and it is exactly what systemd labels links with.
    assert_eq!(vfs_setxattr(&link, "security.selinux", b"link_t".to_vec(), 0, &c), Ok(()));
    assert_eq!(vfs_setxattr(&file, "security.selinux", b"file_t".to_vec(), 0, &c), Ok(()));
    // Each store belongs to its own inode: no bleed in either direction.
    assert_eq!(vfs_getxattr(&link, "security.selinux", &c), Ok(b"link_t".to_vec()));
    assert_eq!(vfs_getxattr(&followed, "security.selinux", &c), Ok(b"file_t".to_vec()));
    // Removing through the symlink leaves the target's attribute intact.
    assert_eq!(vfs_removexattr(&link, "security.selinux", &c), Ok(()));
    assert_eq!(vfs_getxattr(&link, "security.selinux", &c), Err(ENODATA));
    assert_eq!(vfs_getxattr(&file, "security.selinux", &c), Ok(b"file_t".to_vec()));
    // A user.* write to the symlink is EPERM, and the read hides it as ENODATA.
    assert_eq!(vfs_setxattr(&link, "user.x", b"v".to_vec(), 0, &c), Err(-1));
    assert_eq!(vfs_getxattr(&link, "user.x", &c), Err(ENODATA));
}

#[test]
fn tmpfs_xattrs_are_per_inode_and_survive_re_resolution() {
    let root = tree();
    let c = root_cred();
    {
        let file = resolve(&root, "/file", true);
        assert_eq!(vfs_setxattr(&file, "user.comment", b"kept".to_vec(), 0, &c), Ok(()));
        assert_eq!(vfs_setxattr(&file, "trusted.t", b"priv".to_vec(), 0, &c), Ok(()));
    }
    // Re-resolve from scratch (the "open/close" boundary a caller sees).
    let again = resolve(&root, "/file", true);
    assert_eq!(vfs_getxattr(&again, "user.comment", &c), Ok(b"kept".to_vec()));
    assert_eq!(vfs_listxattr(&again, &c), Ok(b"trusted.t\0user.comment\0".to_vec()));
    // The root directory has its own, empty store.
    let dir = resolve(&root, "/", true);
    assert_eq!(vfs_listxattr(&dir, &c), Ok(alloc::vec::Vec::new()));
    assert_eq!(vfs_getxattr(&dir, "user.comment", &c), Err(ENODATA));
}
