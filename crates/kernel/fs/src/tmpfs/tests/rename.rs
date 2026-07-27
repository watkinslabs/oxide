// F740: `shmem_rename2`'s contract — the flag set tmpfs actually implements,
// the `!simple_empty(new_dentry)` ENOTEMPTY gate, and the `..` link
// accounting a directory move moves between the two parents
// (`simple_rename` / `simple_rename_exchange` in `fs/libfs.c`).

use alloc::string::String;
use alloc::sync::Arc;

use vfs::namei::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};
use vfs::{CreateCtx, FileType, VfsError};

use super::super::{TmpfsFs, TmpfsSb};

fn fs() -> Arc<TmpfsFs> { TmpfsFs::with_limits(String::from("/"), TmpfsSb::new(64, 32)) }

#[test]
fn unsupported_flag_bits_are_einval_not_ignored() {
    let fs = fs();
    let root = fs.root_inode();
    root.create_child("a", 0o644, &CreateCtx::root()).expect("create a");
    for bad in [1u32 << 3, 1 << 31, 0xF8] {
        assert_eq!(root.rename_child("a", &root, "b", bad, &CreateCtx::root()),
                   Err(VfsError::Einval), "flag {bad:#x} must be refused, never silently dropped");
    }
    // The three shmem does implement are not refused here.
    assert!(root.rename_child("a", &root, "b", RENAME_NOREPLACE, &CreateCtx::root()).is_ok());
    assert!(root.rename_child("b", &root, "c", RENAME_WHITEOUT, &CreateCtx::root()).is_ok());
}

#[test]
fn rename_onto_nonempty_directory_is_enotempty() {
    let fs = fs();
    let root = fs.root_inode();
    let src = root.mkdir("src", 0o755, &CreateCtx::root()).expect("mkdir src");
    let dst = root.mkdir("dst", 0o755, &CreateCtx::root()).expect("mkdir dst");
    dst.mkdir("keep", 0o755, &CreateCtx::root()).expect("mkdir dst/keep");

    assert_eq!(root.rename_child("src", &root, "dst", 0, &CreateCtx::root()),
               Err(VfsError::Enotempty));
    // Both trees intact — the populated victim was not silently discarded.
    assert!(root.lookup("src").is_ok(), "source survives");
    let still = root.lookup("dst").expect("dst survives");
    assert!(Arc::ptr_eq(&still, &dst));
    assert!(dst.lookup("keep").is_ok(), "the victim's child is still reachable");
    assert!(Arc::ptr_eq(&src, &root.lookup("src").unwrap()));
}

#[test]
fn rename_onto_empty_directory_succeeds() {
    let fs = fs();
    let root = fs.root_inode();
    let src = root.mkdir("src", 0o755, &CreateCtx::root()).expect("mkdir src");
    root.mkdir("dst", 0o755, &CreateCtx::root()).expect("mkdir dst");
    let root_nl0 = root.nlink();

    root.rename_child("src", &root, "dst", 0, &CreateCtx::root()).expect("empty victim is fine");

    assert!(Arc::ptr_eq(&root.lookup("dst").unwrap(), &src));
    assert!(root.lookup("src").is_err());
    // The replaced directory's `..` left; the moved one never changed parent.
    assert_eq!(root.nlink(), root_nl0 - 1, "root nets one lost back-reference");
}

#[test]
fn cross_parent_directory_move_shifts_the_dotdot_link() {
    let fs = fs();
    let root = fs.root_inode();
    let a = root.mkdir("a", 0o755, &CreateCtx::root()).expect("mkdir a");
    let b = root.mkdir("b", 0o755, &CreateCtx::root()).expect("mkdir b");
    a.mkdir("sub", 0o755, &CreateCtx::root()).expect("mkdir a/sub");
    let (a0, b0) = (a.nlink(), b.nlink());

    a.rename_child("sub", &b, "sub", 0, &CreateCtx::root()).expect("move a/sub -> b/sub");

    assert_eq!(a.nlink(), a0 - 1, "old parent lost the child's ..");
    assert_eq!(b.nlink(), b0 + 1, "new parent gained the child's ..");
    assert!(b.lookup("sub").is_ok() && a.lookup("sub").is_err());
}

#[test]
fn cross_parent_move_of_a_file_leaves_both_parent_link_counts_alone() {
    let fs = fs();
    let root = fs.root_inode();
    let a = root.mkdir("a", 0o755, &CreateCtx::root()).expect("mkdir a");
    let b = root.mkdir("b", 0o755, &CreateCtx::root()).expect("mkdir b");
    a.create_child("f", 0o644, &CreateCtx::root()).expect("create a/f");
    let (a0, b0) = (a.nlink(), b.nlink());

    a.rename_child("f", &b, "f", 0, &CreateCtx::root()).expect("move a/f -> b/f");

    assert_eq!((a.nlink(), b.nlink()), (a0, b0), "only directories carry a ..");
}

#[test]
fn cross_parent_exchange_of_a_mixed_pair_swaps_one_dotdot_each_way() {
    let fs = fs();
    let root = fs.root_inode();
    let a = root.mkdir("a", 0o755, &CreateCtx::root()).expect("mkdir a");
    let b = root.mkdir("b", 0o755, &CreateCtx::root()).expect("mkdir b");
    a.mkdir("d", 0o755, &CreateCtx::root()).expect("mkdir a/d");
    b.create_child("f", 0o644, &CreateCtx::root()).expect("create b/f");
    let (a0, b0) = (a.nlink(), b.nlink());

    a.rename_child("d", &b, "f", RENAME_EXCHANGE, &CreateCtx::root()).expect("exchange");

    assert_eq!(a.nlink(), a0 - 1, "a gave up the directory");
    assert_eq!(b.nlink(), b0 + 1, "b took the directory");
    assert_eq!(b.lookup("f").unwrap().file_type(), FileType::Directory);
    assert_eq!(a.lookup("d").unwrap().file_type(), FileType::Regular);
}

#[test]
fn cross_parent_exchange_of_two_directories_leaves_both_counts_intact() {
    let fs = fs();
    let root = fs.root_inode();
    let a = root.mkdir("a", 0o755, &CreateCtx::root()).expect("mkdir a");
    let b = root.mkdir("b", 0o755, &CreateCtx::root()).expect("mkdir b");
    a.mkdir("x", 0o755, &CreateCtx::root()).expect("mkdir a/x");
    b.mkdir("y", 0o755, &CreateCtx::root()).expect("mkdir b/y");
    let (a0, b0) = (a.nlink(), b.nlink());

    a.rename_child("x", &b, "y", RENAME_EXCHANGE, &CreateCtx::root()).expect("exchange dirs");

    assert_eq!((a.nlink(), b.nlink()), (a0, b0), "each parent loses one .. and gains one");
}
