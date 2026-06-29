//! D38: `fork_clone` couples `f_count` — parent and child fd slots point at the
//! SAME open file description (`Arc<File>`), bumping its strong count, NOT a
//! transmute-clone or a fresh `File`. POSIX: fork shares the open-file
//! description (cursor / flags), only the fd-table slots are separate. These
//! tests drive the real `FdTable` and assert pointer identity + that the
//! shared cursor is visible through both tables.

use std::sync::Arc;

use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, InodeRef, OpenFlags,
          default_file_ops, default_inode_ops, mk_mode};

fn mk_file() -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(0x7, mk_mode(FileType::Regular, 0o644),
        default_inode_ops(), default_file_ops()).build();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDWR)
}

/// The child's fd slot is the SAME `Arc<File>` as the parent's (identity), and
/// the f_count rose to cover the new reference.
#[test]
fn child_shares_same_arc_and_bumps_f_count() {
    let parent = FdTable::new();
    let fd = parent.alloc(mk_file()).unwrap();

    let pf = parent.get(fd).unwrap();
    let count_before = pf.f_count(); // parent slot + this local handle
    drop(pf);

    let child = parent.fork_clone();

    let a = parent.get(fd).unwrap();
    let b = child.get(fd).unwrap();
    assert!(Arc::ptr_eq(&a, &b), "fork shares the SAME open file description");

    // parent slot + child slot + the two local handles `a`,`b`.
    assert_eq!(a.f_count(), count_before + 2,
        "fork_clone bumped f_count by one (the child reference)");
}

/// The shared description means a cursor advance through the PARENT's handle is
/// visible through the CHILD's handle — they are one `File`, not two copies.
#[test]
fn shared_cursor_visible_through_both() {
    let parent = FdTable::new();
    let fd = parent.alloc(mk_file()).unwrap();
    let child = parent.fork_clone();

    parent.get(fd).unwrap().set_pos(4096);
    assert_eq!(child.get(fd).unwrap().pos(), 4096,
        "cursor is shared across the fork (same Arc<File>)");
}

/// Closing the parent's fd does NOT release the description while the child
/// still holds it — the last drop wins (f_count coupling).
#[test]
fn close_one_keeps_description_alive() {
    let parent = FdTable::new();
    let fd = parent.alloc(mk_file()).unwrap();
    let child = parent.fork_clone();

    let held = child.get(fd).unwrap();
    parent.close(fd).unwrap();
    assert!(parent.get(fd).is_err(), "parent slot gone");
    // child + local `held` still alive.
    assert_eq!(held.f_count(), 2, "description alive via child reference");
    assert!(child.get(fd).is_ok(), "child still has the open description");
}
