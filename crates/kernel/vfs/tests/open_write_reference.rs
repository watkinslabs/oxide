//! The inode write reference an open file description holds for its whole
//! lifetime, and the `ETXTBSY` it produces in both directions.
//!
//! The primitive (a signed writer/exec counter, `>0` writers and `<0` execs,
//! each refusing the other) is covered by `i_writecount.rs`. What is covered
//! HERE is the wiring nobody had: the reference must be taken by the OPEN, held
//! by the DESCRIPTION, and released only at the final close. A reference taken
//! and dropped inside the open call frame protects nothing — the whole point is
//! that a binary is "running" for as long as some other description exists.

extern crate alloc;

use vfs::{default_file_ops, default_inode_ops, mk_mode, Dentry, FileCred, FileType, InodeRef,
    OpenFlags, VfsError};

/// A non-zero mount id. No such mount is registered, so the mount write
/// admission finds nothing and cannot mask the write-reference decision; the id
/// being non-zero is what marks this a real open rather than an anonymous file.
const MNT: u64 = 7;

fn reg(perm: u16) -> InodeRef {
    vfs::InodeBuilder::new(4242, mk_mode(FileType::Regular, perm),
        default_inode_ops(), default_file_ops()).build()
}

fn node(ftype: FileType) -> InodeRef {
    vfs::InodeBuilder::new(4243, mk_mode(ftype, 0o666),
        default_inode_ops(), default_file_ops()).build()
}

fn open(inode: &InodeRef, flags: OpenFlags, mnt_id: u64)
    -> Result<alloc::sync::Arc<vfs::File>, VfsError>
{
    vfs::file::open_file_at(inode.clone(), Dentry::new_root(inode.clone()), flags, mnt_id,
        FileCred::root(), None)
}

#[test]
fn a_write_open_holds_the_reference_until_it_is_closed() {
    let i = reg(0o755);
    assert_eq!(i.writecount(), 0);
    let f = open(&i, OpenFlags::O_WRONLY, MNT).expect("write-open a plain file");
    assert_eq!(i.writecount(), 1, "the description, not the open call frame, holds the reference");
    // While it is held, the file cannot be executed.
    assert!(matches!(i.deny_write_access(), Err(VfsError::Etxtbsy)));
    drop(f);
    assert_eq!(i.writecount(), 0, "the final close releases exactly one reference");
    i.deny_write_access().expect("executable again once the writer is gone");
}

#[test]
fn a_write_open_of_a_running_image_is_etxtbsy() {
    let i = reg(0o755);
    i.deny_write_access().expect("image now executing");
    assert!(matches!(open(&i, OpenFlags::O_WRONLY, MNT), Err(VfsError::Etxtbsy)),
        "opening a running executable for write must be ETXTBSY");
    assert!(matches!(open(&i, OpenFlags::O_RDWR, MNT), Err(VfsError::Etxtbsy)),
        "O_RDWR is a write-mode open too");
    // The refused open must not have disturbed the counter.
    assert_eq!(i.writecount(), -1);
    // A read-only open is unaffected, and takes no reference.
    let f = open(&i, OpenFlags::O_RDONLY, MNT).expect("reads are always allowed");
    assert_eq!(i.writecount(), -1);
    drop(f);
    assert_eq!(i.writecount(), -1, "a read-only close releases nothing");
    i.allow_write_access();
}

#[test]
fn two_write_opens_nest_and_each_close_releases_one() {
    let i = reg(0o755);
    let a = open(&i, OpenFlags::O_WRONLY, MNT).unwrap();
    let b = open(&i, OpenFlags::O_RDWR, MNT).unwrap();
    assert_eq!(i.writecount(), 2);
    drop(a);
    assert_eq!(i.writecount(), 1);
    // One writer remains: an exec is still refused. A stored boolean instead of
    // a counter would wrongly let this through.
    assert!(matches!(i.deny_write_access(), Err(VfsError::Etxtbsy)));
    drop(b);
    assert_eq!(i.writecount(), 0);
}

#[test]
fn a_dup_of_the_description_still_releases_exactly_one_reference() {
    let i = reg(0o755);
    let f = open(&i, OpenFlags::O_WRONLY, MNT).unwrap();
    let dup = vfs::file::get_file(&f);
    assert_eq!(i.writecount(), 1, "a dup shares the description, it does not re-open");
    drop(f);
    assert_eq!(i.writecount(), 1, "one reference remains: the description is still alive");
    drop(dup);
    assert_eq!(i.writecount(), 0);
}

#[test]
fn an_o_path_open_takes_no_reference() {
    // O_PATH is an fd reference with no read and no write capability, so it
    // must not pin the file as unexecutable.
    let i = reg(0o755);
    let f = open(&i, OpenFlags::O_PATH | OpenFlags::O_WRONLY, MNT).unwrap();
    assert_eq!(i.writecount(), 0);
    i.deny_write_access().expect("an O_PATH holder does not block exec");
    drop(f);
    assert_eq!(i.writecount(), -1);
    i.allow_write_access();
}

#[test]
fn special_file_types_are_exempt() {
    // A write-open of a device, FIFO or socket addresses the driver, not
    // filesystem data. Pinning those would make a running program unable to
    // execute any binary whose device node it happened to hold open.
    for ftype in [FileType::CharDev, FileType::BlockDev, FileType::Fifo, FileType::Socket] {
        let i = node(ftype);
        let f = open(&i, OpenFlags::O_WRONLY, MNT).expect("special-file write-open");
        assert_eq!(i.writecount(), 0, "no write reference on a special file");
        drop(f);
        assert_eq!(i.writecount(), 0, "and nothing released at close");
    }
}

#[test]
fn an_anonymous_file_takes_no_reference() {
    // Pipes, sockets, memfds and the rest are built directly rather than
    // through the open path and never take the reference; releasing one at
    // close would drive the counter negative and make unrelated files look
    // like running executables.
    let i = reg(0o644);
    let f = vfs::File::new(i.clone(), Dentry::new_root(i.clone()), OpenFlags::O_RDWR);
    assert_eq!(i.writecount(), 0);
    drop(f);
    assert_eq!(i.writecount(), 0, "an anonymous description must not release a reference it never took");
}

#[test]
fn a_failed_open_after_the_acquire_leaves_the_counter_balanced() {
    // `O_DIRECT` on a regular file whose backend has no direct-I/O path is
    // EINVAL, and that refusal happens AFTER the write reference is taken.
    // The reference must come back.
    let i = reg(0o644);
    assert!(matches!(open(&i, OpenFlags::O_WRONLY | OpenFlags::O_DIRECT, MNT), Err(VfsError::Einval)));
    assert_eq!(i.writecount(), 0, "a failed open leaks no write reference");
    i.deny_write_access().expect("still executable");
    i.allow_write_access();
}
