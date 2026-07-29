//! Linux `i_writecount` (`include/linux/fs.h:2798-2830`): one signed counter,
//! `>0` writers and `<0` execs, each refusing the other. That mutual exclusion
//! is what `ETXTBSY` is — a running binary cannot be opened for write, and a
//! file open for write cannot be executed.

extern crate alloc;

fn reg() -> vfs::InodeRef {
    vfs::InodeBuilder::new(4242, vfs::mk_mode(vfs::FileType::Regular, 0o755),
        vfs::default_inode_ops(), vfs::default_file_ops()).build()
}

#[test]
fn a_fresh_inode_has_no_writers_and_no_execs() {
    assert_eq!(reg().writecount(), 0);
}

#[test]
fn writers_and_execs_refuse_each_other() {
    let i = reg();
    // A writer is in: an exec must now fail ETXTBSY, as Linux's
    // `atomic_dec_unless_positive` does.
    i.get_write_access().expect("first writer");
    assert_eq!(i.writecount(), 1);
    assert!(matches!(i.deny_write_access(), Err(vfs::VfsError::Etxtbsy)),
        "exec of a file open for write must be ETXTBSY");

    // Drop the writer; the exec can proceed.
    i.put_write_access();
    assert_eq!(i.writecount(), 0);
    i.deny_write_access().expect("exec after last writer left");
    assert_eq!(i.writecount(), -1);

    // Now the reverse: opening for write must fail while it executes.
    assert!(matches!(i.get_write_access(), Err(vfs::VfsError::Etxtbsy)),
        "open-for-write of a running binary must be ETXTBSY");

    i.allow_write_access();
    assert_eq!(i.writecount(), 0);
    i.get_write_access().expect("writable again once the image exits");
}

#[test]
fn multiple_writers_and_multiple_execs_nest() {
    let i = reg();
    i.get_write_access().unwrap();
    i.get_write_access().unwrap();
    assert_eq!(i.writecount(), 2, "writers nest");
    i.put_write_access();
    // ONE writer still holds it — an exec must still be refused. A naive
    // implementation that flipped a boolean would let this through.
    assert!(matches!(i.deny_write_access(), Err(vfs::VfsError::Etxtbsy)));
    i.put_write_access();

    i.deny_write_access().unwrap();
    i.deny_write_access().unwrap();
    assert_eq!(i.writecount(), -2, "two tasks executing the same image");
    i.allow_write_access();
    assert!(matches!(i.get_write_access(), Err(vfs::VfsError::Etxtbsy)),
        "still executing in one task");
    i.allow_write_access();
    i.get_write_access().expect("last exec left");
}
