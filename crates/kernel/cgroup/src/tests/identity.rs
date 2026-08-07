// Identity of a cgroup2 inode comes from the backend state cgroupfs installs
// (`CgDirData` in `i_private`), never from arithmetic on `st_ino`. These pin
// that a foreign inode carrying the SAME number and the SAME cgroup2 fsid is
// rejected, and that directory and control-file identities are separately
// owned by the live hierarchy nodes.


use vfs::{default_inode_ops, mk_mode, FileType, InodeBuilder};

/// Build an inode that copies a cgroup directory's NUMBER and fsid but carries
/// no cgroupfs backend state — the shape a `st_ino`-arithmetic resolver
/// accepted.
fn foreign_lookalike(ino: u64) -> vfs::InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), default_inode_ops(),
                      vfs::default_file_ops())
        .fsid(crate::CGROUP2_SUPER_MAGIC)
        .build()
}

#[test]
fn cg_dir_inode_yields_its_cgid_from_backend_state() {
    let root = crate::inode::make_cg_dir(crate::tree::ROOT);
    assert_eq!(crate::cgid_from_dir_inode(&root), Some(crate::tree::ROOT),
        "a real cgroup dir inode resolves to its own cgid");
}

#[test]
fn foreign_inode_with_same_number_and_fsid_is_not_a_cgroup_dir() {
    let real = crate::inode::make_cg_dir(crate::tree::ROOT);
    let fake = foreign_lookalike(real.ino());
    assert_eq!(fake.ino(), real.ino(), "the lookalike copies the number exactly");
    assert_eq!(fake.fsid(), real.fsid(), "and the cgroup2 fsid the old guard checked");
    assert_eq!(crate::cgid_from_dir_inode(&fake), None,
        "identity is the backend state, not the (ino, fsid) pair");
}

#[test]
fn cgroup_file_inode_is_not_a_cgroup_dir() {
    let f = crate::inode::make_cg_file(crate::tree::ROOT, "cgroup.procs");
    assert_eq!(crate::cgid_from_dir_inode(&f), None,
        "a control file carries CgFileData, so it never resolves as a directory");
}

#[test]
fn hierarchy_node_numbers_do_not_depend_on_cgroup_id() {
    let _ = crate::realize_tree();
    let root = crate::inode::make_cg_dir(crate::tree::ROOT);
    let file = crate::inode::make_cg_file(crate::tree::ROOT, "cgroup.procs");
    assert_ne!(root.ino(), file.ino(), "directory and control file have separate nodes");
}
