// Identity of a cgroup2 inode comes from the backend state cgroupfs installs
// (`CgDirData` in `i_private`), never from arithmetic on `st_ino`. These pin
// that a foreign inode carrying the SAME number and the SAME cgroup2 fsid is
// rejected, and that every number cgroupfs mints stays inside its declared
// pseudo-inode region.


use vfs::pseudo_ino::{CGROUP_DIR, CGROUP_FILE};
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
fn minted_numbers_stay_inside_the_declared_regions() {
    for cgid in [crate::tree::ROOT, 1, 2, 0xFF, 0x1_0000, u64::MAX] {
        let ino = crate::ids::dir_ino(cgid);
        assert!(CGROUP_DIR.contains(ino), "dir ino {ino:#x} inside CGROUP_DIR");
    }
    // The `(cgid << 8) | slot` encoding used to be added to a bare base, so a
    // large cgroup id minted straight past the region's end.
    for cgid in [0u64, 1, 0xFFFF, 0x00FF_FFFF, u64::MAX] {
        for slot in [0u8, 1, 0x7F, u8::MAX] {
            let ino = crate::ids::file_ino(cgid, slot);
            assert!(CGROUP_FILE.contains(ino), "file ino {ino:#x} inside CGROUP_FILE");
        }
    }
}

#[test]
fn dir_and_file_regions_do_not_overlap_devpts() {
    assert!(!vfs::pseudo_ino::overlaps(&CGROUP_DIR, &vfs::pseudo_ino::DEVPTS),
        "cgroup dirs and devpts pty endpoints no longer share a base");
}
