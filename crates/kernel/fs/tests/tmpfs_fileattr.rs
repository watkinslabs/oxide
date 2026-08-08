//! tmpfs's `fileattr_get`/`fileattr_set` inode ops. Reached by
//! `file_getattr(2)`/`file_setattr(2)` (468/469) and by
//! `FS_IOC_{GET,SET}FLAGS` (slot 16).
//!
//! Before F761 tmpfs implemented neither op, so `InodeOps`'s default `ENOTTY`
//! made every `/tmp`, `/run` and `/dev/shm` inode answer `EOPNOTSUPP` where
//! the correct answer is `0` — `chattr +i /tmp/x` could not work at all.

use fs::tmpfs::tmpfs_anon_file;
use vfs::inode::{FS_APPEND_FL, FS_CASEFOLD_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL, FS_NODUMP_FL,
                 FS_SYNC_FL, FS_XFLAG_APPEND, FS_XFLAG_IMMUTABLE, S_APPEND, S_IMMUTABLE, S_NODUMP};
use vfs::{FileAttr, VfsError};

fn set(i: &vfs::InodeRef, flags: u32) -> Result<(), VfsError> {
    i.fileattr_set(&FileAttr { flags, ..Default::default() })
}

#[test]
fn a_fresh_tmpfs_inode_reports_a_clear_chattr_word() {
    let i = tmpfs_anon_file();
    let fa = i.fileattr_get().expect("tmpfs implements fileattr_get");
    assert_eq!(fa.flags, 0);
    assert_eq!(fa.fsx_xflags, 0);
    assert_eq!(fa.fsx_projid, 0);
}

#[test]
fn immutable_and_append_round_trip_through_i_flags() {
    // `shmem_set_inode_flags`: FS_IMMUTABLE_FL → S_IMMUTABLE, FS_APPEND_FL → S_APPEND.
    let i = tmpfs_anon_file();
    set(&i, FS_IMMUTABLE_FL | FS_APPEND_FL).expect("both are SHMEM_FL_USER_MODIFIABLE");
    assert_ne!(i.i_flags() & S_IMMUTABLE, 0, "the VFS enforcement bit must be set too");
    assert_ne!(i.i_flags() & S_APPEND, 0);
    let fa = i.fileattr_get().unwrap();
    assert_eq!(fa.flags, FS_IMMUTABLE_FL | FS_APPEND_FL);
    // `fileattr_fill_flags` publishes the translated xflags view in the same call.
    assert_eq!(fa.fsx_xflags, FS_XFLAG_IMMUTABLE | FS_XFLAG_APPEND);
}

#[test]
fn clearing_a_flag_clears_the_matching_i_flags_bit() {
    let i = tmpfs_anon_file();
    set(&i, FS_IMMUTABLE_FL | FS_NOATIME_FL).unwrap();
    set(&i, FS_NOATIME_FL).unwrap();
    assert_eq!(i.i_flags() & S_IMMUTABLE, 0);
    assert_eq!(i.fileattr_get().unwrap().flags, FS_NOATIME_FL);
}

#[test]
fn nodump_round_trips_even_though_linux_i_flags_has_no_bit_for_it() {
    // `shmem_set_inode_flags`: "FS_NODUMP_FL does not require any action in
    // i_flags" — Linux keeps it in `shmem_inode_info.fsflags`, oxide in the
    // internal `S_NODUMP` bit. Either way `lsattr` must see it come back.
    let i = tmpfs_anon_file();
    set(&i, FS_NODUMP_FL).unwrap();
    assert_ne!(i.i_flags() & S_NODUMP, 0);
    assert_eq!(i.fileattr_get().unwrap().flags, FS_NODUMP_FL);
}

#[test]
fn a_flag_outside_shmem_fl_user_modifiable_is_eopnotsupp() {
    // `if (fa->flags & ~SHMEM_FL_USER_MODIFIABLE) return -EOPNOTSUPP;`
    let i = tmpfs_anon_file();
    assert_eq!(set(&i, FS_SYNC_FL), Err(VfsError::Eopnotsupp));
    assert_eq!(set(&i, 0x0000_0001 /* FS_SECRM_FL */), Err(VfsError::Eopnotsupp));
    assert_eq!(i.fileattr_get().unwrap().flags, 0, "a rejected set changes nothing");
}

#[test]
fn casefold_needs_an_encoding_superblock() {
    // `shmem_inode_casefold_flags`: `if (!sb->s_encoding) return -EOPNOTSUPP;`
    let i = tmpfs_anon_file();
    assert_eq!(set(&i, FS_CASEFOLD_FL), Err(VfsError::Eopnotsupp));
}

#[test]
fn fsxattr_only_state_is_eopnotsupp() {
    // `if (fileattr_has_fsx(fa)) return -EOPNOTSUPP;` — tmpfs has no project
    // ids, extent-size hints or non-common xflags. This is the arm
    // `file_setattr(2)` hits when userspace asks for a project id on /tmp.
    let i = tmpfs_anon_file();
    assert_eq!(i.fileattr_set(&FileAttr { fsx_projid: 7, ..Default::default() }),
               Err(VfsError::Eopnotsupp));
    assert_eq!(i.fileattr_set(&FileAttr { fsx_extsize: 4096, ..Default::default() }),
               Err(VfsError::Eopnotsupp));
    assert_eq!(i.fileattr_set(&FileAttr { fsx_cowextsize: 1, ..Default::default() }),
               Err(VfsError::Eopnotsupp));
    assert_eq!(i.fileattr_set(&FileAttr { fsx_xflags: 0x0000_0800 /* EXTSIZE */, ..Default::default() }),
               Err(VfsError::Eopnotsupp));
    // A COMMON xflag alone is NOT fsx-only state.
    assert_eq!(i.fileattr_set(&FileAttr { flags: FS_APPEND_FL, fsx_xflags: FS_XFLAG_APPEND,
                                          ..Default::default() }), Ok(()));
}

#[test]
fn the_full_vfs_fileattr_set_ladder_reaches_the_tmpfs_backend() {
    // What `file_setattr(2)` actually calls: `vfs_fileattr_set` with the
    // `fsxattr` source, root creds, CAP_LINUX_IMMUTABLE, init user ns.
    let i = tmpfs_anon_file();
    let idmap = vfs::idmap::Idmap::identity();
    let want = vfs::fileattr_fill_xflags(FS_XFLAG_IMMUTABLE);
    vfs::fileattr_set(&idmap, &i, want, vfs::FileAttrSource::Fsxattr, &vfs::Cred::root(), true, true)
        .expect("vfs_fileattr_set reaches shmem_fileattr_set");
    assert_ne!(i.i_flags() & S_IMMUTABLE, 0);
    assert_eq!(vfs::fileattr_get(&i).unwrap().flags, FS_IMMUTABLE_FL);
}

#[test]
fn setting_immutable_without_cap_linux_immutable_is_eperm() {
    // `fileattr_set_prepare`: `(fa->flags ^ old_ma->flags) & (FS_APPEND_FL |
    // FS_IMMUTABLE_FL) && !capable(CAP_LINUX_IMMUTABLE)` → EPERM.
    let i = tmpfs_anon_file();
    let idmap = vfs::idmap::Idmap::identity();
    let want = vfs::fileattr_fill_xflags(FS_XFLAG_IMMUTABLE);
    assert_eq!(vfs::fileattr_set(&idmap, &i, want, vfs::FileAttrSource::Fsxattr,
                                 &vfs::Cred::root(), false, true),
               Err(VfsError::Eperm));
}
