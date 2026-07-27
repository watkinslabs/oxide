use vfs::idmap::Idmap;
use vfs::inode::{
    FS_APPEND_FL, FS_CASEFOLD_FL, FS_COMPR_FL, FS_IMMUTABLE_FL, FS_XFLAG_APPEND,
    FS_XFLAG_EXTSIZE, FS_XFLAG_PROJINHERIT, FS_XFLAG_RTINHERIT, S_CASEFOLD,
};
use vfs::{
    Cred, FileAttr, FileAttrSource, FileType, InodeBuilder, VfsError,
    default_file_ops, default_inode_ops, fileattr_prepare_set, mk_mode,
};

fn cred(uid: u32, fowner: bool) -> Cred {
    Cred {
        uid, gid: uid,
        cap_dac_override: false,
        cap_dac_read_search: false,
        cap_fowner: fowner,
        cap_chown: false,
        cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}

fn inode(uid: u32, ft: FileType) -> vfs::InodeRef {
    InodeBuilder::new(0xFA00 + uid as u64, mk_mode(ft, 0o644), default_inode_ops(), default_file_ops())
        .owner(uid, uid).build()
}

#[test]
fn fileattr_admission_uses_mount_idmap_owner_not_raw_inode_uid() {
    let map = Idmap::uniform(1000, 100_000, 10);
    let node = inode(1000, FileType::Regular);
    let old = FileAttr::default();
    assert_eq!(
        fileattr_prepare_set(&map, &node, old, old, FileAttrSource::Fsxattr, &cred(1000, false), false, true),
        Err(VfsError::Eperm),
        "raw fs uid is not owner through an idmapped mount");
    assert!(fileattr_prepare_set(&map, &node, old, old, FileAttrSource::Fsxattr,
        &cred(100_000, false), false, true).is_ok());
}

#[test]
fn fileattr_admission_denies_cap_fowner_when_owner_unmapped() {
    let map = Idmap::uniform(1000, 100_000, 10);
    let node = inode(5000, FileType::Regular);
    assert_eq!(
        fileattr_prepare_set(&map, &node, FileAttr::default(), FileAttr::default(),
            FileAttrSource::Fsxattr, &cred(0, true), false, true),
        Err(VfsError::Eperm),
        "CAP_FOWNER cannot bypass an unmapped owner");
}

#[test]
fn setflags_preserves_old_fsxattr_only_fields() {
    let node = inode(0, FileType::Regular);
    let old = FileAttr {
        flags: FS_COMPR_FL,
        fsx_xflags: FS_XFLAG_RTINHERIT,
        fsx_extsize: 64,
        fsx_nextents: 7,
        fsx_projid: 99,
        fsx_cowextsize: 128,
    };
    let want = FileAttr { flags: FS_APPEND_FL, fsx_xflags: FS_XFLAG_APPEND, ..Default::default() };
    let got = fileattr_prepare_set(&Idmap::identity(), &node, old, want, FileAttrSource::Flags,
        &cred(0, false), true, true).expect("prepare");
    assert_eq!(got.flags, FS_APPEND_FL);
    assert_eq!(got.fsx_xflags, FS_XFLAG_APPEND | FS_XFLAG_RTINHERIT);
    assert_eq!(got.fsx_extsize, 64);
    assert_eq!(got.fsx_nextents, 7);
    assert_eq!(got.fsx_projid, 99);
    assert_eq!(got.fsx_cowextsize, 128);
}

#[test]
fn fsxattr_preserves_old_non_common_flags_and_restricts_non_init_project_state() {
    let node = inode(0, FileType::Regular);
    let old = FileAttr { flags: FS_COMPR_FL, fsx_projid: 7, fsx_xflags: FS_XFLAG_EXTSIZE, fsx_extsize: 64, ..Default::default() };
    let want = FileAttr { fsx_projid: 9, fsx_xflags: FS_XFLAG_PROJINHERIT, ..Default::default() };
    assert_eq!(
        fileattr_prepare_set(&Idmap::identity(), &node, old, want, FileAttrSource::Fsxattr,
            &cred(0, false), false, false),
        Err(VfsError::Einval));

    let want = FileAttr { fsx_projid: 7, fsx_xflags: FS_XFLAG_EXTSIZE, fsx_extsize: 64, ..Default::default() };
    let got = fileattr_prepare_set(&Idmap::identity(), &node, old, want, FileAttrSource::Fsxattr,
        &cred(0, false), false, false).expect("unchanged project state allowed");
    assert_eq!(got.flags & FS_COMPR_FL, FS_COMPR_FL);
}

#[test]
fn immutable_append_toggle_requires_linux_immutable_capability() {
    let node = inode(0, FileType::Regular);
    let old = FileAttr::default();
    let want = FileAttr { flags: FS_IMMUTABLE_FL, ..Default::default() };
    assert_eq!(
        fileattr_prepare_set(&Idmap::identity(), &node, old, want, FileAttrSource::Flags,
            &cred(0, false), false, true),
        Err(VfsError::Eperm));
    assert!(fileattr_prepare_set(&Idmap::identity(), &node, old, want, FileAttrSource::Flags,
        &cred(0, false), true, true).is_ok());
}

#[test]
fn fileattr_from_i_flags_reports_casefold() {
    assert_eq!(FileAttr::from_i_flags(S_CASEFOLD).flags & FS_CASEFOLD_FL, FS_CASEFOLD_FL);
}
