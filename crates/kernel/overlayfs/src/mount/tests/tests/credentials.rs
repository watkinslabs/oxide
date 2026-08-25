use super::*;

#[test]
fn chmod_forwards_the_acl_rewrite_to_the_copied_up_inode() {
    let (l, up, lo) = image();
    let lower = mkfile(&lo, "acl", b"image");
    let entry = |tag, perm, id| AclEntry { tag, perm, id };
    lower.setxattr("system.posix_acl_access", to_xattr(&[
        entry(ACL_USER_OBJ, 0o6, ACL_UNDEFINED_ID),
        entry(ACL_USER, 0o6, 1000),
        entry(ACL_GROUP_OBJ, 0o4, ACL_UNDEFINED_ID),
        entry(ACL_MASK, 0o6, ACL_UNDEFINED_ID),
        entry(ACL_OTHER, 0o4, ACL_UNDEFINED_ID),
    ]), false, false).expect("set lower acl");
    let user = Cred { uid: 1000, gid: 9, cap_dac_override: false, cap_dac_read_search: false,
                      cap_fowner: false, cap_chown: false, cap_fsetid: false,
                      groups: GroupList::empty() };
    assert_eq!(lower.permission(MAY_READ | MAY_WRITE, &user), Ok(()));

    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let over = fs.root_inode().lookup("acl").unwrap();
    over.setattr(&vfs::IDENTITY,
                 &Iattr { valid: ATTR_MODE, mode: 0o600, ..Iattr::default() })
        .expect("overlay chmod");

    assert_eq!(over.permission(MAY_READ, &user), Err(VfsError::Eacces));
    let upper = find_path(&up, "acl").expect("copied-up inode");
    assert_eq!(upper.permission(MAY_READ, &user), Err(VfsError::Eacces));
    let upper_acl = upper.getxattr("system.posix_acl_access").expect("upper keeps ACL");
    let upper_acl = vfs::posix_acl::from_xattr(&upper_acl).expect("decode upper ACL");
    assert_eq!(upper_acl.iter().find(|e| e.tag == ACL_MASK).unwrap().perm, 0,
               "the forwarded chmod must rewrite the copied-up ACL");
    assert_eq!(lower.permission(MAY_READ | MAY_WRITE, &user), Ok(()),
               "copy-up must not mutate the image layer's ACL");
}

#[test]
fn override_creds_uses_the_mount_owner_for_the_real_layer_check() {
    let (l, _up, lo) = image();
    let lower = mkfile(&lo, "private", b"image");
    lower.set_perm(0).unwrap();
    let mounter = Cred { uid: 1000, gid: 1000, cap_dac_override: false,
        cap_dac_read_search: false, cap_fowner: false, cap_chown: false,
        cap_fsetid: false, groups: GroupList::empty() };
    let caller = Cred { uid: 2000, gid: 2000, cap_dac_override: false,
        cap_dac_read_search: true, cap_fowner: false, cap_chown: false,
        cap_fsetid: false, groups: GroupList::empty() };
    let fs = OverlayFs::open_with_cred(OPTS, &l.resolve(), true, &mounter).unwrap();
    let f = fs.root_inode().lookup("private").unwrap();
    assert_eq!(f.permission(MAY_READ, &caller), Err(VfsError::Eacces));
}

#[test]
fn nooverride_creds_uses_the_requesting_task_for_the_real_layer_check() {
    let (l, _up, lo) = image();
    let lower = mkfile(&lo, "private", b"image");
    lower.set_perm(0).unwrap();
    let mounter = Cred { uid: 1000, gid: 1000, cap_dac_override: false,
        cap_dac_read_search: false, cap_fowner: false, cap_chown: false,
        cap_fsetid: false, groups: GroupList::empty() };
    let caller = Cred { uid: 2000, gid: 2000, cap_dac_override: false,
        cap_dac_read_search: true, cap_fowner: false, cap_chown: false,
        cap_fsetid: false, groups: GroupList::empty() };
    let fs = OverlayFs::open_with_cred(
        "lowerdir=/lower,upperdir=/upper,workdir=/work,nooverride_creds",
        &l.resolve(), true, &mounter).unwrap();
    let f = fs.root_inode().lookup("private").unwrap();
    assert_eq!(f.permission(MAY_READ, &caller), Ok(()));
}

#[test]
fn a_read_only_overlay_of_two_image_layers_merges_them() {
    let up = layer(0);
    let l1 = layer(1);
    let l2 = layer(2);
    mkfile(&l1, "a", b"one");
    mkfile(&l2, "b", b"two");
    let mut m = BTreeMap::new();
    m.insert("/l1".to_string(), l1);
    m.insert("/l2".to_string(), l2);
    let l = Layers(m);
    let fs = OverlayFs::open("lowerdir=/l1:/l2", &l.resolve(), true).unwrap();
    assert!(!fs.writable());
    assert_eq!(names(&fs.root_inode()), vec!["a", "b"]);
    let _ = up;
}
