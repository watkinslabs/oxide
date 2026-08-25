use super::*;

#[test]
fn a_created_file_is_found_by_the_name_it_was_given() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "new.txt", now()).unwrap();
    assert_eq!(made.name, "new.txt");
    assert_eq!(names(&v), alloc::vec!["new.txt"]);
    let hit = v.find_entry(MFT_REC_ROOT, "new.txt").unwrap();
    assert_eq!(hit.reference, made.reference);
}

#[test]
fn a_created_files_record_says_what_it_is() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "f", now()).unwrap();
    let info = v.stat(made.reference.number).unwrap();
    assert!(!info.is_dir);
    assert_eq!(info.size, 0);
    assert_eq!(info.hard_links, 1);
    assert_eq!(info.create_time, now());
    let dir = v.create_dir(MFT_REC_ROOT, "d", now()).unwrap();
    assert!(v.stat(dir.reference.number).unwrap().is_dir);
}

#[test]
fn wsl_permissions_and_posix_acl_survive_the_native_ea_rewrite() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "acl", now()).unwrap();
    let number = made.reference.number;
    v.write_ea(number, b"$LXUID", Some(&1000u32.to_le_bytes()), now()).unwrap();
    v.write_ea(number, b"$LXGID", Some(&1001u32.to_le_bytes()), now()).unwrap();
    v.write_ea(number, b"$LXMOD", Some(&0o100640u32.to_le_bytes()), now()).unwrap();
    let acl = vfs::posix_acl::to_xattr(&[
        vfs::posix_acl::AclEntry { tag: vfs::posix_acl::ACL_USER_OBJ, perm: 7, id: 0 },
        vfs::posix_acl::AclEntry { tag: vfs::posix_acl::ACL_GROUP_OBJ, perm: 6, id: 0 },
        vfs::posix_acl::AclEntry { tag: vfs::posix_acl::ACL_MASK, perm: 6, id: 0 },
        vfs::posix_acl::AclEntry { tag: vfs::posix_acl::ACL_OTHER, perm: 0, id: 0 },
    ]);
    let disk = vfs::posix_acl::disk::disk_from_xattr(&acl).unwrap();
    v.write_ea(number, b"system.posix_acl_access", Some(&disk), now()).unwrap();

    let info = v.stat(number).unwrap();
    assert_eq!(info.posix_owner, Some((1000, 1001)));
    assert_eq!(info.posix_mode, Some(0o100640));
    assert_eq!(v.read_ea(number, b"system.posix_acl_access").unwrap(), disk);
}

#[test]
fn a_large_native_ea_uses_nonresident_storage_and_releases_it() {
    let mut v = test_image::empty();
    let made = v.create_file(MFT_REC_ROOT, "large-ea", now()).unwrap();
    let number = made.reference.number;
    let value = alloc::vec![0x5a; 2_000];
    let before = v.free_clusters();
    v.write_ea(number, b"user.large", Some(&value), now()).unwrap();
    let (_, attrs) = v.read_record(number).unwrap();
    let ea = crate::attrib::find(&attrs, ATTR_EA, &[]).unwrap();
    assert!(ea.non_resident);
    assert_eq!(v.read_ea(number, b"user.large").unwrap(), value);
    let allocated = v.free_clusters();
    assert!(allocated < before);
    let replacement = alloc::vec![0xa5; 2_000];
    v.write_ea(number, b"user.large", Some(&replacement), now()).unwrap();
    assert_eq!(v.read_ea(number, b"user.large").unwrap(), replacement);
    assert_eq!(v.free_clusters(), allocated);
    v.write_ea(number, b"user.large", None, now()).unwrap();
    assert_eq!(v.read_ea(number, b"user.large"), Err(Errno::Enodata));
    assert_eq!(v.free_clusters(), before);
    let (_, attrs) = v.read_record(number).unwrap();
    assert!(crate::attrib::find(&attrs, ATTR_EA, &[]).is_none());
}

#[test]
fn creating_a_name_that_exists_is_refused() {
    let mut v = test_image::empty();
    v.create_file(MFT_REC_ROOT, "dup", now()).unwrap();
    assert_eq!(v.create_file(MFT_REC_ROOT, "dup", now()).unwrap_err(), Errno::Eexist);
    // Case-insensitively, through the volume's own table.
    assert_eq!(v.create_file(MFT_REC_ROOT, "DUP", now()).unwrap_err(), Errno::Eexist);
}

#[test]
fn names_are_created_in_key_order_whatever_order_they_arrive_in() {
    // An appended entry produces a node a descent cannot search.
    let mut v = test_image::empty();
    for name in ["zulu", "alpha", "mike", "bravo"] {
        v.create_file(MFT_REC_ROOT, name, now()).unwrap();
    }
    assert_eq!(names(&v), alloc::vec!["alpha", "bravo", "mike", "zulu"]);
    for name in ["zulu", "alpha", "mike", "bravo"] {
        assert!(v.find_entry(MFT_REC_ROOT, name).is_ok(), "{name} became unfindable");
    }
}
