use super::*;

#[test]
fn a_rename_keeps_the_files_bytes() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "before.txt", stamp()).unwrap();
    v.write_file(&mut made, 0, b"contents survive", stamp()).unwrap();
    v.rename(&dir, "before.txt", &dir, "after.txt", 0, stamp()).unwrap();
    assert_eq!(names(&v), alloc::vec!["after.txt"]);
    let hit = v.find_entry(&v.root_chain(), "after.txt").unwrap();
    assert_eq!(v.read_whole(&hit).unwrap(), b"contents survive");
}

#[test]
fn a_rename_preserves_benign_secondary_entries() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let made = v.create_file(&dir, "before.txt", stamp()).unwrap();
    let root_chain = v.root_chain();
    let mut set_bytes = v.directory_bytes(&root_chain).unwrap();
    let mut extra = alloc::vec![0u8; crate::uapi::DENTRY_BYTES];
    extra[0] = crate::uapi::TYPE_VENDOR_EXT;
    set_bytes[made.set.offset as usize + crate::uapi::FILE_OFF_NUM_EXT] += 1;
    let extra_at = made.set.offset as usize + made.set.entries * crate::uapi::DENTRY_BYTES;
    set_bytes[extra_at..extra_at + extra.len()].copy_from_slice(&extra);
    crate::dirent::set::reseal(&mut set_bytes[made.set.offset as usize..extra_at + extra.len()]);
    v.write_at(&root_chain, 0, &set_bytes).unwrap();

    v.rename(&dir, "before.txt", &dir, "after.txt", 0, stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "after.txt").unwrap();
    assert_eq!(hit.set.entries, 4);
    let bytes = v.directory_bytes(&hit.dir).unwrap();
    let at = hit.set.offset as usize + 3 * crate::uapi::DENTRY_BYTES;
    assert_eq!(&bytes[at..at + crate::uapi::DENTRY_BYTES], &extra);
}

#[test]
fn a_rename_does_not_release_the_renamed_files_clusters() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "a", stamp()).unwrap();
    v.write_file(&mut made, 0, &[1u8; CLUSTER * 2], stamp()).unwrap();
    let used = v.used_clusters();
    v.rename(&dir, "a", &dir, "b", 0, stamp()).unwrap();
    assert_eq!(v.used_clusters(), used);
}

#[test]
fn a_rename_across_directories_moves_the_name() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let made = v.create_dir(&dir, "sub", stamp()).unwrap();
    let inner = DirHandle::child(&dir, made.set.offset);
    let mut file = v.create_file(&dir, "moving.txt", stamp()).unwrap();
    v.write_file(&mut file, 0, b"moved", stamp()).unwrap();
    v.rename(&dir, "moving.txt", &inner, "moved.txt", 0, stamp()).unwrap();
    assert_eq!(names(&v), alloc::vec!["sub"]);
    assert_eq!(v.read_whole(&v.lookup("/sub/moved.txt").unwrap()).unwrap(), b"moved");
}

#[test]
fn a_rename_over_an_existing_name_replaces_it_and_frees_it() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut a = v.create_file(&dir, "a", stamp()).unwrap();
    v.write_file(&mut a, 0, b"keep", stamp()).unwrap();
    let mut b = v.create_file(&dir, "b", stamp()).unwrap();
    v.write_file(&mut b, 0, &[0u8; CLUSTER * 2], stamp()).unwrap();
    let used = v.used_clusters();
    v.rename(&dir, "a", &dir, "b", 0, stamp()).unwrap();
    // b's two clusters go; a's one stays.
    assert_eq!(v.used_clusters(), used - 2);
    assert_eq!(names(&v), alloc::vec!["b"]);
    assert_eq!(v.read_whole(&v.find_entry(&v.root_chain(), "b").unwrap()).unwrap(), b"keep");
}

#[test]
fn noreplace_refuses_rather_than_replacing() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "a", stamp()).unwrap();
    v.create_file(&dir, "b", stamp()).unwrap();
    assert_eq!(v.rename(&dir, "a", &dir, "b", RENAME_NOREPLACE, stamp()).unwrap_err(),
               Errno::Eexist);
    assert_eq!(names(&v).len(), 2);
}

#[test]
fn an_exchange_swaps_two_names_and_keeps_both_files() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut a = v.create_file(&dir, "a", stamp()).unwrap();
    v.write_file(&mut a, 0, b"AAAA", stamp()).unwrap();
    let mut b = v.create_file(&dir, "b", stamp()).unwrap();
    v.write_file(&mut b, 0, b"BB", stamp()).unwrap();
    v.rename(&dir, "a", &dir, "b", RENAME_EXCHANGE, stamp()).unwrap();
    let mut got = names(&v);
    got.sort();
    assert_eq!(got, alloc::vec!["a", "b"]);
    assert_eq!(v.read_whole(&v.find_entry(&v.root_chain(), "a").unwrap()).unwrap(), b"BB");
    assert_eq!(v.read_whole(&v.find_entry(&v.root_chain(), "b").unwrap()).unwrap(), b"AAAA");
}

#[test]
fn an_exchange_with_a_name_that_is_not_there_is_refused() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "a", stamp()).unwrap();
    assert_eq!(v.rename(&dir, "a", &dir, "b", RENAME_EXCHANGE, stamp()).unwrap_err(),
               Errno::Enoent);
}

#[test]
fn renaming_a_name_onto_itself_does_not_remove_it() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "same", stamp()).unwrap();
    v.rename(&dir, "same", &dir, "same", 0, stamp()).unwrap();
    assert_eq!(names(&v), alloc::vec!["same"]);
}

#[test]
fn a_rename_may_not_replace_a_directory_with_a_file() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "f", stamp()).unwrap();
    v.create_dir(&dir, "d", stamp()).unwrap();
    assert_eq!(v.rename(&dir, "f", &dir, "d", 0, stamp()).unwrap_err(), Errno::Eisdir);
    assert_eq!(v.rename(&dir, "d", &dir, "f", 0, stamp()).unwrap_err(), Errno::Enotdir);
}

#[test]
fn a_rename_may_not_replace_a_populated_directory() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_dir(&dir, "empty", stamp()).unwrap();
    let full = v.create_dir(&dir, "full", stamp()).unwrap();
    let inner = DirHandle::child(&dir, full.set.offset);
    v.create_file(&inner, "child", stamp()).unwrap();
    assert_eq!(v.rename(&dir, "empty", &dir, "full", 0, stamp()).unwrap_err(), Errno::Enotempty);
}

#[test]
fn a_directory_grows_when_its_cluster_is_full_of_names() {
    // 128 entries per 4 KiB cluster; the root already holds three, and each
    // short name takes three, so forty names cannot fit in one.
    let mut v = test_image::empty();
    let dir = root(&v);
    for i in 0..60 {
        let name = alloc::format!("file{i:03}");
        v.create_file(&dir, &name, stamp()).unwrap();
    }
    assert_eq!(names(&v).len(), 60);
    assert!(v.root_chain().size > 1, "the root should have grown");
    for i in 0..60 {
        let name = alloc::format!("file{i:03}");
        assert!(v.find_entry(&v.root_chain(), &name).is_ok(), "{name} went missing");
    }
}

