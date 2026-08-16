//! Finding a name, and listing a directory.

use super::*;
use crate::test_image::nodes::dir::{ent, Ent};
use alloc::vec::Vec;

/// Names present in every fixture directory.
fn some_names() -> Vec<Ent> {
    alloc::vec![
        ent("alpha", 10, FT_REG_FILE),
        ent("beta", 11, FT_DIR),
        ent("a-rather-long-name.txt", 12, FT_REG_FILE),
        ent("g", 13, FT_SYMLINK),
    ]
}

#[test]
fn an_inline_directory_lists_its_stored_dots_and_entries() {
    let mut b = Builder::new();
    nodes::add_inline_dir(&mut b, ROOT_INO, &some_names());
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    let list = v.read_dir(&root, ROOT_INO).unwrap();
    let names: Vec<&[u8]> = list.iter().map(|e| e.name.as_slice()).collect();
    assert_eq!(names[0], b".");
    assert_eq!(names[1], b"..");
    assert!(names.contains(&b"alpha".as_slice()));
    assert!(names.contains(&b"a-rather-long-name.txt".as_slice()));
    assert_eq!(list.len(), 6);
}

#[test]
fn an_inline_directory_finds_each_of_its_names() {
    let mut b = Builder::new();
    nodes::add_inline_dir(&mut b, ROOT_INO, &some_names());
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    for e in some_names() {
        let hit = v.lookup(&root, ROOT_INO, &e.name).unwrap();
        assert_eq!(hit.ino, e.ino, "name {:?}", core::str::from_utf8(&e.name));
        assert_eq!(hit.file_type, e.file_type);
    }
}

#[test]
fn an_inline_directory_finds_its_own_dots() {
    let mut b = Builder::new();
    nodes::add_inline_dir(&mut b, ROOT_INO, &[]);
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b".").unwrap().ino, ROOT_INO);
    assert_eq!(v.lookup(&root, ROOT_INO, b"..").unwrap().ino, ROOT_INO);
}

#[test]
fn an_absent_name_is_reported_as_absent() {
    let mut b = Builder::new();
    nodes::add_inline_dir(&mut b, ROOT_INO, &some_names());
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b"missing").err(), Some(Errno::Enoent));
}

#[test]
fn an_empty_name_is_refused() {
    let v = test_image::with_root().mount().unwrap();
    let root = v.root().unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b"").err(), Some(Errno::Enametoolong));
}

#[test]
fn a_name_longer_than_the_format_allows_is_refused() {
    let v = test_image::with_root().mount().unwrap();
    let root = v.root().unwrap();
    let long = alloc::vec![b'x'; NAME_LEN + 1];
    assert_eq!(v.lookup(&root, ROOT_INO, &long).err(), Some(Errno::Enametoolong));
}

#[test]
fn a_directory_of_only_dots_is_empty() {
    let mut b = Builder::new();
    nodes::add_inline_dir(&mut b, ROOT_INO, &[]);
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert!(v.dir_is_empty(&root, ROOT_INO).unwrap());
}

#[test]
fn a_directory_with_one_name_is_not_empty() {
    let mut b = Builder::new();
    nodes::add_inline_dir(&mut b, ROOT_INO, &[ent("x", 9, FT_REG_FILE)]);
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert!(!v.dir_is_empty(&root, ROOT_INO).unwrap());
}

#[test]
fn a_blocked_directory_finds_each_of_its_names() {
    // Placed by hash into level-zero buckets; a reader computing a different
    // hash or a different bucket finds nothing.
    let mut b = Builder::new();
    nodes::add_block_dir(&mut b, ROOT_INO, 0, 1, &some_names());
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert!(!root.inline_dentry());
    for e in some_names() {
        let hit = v.lookup(&root, ROOT_INO, &e.name).unwrap();
        assert_eq!(hit.ino, e.ino, "name {:?}", core::str::from_utf8(&e.name));
    }
}

#[test]
fn a_blocked_directory_lists_every_name() {
    let mut b = Builder::new();
    nodes::add_block_dir(&mut b, ROOT_INO, 0, 1, &some_names());
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    let list = v.read_dir(&root, ROOT_INO).unwrap();
    assert_eq!(list.len(), 6);
    let names: Vec<Vec<u8>> = list.iter().map(|e| e.name.clone()).collect();
    for e in some_names() { assert!(names.contains(&e.name)); }
}

#[test]
fn a_directory_with_its_own_base_level_still_finds_its_names() {
    // The base level shifts every bucket; ignoring it looks in the wrong one.
    let mut b = Builder::new();
    nodes::add_block_dir(&mut b, ROOT_INO, 2, 1, &some_names());
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert_eq!(root.dir_level, 2);
    for e in some_names() {
        assert_eq!(v.lookup(&root, ROOT_INO, &e.name).unwrap().ino, e.ino);
    }
}

#[test]
fn a_directory_whose_depth_is_zero_finds_nothing() {
    // A lookup examines levels up to the recorded depth; zero means none.
    let mut b = Builder::new();
    nodes::add_block_dir(&mut b, ROOT_INO, 0, 0, &some_names());
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b"alpha").err(), Some(Errno::Enoent));
    // The listing still reports them, which is exactly the shape a
    // depth-ignoring lookup would hide.
    assert_eq!(v.read_dir(&root, ROOT_INO).unwrap().len(), 6);
}

#[test]
fn a_name_only_present_at_a_deeper_level_is_still_found() {
    // The fixture places everything at level zero, so a directory declaring a
    // depth of three must still find them: the walk starts at level zero.
    let mut b = Builder::new();
    nodes::add_block_dir(&mut b, ROOT_INO, 0, 3, &some_names());
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b"beta").unwrap().ino, 11);
}

#[test]
fn a_sparse_directory_block_is_skipped_rather_than_read_as_zeroes() {
    let mut b = Builder::new();
    nodes::add_block_dir(&mut b, ROOT_INO, 1, 1, &some_names());
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    // With two buckets at level zero, at least one of the four blocks is
    // unallocated; the listing must still be exactly the six names.
    assert_eq!(v.read_dir(&root, ROOT_INO).unwrap().len(), 6);
}

#[test]
fn a_lookup_in_something_that_is_not_a_directory_finds_nothing() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, 4, b"data");
    let v = b.mount().unwrap();
    let file = v.read_inode(4).unwrap();
    assert!(v.lookup(&file, 4, b"x").is_err());
}

/// A volume whose names fold, holding `entries` in its root.
fn folding_root(entries: &[Ent]) -> Volume<sectors::MemImage> {
    let mut b = Builder::new();
    b.feature |= crate::flags::FEATURE_CASEFOLD;
    b.s_encoding = crate::uapi::ENC_UTF8_12_1;
    let mut s = nodes::Spec::dir(ROOT_INO);
    s.flags = crate::flags::F2FS_CASEFOLD_FL;
    s.inline |= INLINE_DENTRY | INLINE_DATA | DATA_EXIST;
    let (at, len) = (s.addr_base() + INLINE_RESERVED_SIZE * 4,
                     (s.addrs_per_inode() - INLINE_RESERVED_SIZE) * 4);
    let layout = crate::dirent::Layout::inline(len);
    let cf = crate::casefold::Casefold::load(crate::uapi::ENC_UTF8_12_1, 0).unwrap();
    let mut all = nodes::dir::dots(ROOT_INO, ROOT_INO);
    all.extend_from_slice(entries);
    // A folding directory stores the hash of the FOLDED name.
    let area = nodes::dir::dentry_area_hashed(&layout, &all, |n| {
        crate::casefold::Query::prepare(&cf, n).unwrap().hash()
    });
    let mut block = nodes::inode_block(&s);
    block[at..at + len].copy_from_slice(&area);
    nodes::place_inode(&mut b, &s, block, 1);
    b.mount().unwrap()
}

#[test]
fn a_folding_volume_mounts_when_its_encoding_is_one_we_carry() {
    let v = folding_root(&[]);
    assert!(v.casefold().is_some());
    assert!(v.root().unwrap().casefolded());
}

#[test]
fn a_folding_volume_whose_encoding_we_cannot_load_is_refused() {
    // Guessing at a table we do not have would report names absent that the
    // directory would match.
    let mut b = Builder::new();
    b.feature |= crate::flags::FEATURE_CASEFOLD;
    b.s_encoding = 0xBEEF;
    nodes::add_inline_dir(&mut b, ROOT_INO, &[]);
    assert_eq!(b.mount().err(), Some(Errno::Einval));
}

#[test]
fn a_name_is_found_by_any_spelling_of_its_case() {
    let v = folding_root(&[ent("README", 10, FT_REG_FILE)]);
    let root = v.root().unwrap();
    for spelling in [b"README".as_slice(), b"readme", b"ReadMe", b"rEaDmE"] {
        assert_eq!(v.lookup(&root, ROOT_INO, spelling).unwrap().ino, 10,
                   "lost {:?}", core::str::from_utf8(spelling));
    }
}

#[test]
fn a_genuinely_different_name_is_still_absent() {
    let v = folding_root(&[ent("README", 10, FT_REG_FILE)]);
    let root = v.root().unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b"README2").err(), Some(Errno::Enoent));
    assert_eq!(v.lookup(&root, ROOT_INO, b"READM").err(), Some(Errno::Enoent));
}

#[test]
fn the_two_dot_names_are_compared_exactly_not_folded() {
    let v = folding_root(&[]);
    let root = v.root().unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b".").unwrap().ino, ROOT_INO);
    assert_eq!(v.lookup(&root, ROOT_INO, b"..").unwrap().ino, ROOT_INO);
}

#[test]
fn a_folding_directory_still_lists_the_bytes_it_stored() {
    // Folding decides what MATCHES, never what is reported.
    let v = folding_root(&[ent("README", 10, FT_REG_FILE)]);
    let root = v.root().unwrap();
    let names: Vec<Vec<u8>> =
        v.read_dir(&root, ROOT_INO).unwrap().into_iter().map(|e| e.name).collect();
    assert!(names.contains(&b"README".to_vec()));
    assert!(!names.contains(&b"readme".to_vec()));
}

#[test]
fn a_non_folding_directory_is_still_case_sensitive() {
    // The fold must key on the directory's own flag, or every volume becomes
    // case-insensitive the moment one directory is.
    let mut b = Builder::new();
    nodes::add_inline_dir(&mut b, ROOT_INO, &[ent("README", 10, FT_REG_FILE)]);
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, b"README").unwrap().ino, 10);
    assert_eq!(v.lookup(&root, ROOT_INO, b"readme").err(), Some(Errno::Enoent));
}

#[test]
fn an_encrypted_directory_refuses_rather_than_reporting_ciphertext_names() {
    let mut b = Builder::new();
    let mut s = nodes::Spec::dir(ROOT_INO);
    s.flags = F2FS_ENCRYPT_FL;
    s.inline |= INLINE_DENTRY | INLINE_DATA | DATA_EXIST;
    let block = nodes::inode_block(&s);
    nodes::place_inode(&mut b, &s, block, 1);
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert!(root.encrypted());
    assert_eq!(v.read_dir(&root, ROOT_INO).err(), Some(Errno::Eopnotsupp));
}

#[test]
fn a_directory_entry_with_a_corrupt_length_is_an_error_not_a_wrong_name() {
    let mut b = Builder::new();
    nodes::add_inline_dir(&mut b, ROOT_INO, &[ent("x", 9, FT_REG_FILE)]);
    let s = nodes::Spec::dir(ROOT_INO);
    let (at, len) = (s.addr_base() + INLINE_RESERVED_SIZE * 4,
                     (s.addrs_per_inode() - INLINE_RESERVED_SIZE) * 4);
    let layout = crate::dirent::Layout::inline(len);
    let de = at + layout.dentry_off(0) + DE_NAME_LEN;
    nodes::patch_inode(&mut b, ROOT_INO,
        |blk| blk[de..de + 2].copy_from_slice(&9999u16.to_le_bytes()));
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert_eq!(v.read_dir(&root, ROOT_INO).err(), Some(Errno::Eio));
}

#[test]
fn a_directory_of_many_names_finds_all_of_them() {
    let names: Vec<Ent> =
        (0..60u32).map(|i| ent(&alloc::format!("entry-{i:03}"), 100 + i, FT_REG_FILE)).collect();
    let mut b = Builder::new();
    nodes::add_block_dir(&mut b, ROOT_INO, 0, 1, &names);
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    for e in &names {
        assert_eq!(v.lookup(&root, ROOT_INO, &e.name).unwrap().ino, e.ino,
                   "name {:?}", core::str::from_utf8(&e.name));
    }
    assert_eq!(v.read_dir(&root, ROOT_INO).unwrap().len(), names.len() + 2);
}

#[test]
fn a_directory_holding_a_longest_name_finds_it() {
    let long = "z".repeat(NAME_LEN);
    let mut b = Builder::new();
    nodes::add_inline_dir(&mut b, ROOT_INO, &[ent(&long, 42, FT_REG_FILE)]);
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    assert_eq!(v.lookup(&root, ROOT_INO, long.as_bytes()).unwrap().ino, 42);
}

#[test]
fn an_entry_reports_the_type_it_was_stored_with() {
    let mut b = Builder::new();
    nodes::add_inline_dir(&mut b, ROOT_INO, &some_names());
    let v = b.mount().unwrap();
    let root = v.root().unwrap();
    let hit = v.lookup(&root, ROOT_INO, b"beta").unwrap();
    assert!(crate::volume::dir::entry_is_dir(&hit));
    let hit = v.lookup(&root, ROOT_INO, b"g").unwrap();
    assert!(!crate::volume::dir::entry_is_dir(&hit));
    assert_eq!(hit.file_type, FT_SYMLINK);
}
