use super::*;

#[test]
fn a_directory_lists_its_own_stored_dots_exactly_once() {
    // The interface synthesises `.` and `..` for backends that lack them, so a
    // backend that stores them must say so or every listing shows them twice.
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    assert!(root.dir_emits_dots());
    let names = list(&root);
    assert_eq!(names.iter().filter(|n| *n == ".").count(), 1);
    assert_eq!(names.iter().filter(|n| *n == "..").count(), 1);
}

#[test]
fn a_listing_reports_what_was_created() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx::root();
    root.create_child("one", 0o644, &ctx).unwrap();
    root.mkdir("two", 0o755, &ctx).unwrap();
    let names = list(&root);
    assert!(names.iter().any(|n| n == "one"));
    assert!(names.iter().any(|n| n == "two"));
    assert_eq!(names.len(), 4);
}

/// Every name a directory reports.
#[test]
fn a_directory_removed_through_the_interface_is_gone() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx::root();
    root.mkdir("d", 0o755, &ctx).unwrap();
    root.rmdir("d").unwrap();
    assert_eq!(root.lookup("d").err(), Some(VfsError::Enoent));
}

#[test]
fn removing_a_directory_that_holds_a_name_is_refused() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx::root();
    let d = root.mkdir("d", 0o755, &ctx).unwrap();
    d.create_child("inside", 0o644, &ctx).unwrap();
    assert_eq!(root.rmdir("d").err(), Some(VfsError::Enotempty));
}

#[test]
fn a_symbolic_link_reads_its_target_back() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx::root();
    root.symlink_child("l", b"/somewhere/else", &ctx).unwrap();
    let link = root.lookup("l").unwrap();
    assert_eq!(link.file_type(), FileType::Symlink);
    assert_eq!(link.readlink().unwrap(), b"/somewhere/else".to_vec());
}

#[test]
fn an_empty_link_target_is_refused() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    assert!(root.symlink_child("l", b"", &CreateCtx::root()).is_err());
}

#[test]
fn an_attribute_set_through_the_interface_reads_back() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("f", 0o644, &CreateCtx::root()).unwrap();
    file.setxattr("user.k", b"v".to_vec(), false, false).unwrap();
    assert_eq!(file.getxattr("user.k").unwrap(), b"v".to_vec());
    assert_eq!(file.listxattr().unwrap(), ["user.k"]);
}

#[test]
fn statfs_reports_this_filesystem() {
    let (fs, _dev) = mounted();
    let st = fs.super_ops().unwrap().statfs().unwrap();
    assert_eq!(st.f_type, crate::uapi::F2FS_SUPER_MAGIC);
    assert_eq!(st.f_bsize, BS);
    assert_eq!(st.f_namelen, crate::limits::NAME_MAX);
    assert!(st.f_blocks > 0);
    assert!(st.f_bfree <= st.f_blocks);
    assert!(st.f_bavail <= st.f_bfree);
}

#[test]
fn statfs_free_space_falls_as_the_volume_fills() {
    let (fs, _dev) = mounted();
    let ops = fs.super_ops().unwrap();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("big", 0o644, &CreateCtx::root()).unwrap();
    ops.sync_fs(true).unwrap();
    let before = ops.statfs().unwrap().f_bfree;
    file.write(0, &vec![1u8; 8 * BLKSIZE]).unwrap();
    ops.sync_fs(true).unwrap();
    assert!(ops.statfs().unwrap().f_bfree < before);
}

#[test]
fn the_option_tail_round_trips_and_names_this_filesystem() {
    let dev = disk(&test_image::with_root().finish());
    let opts = crate::opts::parse(&Options::defaults(), "noacl,mode=lfs").unwrap();
    let fs = F2fs::open_with(dev, "/dev/fake", true, opts).unwrap();
    let shown = vfs::fs::FileSystem::show_options(&*fs);
    assert!(shown.contains(",noacl"));
    assert!(shown.contains(",mode=lfs"));
    assert_eq!(fs.super_ops().unwrap().show_options(), shown);
    assert!(crate::opts::parse(&Options::defaults(), &shown).is_ok());
}

