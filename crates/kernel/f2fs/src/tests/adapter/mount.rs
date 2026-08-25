use super::*;

#[test]
fn the_acl_mount_option_stamps_the_posixacl_superblock_flag() {
    let dev = disk(&test_image::with_root().finish());
    let acl = crate::opts::parse(&Options::defaults(), "acl").unwrap();
    let fs = F2fs::open_with(dev, "/dev/fake", true, acl).unwrap();
    let sb = realize(&fs);
    assert!(sb.is_posixacl());

    let dev = disk(&test_image::with_root().finish());
    let noacl = crate::opts::parse(&Options::defaults(), "noacl").unwrap();
    let fs = F2fs::open_with(dev, "/dev/fake", true, noacl).unwrap();
    let sb = realize(&fs);
    assert!(!sb.is_posixacl());
}

#[test]
fn a_fixture_image_mounts_through_the_interface() {
    let (fs, _dev) = mounted();
    assert!(fs.is_writable());
    assert_eq!(fs.source(), "/dev/fake");
    assert_eq!(vfs::fs::FileSystem::name(&*fs), F2FS_NAME);
    assert_eq!(vfs::fs::FileSystem::magic(&*fs), crate::uapi::F2FS_SUPER_MAGIC);
    assert_eq!(vfs::fs::FileSystem::block_size(&*fs), BS);
}

/// Naming no option is not the same as taking the build-wide default set:
/// the volume's own shape decides several of them, and a build-wide answer is
/// wrong on some volume every time.
#[test]
fn a_mount_that_names_nothing_takes_the_volumes_defaults_not_the_builds() {
    let dev = disk(&test_image::with_root().finish());
    let can_discard = dev.supports_discard();
    let fs = F2fs::open(dev, "/dev/fake").expect("mount");
    let o = fs.options();
    let build = Options::defaults();
    // A volume this small runs out of whole free segments long before it runs
    // out of space, so it reuses room inside a partly used one.
    assert_eq!(o.alloc_mode, crate::opts::AllocMode::Reuse);
    assert_ne!(o.alloc_mode, build.alloc_mode);
    // Whether the device is told about freed blocks follows the DEVICE, not
    // a build-wide guess.
    assert_eq!(o.discard, can_discard);
    // Merging flushes is a write-side optimisation and this mount cannot
    // write.
    assert!(!o.flush_merge);
}

#[test]
fn a_mount_that_did_not_ask_to_write_is_not_writable() {
    let dev = disk(&test_image::with_root().finish());
    let fs = F2fs::open_with(dev, "/dev/fake", false, Options::defaults()).unwrap();
    assert!(!fs.is_writable());
}

#[test]
fn the_root_inode_is_a_directory() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    assert_eq!(root.file_type(), FileType::Directory);
    assert_eq!(root.ino(), u64::from(ROOT_INO));
}

#[test]
fn a_file_created_through_the_interface_is_found_again() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let ctx = CreateCtx::root();
    let made = root.create_child("hello", 0o644, &ctx).unwrap();
    assert_eq!(made.file_type(), FileType::Regular);
    let found = root.lookup("hello").unwrap();
    assert_eq!(found.ino(), made.ino());
}

#[test]
fn repeated_lookups_share_one_inode_and_its_cached_shape() {
    let (fs, _dev) = mounted();
    let sb = realize(&fs);
    let root = sb.s_root_inode().unwrap();
    root.create_child("shared", 0o644, &CreateCtx::root()).unwrap();
    let first = root.lookup("shared").unwrap();
    let second = root.lookup("shared").unwrap();
    assert!(Arc::ptr_eq(&first, &second), "one inode number must name one in-core inode");
    first.write(0, b"shared shape").unwrap();
    assert_eq!(second.size(), 12, "a sibling handle must see the cached size move");
}

#[test]
fn a_missing_name_reports_no_entry() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    assert_eq!(root.lookup("absent").err(), Some(VfsError::Enoent));
}

#[test]
fn bytes_written_through_the_interface_read_back() {
    let (fs, _dev) = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("f", 0o644, &CreateCtx::root()).unwrap();
    assert_eq!(file.write(0, b"payload").unwrap(), 7);
    let mut buf = [0u8; 7];
    assert_eq!(file.read(0, &mut buf).unwrap(), 7);
    assert_eq!(&buf, b"payload");
    assert_eq!(file.size(), 7);
}

#[test]
fn a_write_survives_an_unmount_and_a_fresh_mount() {
    // The whole point of the adapter: state has to reach the DEVICE.
    let (fs, dev) = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("f", 0o644, &CreateCtx::root()).unwrap();
    file.write(0, b"durable").unwrap();
    fs.super_ops().unwrap().put_super();
    let fs = remount(&dev);
    let root = fs.root_inode().unwrap();
    let found = root.lookup("f").unwrap();
    let mut buf = [0u8; 7];
    found.read(0, &mut buf).unwrap();
    assert_eq!(&buf, b"durable");
}

#[test]
fn an_unmount_without_a_sync_still_writes_a_checkpoint() {
    // Skipping this loses everything the mount did; the medium would still
    // describe the state it was mounted in.
    let (fs, dev) = mounted();
    let root = fs.root_inode().unwrap();
    root.create_child("kept", 0o644, &CreateCtx::root()).unwrap();
    fs.super_ops().unwrap().put_super();
    let fs = remount(&dev);
    let root = fs.root_inode().unwrap();
    assert!(root.lookup("kept").is_ok());
}

#[test]
fn a_sync_makes_a_change_durable_without_an_unmount() {
    let (fs, dev) = mounted();
    let root = fs.root_inode().unwrap();
    root.create_child("synced", 0o644, &CreateCtx::root()).unwrap();
    fs.super_ops().unwrap().sync_fs(true).unwrap();
    let fs = remount(&dev);
    let root = fs.root_inode().unwrap();
    assert!(root.lookup("synced").is_ok());
}

#[test]
fn fsync_makes_a_files_bytes_durable() {
    // Reporting success here while the data is only in memory is the one
    // failure a database cannot defend against.
    let (fs, dev) = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("j", 0o644, &CreateCtx::root()).unwrap();
    file.write(0, b"committed").unwrap();
    let dentry = vfs::Dentry::new_root(file.clone());
    let f = File::new(file.clone(), dentry, OpenFlags::empty());
    crate::mount::ops::F2fsOps.fsync(&f, false).unwrap();
    let fs = remount(&dev);
    let root = fs.root_inode().unwrap();
    let found = root.lookup("j").unwrap();
    let mut buf = [0u8; 9];
    found.read(0, &mut buf).unwrap();
    assert_eq!(&buf, b"committed");
}

#[test]
fn fsync_costs_a_chain_and_not_a_checkpoint() {
    // A checkpoint makes the WHOLE volume durable and rewrites both tables;
    // paying one per `fsync` turns a database's every commit into a
    // filesystem-wide flush. The cheaper promise is a chain of the file's own
    // node blocks, which the next mount replays — so the test is that the
    // pack does not move and the bytes come back anyway.
    let (fs, dev) = mounted();
    let root = fs.root_inode().unwrap();
    let file = root.create_child("c", 0o644, &CreateCtx::root()).unwrap();
    fs.checkpoint().unwrap();
    file.write(0, b"promised").unwrap();
    let before = fs.volume.lock().checkpoint().version;
    let dentry = vfs::Dentry::new_root(file.clone());
    let f = File::new(file.clone(), dentry, OpenFlags::empty());
    crate::mount::ops::F2fsOps.fsync(&f, false).unwrap();
    assert_eq!(fs.volume.lock().checkpoint().version, before, "a chain, not a pack");
    let fs = remount(&dev);
    let root = fs.root_inode().unwrap();
    let found = root.lookup("c").unwrap();
    let mut buf = [0u8; 8];
    found.read(0, &mut buf).unwrap();
    assert_eq!(&buf, b"promised");
}

