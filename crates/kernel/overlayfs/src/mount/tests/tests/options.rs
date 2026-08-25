use super::*;

#[test]
fn the_mount_line_names_the_layers_back() {
    let (l, _up, _lo) = image();
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let line = vfs::fs::FileSystem::show_options(&*fs);
    assert!(line.contains("lowerdir=/lower"), "{line}");
    assert!(line.contains("upperdir=/upper"), "{line}");
    assert!(line.contains("workdir=/work"), "{line}");
}

#[test]
fn the_mount_line_escapes_the_verbatim_lowerdir_list_again() {
    let up = layer(0);
    let lo = layer(1);
    let work = layer(2);
    let mut m = BTreeMap::new();
    m.insert("/upper".to_string(), up);
    m.insert("/a,b".to_string(), lo);
    m.insert("/work".to_string(), work);
    let l = Layers(m);
    let fs = OverlayFs::open("lowerdir=/a\\,b,upperdir=/upper,workdir=/work",
        &l.resolve(), true).unwrap();
    let line = vfs::fs::FileSystem::show_options(&*fs);
    assert!(line.contains("lowerdir=/a\\\\\\,b"), "{line}");
}

#[test]
fn the_reported_filesystem_type_is_the_overlays() {
    let (l, _up, _lo) = image();
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let ops = vfs::fs::FileSystem::super_ops(&*fs).unwrap();
    assert_eq!(ops.statfs().unwrap().f_type, crate::OVERLAYFS_SUPER_MAGIC);
    assert_eq!(vfs::fs::FileSystem::magic(&*fs), crate::OVERLAYFS_SUPER_MAGIC);
}

#[test]
fn a_copied_up_file_keeps_the_inode_number_it_had() {
    // A program holding the file open across a write must not see its identity
    // change under it.
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"image");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let before = fs.root_inode().lookup("f").unwrap().ino();
    let f = fs.root_inode().lookup("f").unwrap();
    f.write(0, b"local").unwrap();
    let after = fs.root_inode().lookup("f").unwrap().ino();
    assert_eq!(before, after);
    let _ = mkpath(&lo, "unused");
    let _ = Config::default();
    let _ = Arc::new(());
    let _ = vec![0u8; 0];
}
