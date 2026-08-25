use super::*;

#[test]
fn writing_a_lower_file_copies_it_up_and_leaves_the_image_alone() {
    let (l, up, lo) = image();
    mkfile(&lo, "f", b"image");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let f = fs.root_inode().lookup("f").unwrap();
    f.write(0, b"local").unwrap();
    assert_eq!(slurp(&find_path(&up, "f").expect("copied up")), b"local".to_vec());
    assert_eq!(slurp(&find_path(&lo, "f").unwrap()), b"image".to_vec());
    let mut buf = [0u8; 16];
    let n = f.read(0, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"local");
}

#[test]
fn fallocate_on_a_lower_file_copies_data_up_before_forwarding() {
    let (l, up, lo) = image();
    mkfile(&lo, "f", b"image");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let f = fs.root_inode().lookup("f").unwrap();
    f.fallocate(0, 4096, 4096).unwrap();
    assert_eq!(f.size(), 8192);
    assert_eq!(slurp(&find_path(&lo, "f").unwrap()), b"image".to_vec());
    assert_eq!(find_path(&up, "f").unwrap().size(), 8192);
}

#[test]
fn fiemap_on_a_metadata_only_file_reads_the_data_owner() {
    let (l, up, lo) = image();
    mkfile(&lo, "f", b"image");
    let fs = OverlayFs::open("lowerdir=/lower,upperdir=/upper,workdir=/work,metacopy=on",
                             &l.resolve(), true).unwrap();
    let f = fs.root_inode().lookup("f").unwrap();
    let mut extents = Vec::new();
    f.fiemap(0, 4096, &mut |e| { extents.push(e); true }).unwrap();
    assert_eq!(extents.len(), 1);
    assert!(find_path(&up, "f").is_none(), "fiemap is read-only");
    assert_eq!(slurp(&find_path(&lo, "f").unwrap()), b"image".to_vec());
}

#[test]
fn overlay_tmpfile_is_unlinked_until_linked_into_the_upper_layer() {
    let (l, up, _lo) = image();
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let tmp = fs.root_inode().tmpfile(S_IFREG as u32 | 0o600, &CreateCtx::root()).unwrap();
    assert_eq!(tmp.nlink(), 0);
    tmp.write(0, b"anonymous").unwrap();
    fs.root_inode().link_child(&tmp, "published", &CreateCtx::root()).unwrap();
    assert_eq!(slurp(&find_path(&up, "published").unwrap()), b"anonymous".to_vec());
}

#[test]
fn creating_a_file_lands_in_the_writable_layer_only() {
    let (l, up, lo) = image();
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    fs.root_inode().create_child("new", S_IFREG as u32 | 0o644, &CreateCtx::root()).unwrap();
    assert!(find_path(&up, "new").is_some());
    assert!(find_path(&lo, "new").is_none());
}

#[test]
fn deleting_a_lower_file_hides_it_without_touching_the_image() {
    let (l, up, lo) = image();
    mkfile(&lo, "f", b"image");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    fs.root_inode().unlink_child("f").unwrap();
    assert!(fs.root_inode().lookup("f").is_err());
    assert!(whiteout::is_device(&find_path(&up, "f").unwrap()));
    assert!(find_path(&lo, "f").is_some(), "the image is read-only");
    assert!(names(&fs.root_inode()).is_empty());
}

#[test]
fn a_write_deep_in_the_image_copies_up_the_directories_above_it() {
    // A container writing one configuration file must not copy the tree it
    // sits in, but the directories themselves have to exist above it.
    let (l, up, lo) = image();
    mkfile(&lo, "etc/nested/conf", b"image");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let etc = fs.root_inode().lookup("etc").unwrap();
    let nested = etc.lookup("nested").unwrap();
    let conf = nested.lookup("conf").unwrap();
    conf.write(0, b"local").unwrap();
    assert_eq!(find_path(&up, "etc").unwrap().file_type(), FileType::Directory);
    assert_eq!(slurp(&find_path(&up, "etc/nested/conf").unwrap()), b"local".to_vec());
    assert_eq!(slurp(&find_path(&lo, "etc/nested/conf").unwrap()), b"image".to_vec());
}

#[test]
fn a_merged_directory_lists_every_layer_and_hides_what_was_deleted() {
    let (l, _up, lo) = image();
    mkfile(&lo, "d/a", b"");
    mkfile(&lo, "d/b", b"");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let d = fs.root_inode().lookup("d").unwrap();
    d.create_child("c", S_IFREG as u32 | 0o644, &CreateCtx::root()).unwrap();
    assert_eq!(names(&d), vec!["a", "b", "c"]);
    d.unlink_child("a").unwrap();
    assert_eq!(names(&d), vec!["b", "c"]);
}

#[test]
fn the_overlays_own_markers_are_invisible_to_a_caller() {
    // Listing one would make a `tar` of the overlay carry it into the archive,
    // and restoring that produces a file nothing can see.
    let (l, _up, lo) = image();
    mkfile(&lo, "f", b"x");
    let fs = OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let f = fs.root_inode().lookup("f").unwrap();
    f.setxattr("user.mine", b"v".to_vec(), false, false).unwrap();
    let listed = f.listxattr().unwrap();
    assert!(listed.contains(&"user.mine".to_string()));
    assert!(!listed.iter().any(|n| n.starts_with("trusted.overlay.")), "{listed:?}");
    assert!(f.setxattr("trusted.overlay.opaque", b"y".to_vec(), false, false).is_err());
}
