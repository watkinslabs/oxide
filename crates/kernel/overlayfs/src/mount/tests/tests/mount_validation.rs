use super::*;

#[test]
fn a_work_directory_inside_the_writable_layer_is_refused() {
    let (l, _up, _lo) = image();
    let opts = "lowerdir=/lower,upperdir=/upper,workdir=/upper/work";
    assert_eq!(OverlayFs::open(opts, &l.resolve(), true).err(), Some(Errno::Einval));
}

#[test]
fn a_layer_that_is_not_a_directory_is_refused() {
    let (mut l, _up, lo) = image();
    let f = mkfile(&lo, "file", b"x");
    l.0.insert("/notadir".to_string(), f);
    let opts = "lowerdir=/notadir,upperdir=/upper,workdir=/work";
    assert_eq!(OverlayFs::open(opts, &l.resolve(), true).err(), Some(Errno::Enotdir));
}

#[test]
fn a_layer_that_does_not_exist_is_refused() {
    let (l, _up, _lo) = image();
    let opts = "lowerdir=/absent,upperdir=/upper,workdir=/work";
    assert_eq!(OverlayFs::open(opts, &l.resolve(), true).err(), Some(Errno::Enoent));
}

#[test]
fn a_single_lower_layer_with_nothing_to_write_to_is_refused() {
    // It would present the layer unchanged and fail every write in a way the
    // caller cannot tell from a broken mount.
    let (l, _up, _lo) = image();
    assert_eq!(OverlayFs::open("lowerdir=/lower", &l.resolve(), true).err(), Some(Errno::Einval));
}

#[test]
fn a_mount_with_no_layers_at_all_is_refused() {
    let (l, _up, _lo) = image();
    assert_eq!(OverlayFs::open("", &l.resolve(), true).err(), Some(Errno::Einval));
}

#[test]
fn the_work_directory_is_created_under_the_named_base() {
    let (l, _up, _lo) = image();
    OverlayFs::open(OPTS, &l.resolve(), true).unwrap();
    let work = l.0.get("/work").unwrap();
    assert!(find_path(work, "work").is_some());
}

#[test]
fn a_volatile_mount_publishes_the_incompatibility_marker() {
    let (l, _up, _lo) = image();
    OverlayFs::open(&alloc::format!("{OPTS},volatile"), &l.resolve(), true).unwrap();
    let base = l.0.get("/work").unwrap();
    let work = find_path(base, crate::uapi::WORKDIR_NAME).unwrap();
    assert!(find_path(&work, crate::uapi::VOLATILE_DIRTY_NAME).is_some());
}

#[test]
fn a_mount_refuses_a_workdir_with_a_volatile_incompatibility_marker() {
    let (l, _up, _lo) = image();
    let base = l.0.get("/work").unwrap();
    let work = mkpath(base, crate::uapi::WORKDIR_NAME);
    mkfile(&work, crate::uapi::VOLATILE_DIRTY_NAME, b"");
    assert_eq!(OverlayFs::open(OPTS, &l.resolve(), true).err(), Some(Errno::Einval));
}

#[test]
fn a_mount_removes_a_malformed_index_entry_before_publishing_root() {
    let (l, _up, _lo) = image();
    let base = l.0.get("/work").unwrap();
    let index = mkpath(base, "index");
    mkfile(&index, "not-an-origin-handle", b"");
    assert!(names(&index).contains(&"not-an-origin-handle".to_string()));
    let opts = "lowerdir=/lower,upperdir=/upper,workdir=/work,index=on";
    let fs = OverlayFs::open(opts, &l.resolve(), true).unwrap();
    assert!(fs.layers().indexdir.is_some());
    assert!(index.lookup("not-an-origin-handle").is_err(),
            "mount must clean an index entry it cannot decode");
}
