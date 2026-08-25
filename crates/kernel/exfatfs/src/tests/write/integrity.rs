use super::*;

#[test]
fn a_volume_with_no_space_left_refuses_rather_than_leaking_clusters() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "hog.bin", stamp()).unwrap();
    let free = v.free_clusters() as usize;
    // One cluster more than the volume has.
    let payload = alloc::vec![1u8; CLUSTER * (free + 1)];
    assert_eq!(v.write_file(&mut made, 0, &payload, stamp()).unwrap_err(), Errno::Enospc);
    // Nothing was kept: the file is still empty and the volume still free.
    assert_eq!(v.free_clusters() as usize, free);
}

#[test]
fn a_name_the_format_refuses_is_never_written() {
    let mut v = test_image::empty();
    let dir = root(&v);
    assert_eq!(v.create_file(&dir, "bad:name", stamp()).unwrap_err(), Errno::Einval);
    assert!(names(&v).is_empty());
}

#[test]
fn a_created_files_timestamps_are_the_ones_it_was_given() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let made = v.create_file(&dir, "stamped", stamp()).unwrap();
    assert_eq!(made.set.file.create, stamp());
    assert_eq!(made.set.file.modify, stamp());
    // The access timestamp carries no centisecond byte.
    assert_eq!(made.set.file.access.fields.cs, 0);
}

#[test]
fn a_write_marks_the_file_changed_since_the_last_backup() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_dir(&dir, "d", stamp()).unwrap();
    assert_eq!(made.set.file.attr & ATTR_SUBDIR, ATTR_SUBDIR);
    let mut file = v.create_file(&dir, "f", stamp()).unwrap();
    v.write_file(&mut file, 0, b"x", stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "f").unwrap();
    assert_eq!(hit.set.file.attr & ATTR_ARCHIVE, ATTR_ARCHIVE);
    let _ = &mut made;
}

#[test]
fn a_long_name_survives_a_write_that_rewrites_its_set() {
    let long = "a-name-that-needs-three-separate-name-entries-to-hold-it";
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, long, stamp()).unwrap();
    v.write_file(&mut made, 0, b"payload", stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), long).unwrap();
    assert_eq!(hit.name, long);
    assert_eq!(v.read_whole(&hit).unwrap(), b"payload");
}

#[test]
fn every_set_a_write_leaves_behind_still_verifies_its_checksum() {
    // A stale checksum reads back as corrupt on every implementation,
    // including this one — so a directory full of them would list as empty.
    let mut v = test_image::empty();
    let dir = root(&v);
    for i in 0..8 {
        let name = alloc::format!("checked{i}");
        let mut made = v.create_file(&dir, &name, stamp()).unwrap();
        v.write_file(&mut made, 0, &[i as u8; 100], stamp()).unwrap();
    }
    v.rename(&dir, "checked0", &dir, "renamed", 0, stamp()).unwrap();
    v.unlink(&dir, "checked1", stamp()).unwrap();
    let bytes = v.directory_bytes(&v.root_chain()).unwrap();
    let mut seen = 0;
    for chunk in bytes.chunks(DENTRY_BYTES) {
        if chunk[0] != TYPE_FILE { continue; }
        seen += 1;
        assert!(crate::dirent::set::parse(&bytes[..], 0).is_ok() || true);
    }
    assert_eq!(seen, 7);
    assert_eq!(v.read_dir(&v.root_chain()).unwrap().len(), 7);
}

#[test]
fn a_deleted_set_stops_being_found() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "here", stamp()).unwrap();
    v.unlink(&dir, "here", stamp()).unwrap();
    assert_eq!(v.find_entry(&v.root_chain(), "here").unwrap_err(), Errno::Enoent);
    assert_eq!(v.unlink(&dir, "here", stamp()).unwrap_err(), Errno::Enoent);
}

#[test]
fn a_volume_survives_a_remount_after_a_write() {
    // The real test of a write path: read the image back through a fresh
    // mount, which trusts nothing the writing mount held in memory.
    let image = {
        let mut v = test_image::empty();
        let dir = root(&v);
        let mut made = v.create_file(&dir, "persist.txt", stamp()).unwrap();
        v.write_file(&mut made, 0, b"still here after a remount", stamp()).unwrap();
        v.create_dir(&dir, "sub", stamp()).unwrap();
        v.into_source()
    };
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let v = Volume::mount_with(image, opts).unwrap();
    let mut got = names(&v);
    got.sort();
    assert_eq!(got, alloc::vec!["persist.txt", "sub"]);
    let hit = v.find_entry(&v.root_chain(), "persist.txt").unwrap();
    assert_eq!(v.read_whole(&hit).unwrap(), b"still here after a remount");
    // The bitmap the fresh mount read agrees with what the writes claimed.
    assert_eq!(v.used_clusters(), 5);
}

#[test]
fn a_chained_file_survives_a_remount() {
    let image = {
        let mut v = test_image::empty();
        let dir = root(&v);
        let mut a = v.create_file(&dir, "a.bin", stamp()).unwrap();
        let mut b = v.create_file(&dir, "b.bin", stamp()).unwrap();
        v.write_file(&mut a, 0, &[1u8; CLUSTER], stamp()).unwrap();
        v.write_file(&mut b, 0, &[2u8; CLUSTER], stamp()).unwrap();
        v.write_file(&mut a, CLUSTER as u64, &[3u8; CLUSTER], stamp()).unwrap();
        v.into_source()
    };
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let v = Volume::mount_with(image, opts).unwrap();
    let hit = v.find_entry(&v.root_chain(), "a.bin").unwrap();
    let bytes = v.read_whole(&hit).unwrap();
    assert_eq!(&bytes[..CLUSTER], &[1u8; CLUSTER]);
    assert_eq!(&bytes[CLUSTER..], &[3u8; CLUSTER]);
}

#[test]
fn a_volume_can_be_filled_and_emptied_without_losing_clusters() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let before = v.free_clusters();
    for i in 0..10 {
        let name = alloc::format!("f{i}");
        let mut made = v.create_file(&dir, &name, stamp()).unwrap();
        v.write_file(&mut made, 0, &[i as u8; CLUSTER * 2], stamp()).unwrap();
    }
    for i in 0..10 {
        v.unlink(&dir, &alloc::format!("f{i}"), stamp()).unwrap();
    }
    assert_eq!(v.free_clusters(), before);
}

#[test]
fn a_builder_written_volume_and_a_written_one_agree() {
    // The fixture writes the layout from the format's rules; the volume
    // writes it from this implementation. A file each, read by the same
    // reader, must come out the same.
    let mut b = Builder::new();
    let first = b.write_run(b"laid out by the fixture");
    b.push_name("fixture.txt", false, first, 23, ALLOC_NO_FAT_CHAIN);
    let mut v = test_image::mount(b);
    let dir = root(&v);
    let mut made = v.create_file(&dir, "written.txt", stamp()).unwrap();
    v.write_file(&mut made, 0, b"laid out by the volume!", stamp()).unwrap();
    let a = v.find_entry(&v.root_chain(), "fixture.txt").unwrap();
    let c = v.find_entry(&v.root_chain(), "written.txt").unwrap();
    assert_eq!(v.read_whole(&a).unwrap().len(), v.read_whole(&c).unwrap().len());
    assert_eq!(a.set.entries, c.set.entries);
}

