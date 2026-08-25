use super::*;

#[test]
fn a_volume_survives_a_remount_after_a_write() {
    // The real test of a write path: read the image back through a fresh
    // mount, which trusts nothing the writing mount held in memory.
    let image = {
        let mut v = test_image::empty();
        let made = v.create_file(MFT_REC_ROOT, "persist.txt", now()).unwrap();
        v.write_file(made.reference.number, 0, b"still here after a remount", now()).unwrap();
        v.create_dir(MFT_REC_ROOT, "sub", now()).unwrap();
        v.into_source()
    };
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let v = Volume::mount_with(image, opts).unwrap();
    assert_eq!(names(&v), alloc::vec!["persist.txt", "sub"]);
    let hit = v.find_entry(MFT_REC_ROOT, "persist.txt").unwrap();
    assert_eq!(v.read_whole(hit.reference.number).unwrap(), b"still here after a remount");
}

#[test]
fn a_large_file_survives_a_remount() {
    let payload: alloc::vec::Vec<u8> = (0..CLUSTER * 4 + 11).map(|i| (i % 241) as u8).collect();
    let image = {
        let mut v = test_image::empty();
        let made = v.create_file(MFT_REC_ROOT, "big.bin", now()).unwrap();
        v.write_file(made.reference.number, 0, &payload, now()).unwrap();
        v.into_source()
    };
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let v = Volume::mount_with(image, opts).unwrap();
    let hit = v.find_entry(MFT_REC_ROOT, "big.bin").unwrap();
    assert_eq!(v.read_whole(hit.reference.number).unwrap(), payload);
}

#[test]
fn a_volume_can_be_filled_and_emptied_without_losing_clusters() {
    let mut v = test_image::empty();
    let before = v.free_clusters();
    for i in 0..8 {
        let name = alloc::format!("f{i}");
        let made = v.create_file(MFT_REC_ROOT, &name, now()).unwrap();
        v.write_file(made.reference.number, 0, &alloc::vec![i as u8; CLUSTER * 2], now()).unwrap();
    }
    for i in 0..8 { v.unlink(MFT_REC_ROOT, &alloc::format!("f{i}"), now()).unwrap(); }
    assert_eq!(v.free_clusters(), before);
    assert!(names(&v).is_empty());
}

#[test]
fn the_dirty_flag_round_trips() {
    let mut v = test_image::empty();
    assert!(!v.was_dirty());
    v.set_dirty(true).unwrap();
    let image = v.into_source();
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let mut v = Volume::mount_with(image, opts).unwrap();
    assert!(v.was_dirty());
    v.set_dirty(false).unwrap();
    let image = v.into_source();
    let v = Volume::mount_with(image, opts).unwrap();
    assert!(!v.was_dirty());
}

#[test]
fn a_name_past_the_length_ceiling_is_refused_before_anything_is_written() {
    let mut v = test_image::empty();
    let long: alloc::string::String = core::iter::repeat('x').take(256).collect();
    assert_eq!(v.create_file(MFT_REC_ROOT, &long, now()).unwrap_err(), Errno::Enametoolong);
    assert!(names(&v).is_empty());
}

#[test]
fn a_directory_fills_when_its_index_root_is_full() {
    // Once the resident root fills, Linux moves its ordered entries into the
    // first `$INDEX_ALLOCATION` buffer and keeps creating names there.
    let mut v = test_image::empty();
    let made = 30usize;
    for i in 0..made {
        v.create_file(MFT_REC_ROOT, &alloc::format!("long-directory-entry-{i:03}"), now())
            .unwrap_or_else(|e| panic!("create {i}: {e:?}"));
    }
    assert_eq!(names(&v).len(), made);
    for i in 0..made {
        assert!(v.find_entry(MFT_REC_ROOT,
                              &alloc::format!("long-directory-entry-{i:03}")).is_ok());
    }
    let (_, attrs) = v.read_live_record(MFT_REC_ROOT).unwrap();
    let alloc = crate::attrib::find(&attrs, ATTR_ALLOC, &I30_NAME).expect("index allocation");
    assert!(alloc.data_size() >= u64::from(test_image::INDEX_SIZE) * 2,
            "the test must exercise an allocation-buffer split");
    let image = v.into_source();
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let mut v = Volume::mount_with(image, opts).unwrap();
    assert_eq!(v.read_dir(MFT_REC_ROOT).unwrap().len(), made);
    v.unlink(MFT_REC_ROOT, "long-directory-entry-010", now()).unwrap();
    assert!(v.find_entry(MFT_REC_ROOT, "long-directory-entry-010").is_err());
    assert_eq!(v.read_dir(MFT_REC_ROOT).unwrap().len(), made - 1);
}

#[test]
fn a_directory_promotes_allocation_parents_when_the_root_fills() {
    let mut v = test_image::empty();
    let mut targets = alloc::vec::Vec::new();
    for i in 0..24 {
        let name = alloc::format!("p{i:02}");
        targets.push(v.create_file(MFT_REC_ROOT, &name, now()).unwrap().reference.number);
    }
    let mut made = targets.len();
    for (i, target) in targets.iter().enumerate() {
        for j in 0..6 {
            let name = alloc::format!("alias-{i:02}-{j}");
            v.link(MFT_REC_ROOT, &name, *target, now()).unwrap();
            made += 1;
        }
    }
    assert_eq!(v.read_dir(MFT_REC_ROOT).unwrap().len(), made);
    assert!(v.find_entry(MFT_REC_ROOT, "alias-23-5").is_ok());
    let image = v.into_source();
    let mut opts = crate::opts::Options::defaults();
    opts.settle();
    let mut v = Volume::mount_with(image, opts).unwrap();
    assert_eq!(v.read_dir(MFT_REC_ROOT).unwrap().len(), made);
    assert!(v.find_entry(MFT_REC_ROOT, "alias-23-5").is_ok());
    v.unlink(MFT_REC_ROOT, "alias-23-5", now()).unwrap();
    assert_eq!(v.read_dir(MFT_REC_ROOT).unwrap().len(), made - 1);
}
