use super::*;
use crate::test_image::{self, Builder, CLUSTER};
use crate::time::Stamp;

/// A timestamp every test writes with, so a comparison never depends on a
/// clock.
fn stamp() -> Stamp {
    Stamp { fields: dostime::DosTime { time: (12 << 11) | (30 << 5) | 5, date: (40 << 9) | (6 << 5) | 15, cs: 0 },
            tz: TZ_VALID }
}



#[test]
fn a_formatted_volume_mounts_and_finds_its_own_structures() {
    let v = test_image::empty();
    assert_eq!(v.geometry().cluster_bytes(), CLUSTER as u64);
    assert_eq!(v.geometry().data_clusters(), test_image::CLUSTER_COUNT);
    assert_eq!(v.label_string(), "OXIDE");
    // The root, bitmap and up-case clusters are the three in use.
    assert_eq!(v.used_clusters(), 3);
}

#[test]
fn the_boot_region_checksum_verifies() {
    let v = test_image::empty();
    assert!(v.verify_boot_region().unwrap());
}

#[test]
fn a_volume_with_no_allocation_bitmap_is_refused() {
    // Every cluster's freedom is the bitmap's answer, so a volume without one
    // cannot be allocated on and cannot be trusted about what is in use.
    let mut b = Builder::new();
    let image = {
        b.push_name("only.txt", false, 0, 0, ALLOC_FAT_CHAIN);
        let image = b.finish();
        // Blank the bitmap entry in the root: it sits second, after the label.
        let root_at = (test_image::DATA_START as usize) * test_image::SECTOR;
        let blank = alloc::vec![0u8; DENTRY_BYTES];
        image.poke(root_at + DENTRY_BYTES, &blank);
        image
    };
    let mut opts = Options::defaults();
    opts.settle();
    assert!(Volume::mount_with(image, opts).is_err());
}

#[test]
fn names_written_by_a_formatter_read_back() {
    let mut b = Builder::new();
    let first = b.write_run(b"hello exfat");
    b.push_name("hello.txt", false, first, 11, ALLOC_NO_FAT_CHAIN);
    b.push_name("Directory", true, 0, 0, ALLOC_FAT_CHAIN);
    let v = test_image::mount(b);
    let names: alloc::vec::Vec<_> = v.read_dir(&v.root_chain()).unwrap()
        .into_iter().map(|e| e.name).collect();
    assert_eq!(names, alloc::vec!["hello.txt", "Directory"]);
}

#[test]
fn a_file_written_as_one_extent_reads_without_the_table() {
    // A contiguous run carries no table entries at all; reading it through the
    // table would follow whatever the table's stale bytes say.
    let payload: alloc::vec::Vec<u8> = (0..CLUSTER * 3).map(|i| (i % 251) as u8).collect();
    let mut b = Builder::new();
    let first = b.write_run(&payload);
    b.push_name("big.bin", false, first, payload.len() as u64, ALLOC_NO_FAT_CHAIN);
    let v = test_image::mount(b);
    let hit = v.find_entry(&v.root_chain(), "big.bin").unwrap();
    assert!(hit.set.stream.contiguous());
    assert_eq!(v.read_whole(&hit).unwrap(), payload);
}

#[test]
fn a_file_written_as_a_chain_reads_through_the_table() {
    let payload: alloc::vec::Vec<u8> = (0..CLUSTER * 3).map(|i| (i % 199) as u8).collect();
    let mut b = Builder::new();
    let first = b.write_chained(&payload);
    b.push_name("split.bin", false, first, payload.len() as u64, ALLOC_FAT_CHAIN);
    let v = test_image::mount(b);
    let hit = v.find_entry(&v.root_chain(), "split.bin").unwrap();
    assert!(!hit.set.stream.contiguous());
    assert_eq!(v.read_whole(&hit).unwrap(), payload);
}

#[test]
fn a_read_stops_at_the_valid_size_not_the_allocation() {
    // The allocation covers a whole cluster of 0xAA; only eight bytes of it
    // were ever written. The rest belongs to whoever had the cluster before,
    // and returning it hands one user's data to another.
    let mut b = Builder::new();
    let first = b.write_run(&[0xAA; CLUSTER]);
    b.push_name_sized("short.bin", false, first, CLUSTER as u64, 8, ALLOC_NO_FAT_CHAIN);
    let v = test_image::mount(b);
    let hit = v.find_entry(&v.root_chain(), "short.bin").unwrap();
    assert_eq!(hit.set.stream.size, CLUSTER as u64);
    assert_eq!(hit.size(), 8);
    let bytes = v.read_whole(&hit).unwrap();
    assert_eq!(bytes.len(), 8);
    // And a read that ASKS for the whole allocation still stops at eight.
    let mut buf = alloc::vec![0u8; CLUSTER];
    assert_eq!(v.read_file(&hit, 0, &mut buf).unwrap(), 8);
    assert_eq!(v.read_file(&hit, 8, &mut buf).unwrap(), 0);
}

#[test]
fn a_lookup_is_case_insensitive_through_the_volumes_own_table() {
    let mut b = Builder::new();
    b.push_name("MixedCase.TXT", false, 0, 0, ALLOC_FAT_CHAIN);
    let v = test_image::mount(b);
    assert!(v.find_entry(&v.root_chain(), "mixedcase.txt").is_ok());
    assert!(v.find_entry(&v.root_chain(), "MIXEDCASE.TXT").is_ok());
    assert!(v.find_entry(&v.root_chain(), "mixedcase.tx").is_err());
}

#[test]
fn a_name_longer_than_one_entry_round_trips() {
    // Sixteen units needs two name entries, so the second one's characters
    // must be read as a continuation rather than a new name.
    let long = "0123456789abcdef-continues-past-one-entry";
    let mut b = Builder::new();
    b.push_name(long, false, 0, 0, ALLOC_FAT_CHAIN);
    let v = test_image::mount(b);
    assert_eq!(v.find_entry(&v.root_chain(), long).unwrap().name, long);
}

#[test]
fn a_path_resolves_through_directories() {
    let mut b = Builder::new();
    let dir_cluster = b.alloc();
    let mut inner = alloc::vec![0u8; CLUSTER];
    {
        let table = crate::upcase::builtin();
        let units: alloc::vec::Vec<u16> = "inner.txt".encode_utf16().collect();
        let hash = crate::checksum::name_hash(&table.fold_name(&units));
        let bytes = crate::dirent::set::build(crate::dirent::file::new_attrs(false), &units, hash,
                                              0, 0, 0, ALLOC_FAT_CHAIN, stamp(), stamp(), stamp())
            .unwrap();
        inner[..bytes.len()].copy_from_slice(&bytes);
    }
    let at = b.cluster_at(dir_cluster);
    b.bytes[at..at + CLUSTER].copy_from_slice(&inner);
    b.put_fat(dir_cluster, EOF_CLUSTER);
    b.push_name("sub", true, dir_cluster, CLUSTER as u64, ALLOC_NO_FAT_CHAIN);
    let v = test_image::mount(b);
    assert_eq!(v.lookup("/sub/inner.txt").unwrap().name, "inner.txt");
    assert!(v.lookup("/sub/missing.txt").is_err());
}

#[test]
fn a_read_only_volume_refuses_every_write() {
    let mut opts = Options::defaults();
    opts.settle();
    let mut v = Volume::mount_with(Builder::new().finish().read_only(), opts).unwrap();
    assert!(!v.writable());
    let dir = DirHandle::Root;
    assert_eq!(v.create_file(&dir, "new.txt", stamp()), Err(syscall::errno::Errno::Erofs));
    assert_eq!(v.set_dirty(true), Err(syscall::errno::Errno::Erofs));
}

#[test]
fn statfs_counts_clusters_not_sectors() {
    let v = test_image::empty();
    let space = v.space();
    assert_eq!(space.cluster_bytes, CLUSTER as u64);
    assert_eq!(space.total, u64::from(test_image::CLUSTER_COUNT));
    assert_eq!(space.free, u64::from(test_image::CLUSTER_COUNT) - 3);
    assert_eq!(space.name_max, MAX_NAME_LENGTH as u64);
}

#[test]
fn marking_dirty_writes_only_the_flags_word() {
    let mut v = test_image::empty();
    assert!(!v.was_dirty());
    v.set_dirty(true).unwrap();
    // The region checksum excludes the flags word, so the region is still
    // valid after the write.
    assert!(v.verify_boot_region().unwrap());
}

#[test]
fn the_in_use_percentage_is_written_at_unmount() {
    let mut v = test_image::empty();
    v.flush_percent_in_use().unwrap();
    assert!(v.verify_boot_region().unwrap());
}

#[test]
fn the_label_can_be_replaced() {
    let mut v = test_image::empty();
    v.set_label("NEWNAME").unwrap();
    assert_eq!(v.label_string(), "NEWNAME");
    // A label longer than the field holds is refused rather than truncated.
    assert!(v.set_label("FAR TOO LONG A LABEL").is_err());
}
