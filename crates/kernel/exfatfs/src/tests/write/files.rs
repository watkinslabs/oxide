use super::*;

#[test]
fn a_created_file_is_found_by_the_name_it_was_given() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let made = v.create_file(&dir, "new.txt", stamp()).unwrap();
    assert_eq!(made.name, "new.txt");
    assert_eq!(made.size(), 0);
    assert_eq!(names(&v), alloc::vec!["new.txt"]);
    assert_eq!(v.find_entry(&v.root_chain(), "NEW.TXT").unwrap().name, "new.txt");
}

#[test]
fn an_empty_file_claims_no_clusters() {
    let mut v = test_image::empty();
    let before = v.used_clusters();
    let dir = root(&v);
    let made = v.create_file(&dir, "empty", stamp()).unwrap();
    assert_eq!(v.used_clusters(), before);
    assert_eq!(made.set.stream.start_cluster, 0);
}

#[test]
fn keep_size_preallocation_reserves_clusters_without_growing() {
    let mut v = test_image::empty();
    let mut made = v.create_file(&DirHandle::Root, "reserve", stamp()).unwrap();
    let before = v.used_clusters();
    v.preallocate_file(&mut made, 0, (CLUSTER * 2) as u64, stamp()).unwrap();
    assert_eq!(made.size(), 0);
    assert_eq!(v.used_clusters(), before + 2);
    v.write_file(&mut made, 0, b"x", stamp()).unwrap();
    assert_eq!(v.find_entry(&v.root_chain(), "reserve").unwrap().size(), 1);
}

#[test]
fn creating_a_name_that_exists_is_refused() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "dup", stamp()).unwrap();
    assert_eq!(v.create_file(&dir, "dup", stamp()).unwrap_err(), Errno::Eexist);
    // Case-insensitively, through the volume's own table.
    assert_eq!(v.create_file(&dir, "DUP", stamp()).unwrap_err(), Errno::Eexist);
}

#[test]
fn a_written_file_reads_back() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "hello.txt", stamp()).unwrap();
    let payload = b"hello exfat, from a write";
    v.write_file(&mut made, 0, payload, stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "hello.txt").unwrap();
    assert_eq!(hit.size(), payload.len() as u64);
    assert_eq!(v.read_whole(&hit).unwrap(), payload);
}

#[test]
fn a_write_spanning_several_clusters_reads_back_whole() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "big.bin", stamp()).unwrap();
    let payload: alloc::vec::Vec<u8> = (0..CLUSTER * 5 + 17).map(|i| (i % 251) as u8).collect();
    v.write_file(&mut made, 0, &payload, stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "big.bin").unwrap();
    assert_eq!(v.read_whole(&hit).unwrap(), payload);
}

#[test]
fn a_file_grown_in_place_stays_one_extent() {
    // Which is the point of the contiguous flag: nothing else on the volume
    // is allocating, so every cluster follows the last.
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "run.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[7u8; CLUSTER * 3], stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "run.bin").unwrap();
    assert!(hit.set.stream.contiguous(), "flags={:#x}", hit.set.stream.flags);
}

#[test]
fn a_file_that_cannot_grow_in_place_becomes_a_chain() {
    // Two files grown alternately cannot both stay contiguous, and the one
    // that is forced apart must have its table entries written before its
    // flag flips — reading it as contiguous afterwards reads the other file.
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut a = v.create_file(&dir, "a.bin", stamp()).unwrap();
    let mut b = v.create_file(&dir, "b.bin", stamp()).unwrap();
    let fill_a: alloc::vec::Vec<u8> = (0..CLUSTER * 2).map(|i| (i % 97) as u8).collect();
    let fill_b: alloc::vec::Vec<u8> = (0..CLUSTER * 2).map(|i| (i % 89) as u8).collect();
    v.write_file(&mut a, 0, &fill_a[..CLUSTER], stamp()).unwrap();
    v.write_file(&mut b, 0, &fill_b[..CLUSTER], stamp()).unwrap();
    v.write_file(&mut a, CLUSTER as u64, &fill_a[CLUSTER..], stamp()).unwrap();
    v.write_file(&mut b, CLUSTER as u64, &fill_b[CLUSTER..], stamp()).unwrap();

    let got_a = v.find_entry(&v.root_chain(), "a.bin").unwrap();
    let got_b = v.find_entry(&v.root_chain(), "b.bin").unwrap();
    assert!(!got_a.set.stream.contiguous(), "a must have become a chain");
    assert_eq!(v.read_whole(&got_a).unwrap(), fill_a);
    assert_eq!(v.read_whole(&got_b).unwrap(), fill_b);
}

#[test]
fn a_write_past_the_end_leaves_zeros_not_the_previous_owners_bytes() {
    let mut v = test_image::empty();
    let dir = root(&v);
    // Fill a run, delete it, then create a file that grows into the same
    // clusters with a gap.
    let mut scratch = v.create_file(&dir, "scratch", stamp()).unwrap();
    v.write_file(&mut scratch, 0, &[0xAB; CLUSTER * 2], stamp()).unwrap();
    v.unlink(&dir, "scratch", stamp()).unwrap();

    let mut made = v.create_file(&dir, "sparse", stamp()).unwrap();
    v.write_file(&mut made, CLUSTER as u64, b"tail", stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "sparse").unwrap();
    let bytes = v.read_whole(&hit).unwrap();
    assert_eq!(bytes.len(), CLUSTER + 4);
    assert!(bytes[..CLUSTER].iter().all(|b| *b == 0), "the gap kept old bytes");
    assert_eq!(&bytes[CLUSTER..], b"tail");
}

#[test]
fn a_write_into_the_middle_keeps_the_bytes_either_side() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "patch.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[1u8; 64], stamp()).unwrap();
    v.write_file(&mut made, 16, &[2u8; 8], stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "patch.bin").unwrap();
    let bytes = v.read_whole(&hit).unwrap();
    assert_eq!(&bytes[..16], &[1u8; 16]);
    assert_eq!(&bytes[16..24], &[2u8; 8]);
    assert_eq!(&bytes[24..], &[1u8; 40]);
}

#[test]
fn shortening_a_file_releases_the_clusters_it_no_longer_needs() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "shrink.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[3u8; CLUSTER * 4], stamp()).unwrap();
    let used = v.used_clusters();
    v.truncate_file(&mut made, CLUSTER as u64, stamp()).unwrap();
    assert_eq!(v.used_clusters(), used - 3);
    let hit = v.find_entry(&v.root_chain(), "shrink.bin").unwrap();
    assert_eq!(hit.size(), CLUSTER as u64);
    assert_eq!(v.read_whole(&hit).unwrap(), alloc::vec![3u8; CLUSTER]);
}

#[test]
fn shortening_to_nothing_releases_everything() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let before = v.used_clusters();
    let mut made = v.create_file(&dir, "gone.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[3u8; CLUSTER * 2], stamp()).unwrap();
    v.truncate_file(&mut made, 0, stamp()).unwrap();
    assert_eq!(v.used_clusters(), before);
    assert_eq!(v.find_entry(&v.root_chain(), "gone.bin").unwrap().size(), 0);
}

#[test]
fn lengthening_a_file_allocates_and_zeroes() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "grow.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, b"abc", stamp()).unwrap();
    v.truncate_file(&mut made, CLUSTER as u64 * 2, stamp()).unwrap();
    let hit = v.find_entry(&v.root_chain(), "grow.bin").unwrap();
    let bytes = v.read_whole(&hit).unwrap();
    assert_eq!(bytes.len(), CLUSTER * 2);
    assert_eq!(&bytes[..3], b"abc");
    assert!(bytes[3..].iter().all(|b| *b == 0));
}

#[test]
fn a_deleted_name_releases_its_clusters() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let before = v.used_clusters();
    let mut made = v.create_file(&dir, "temp.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[9u8; CLUSTER * 3], stamp()).unwrap();
    assert_eq!(v.used_clusters(), before + 3);
    v.unlink(&dir, "temp.bin", stamp()).unwrap();
    assert_eq!(v.used_clusters(), before);
    assert!(names(&v).is_empty());
}

#[test]
fn a_deleted_names_entries_are_reused() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let first = v.create_file(&dir, "one", stamp()).unwrap();
    v.unlink(&dir, "one", stamp()).unwrap();
    let second = v.create_file(&dir, "two", stamp()).unwrap();
    assert_eq!(second.set.offset, first.set.offset);
}

