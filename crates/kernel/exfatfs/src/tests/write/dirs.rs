use super::*;

#[test]
fn a_directory_can_be_made_and_holds_names_of_its_own() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let made = v.create_dir(&dir, "sub", stamp()).unwrap();
    assert!(made.is_dir());
    let inner = DirHandle::child(&dir, made.set.offset);
    v.create_file(&inner, "inside.txt", stamp()).unwrap();
    assert_eq!(v.lookup("/sub/inside.txt").unwrap().name, "inside.txt");
}

#[test]
fn a_new_directorys_cluster_is_cleared_before_it_is_named() {
    // A byte left over from the cluster's last owner reads as a name in a
    // directory that is supposed to be empty.
    let mut v = test_image::empty();
    let dir = root(&v);
    // Leftover bytes that are a VALID entry set, so an uncleared cluster
    // would LIST as a name rather than merely failing to decode.
    let units: alloc::vec::Vec<u16> = "ghost.txt".encode_utf16().collect();
    let hash = crate::checksum::name_hash(&v.upcase().fold_name(&units));
    let leftover = crate::dirent::set::build(crate::dirent::file::new_attrs(false), &units, hash,
                                             0, 0, 0, ALLOC_FAT_CHAIN, stamp(), stamp(), stamp())
        .unwrap();
    let mut junk = alloc::vec![0u8; CLUSTER];
    junk[..leftover.len()].copy_from_slice(&leftover);
    let mut scratch = v.create_file(&dir, "scratch", stamp()).unwrap();
    v.write_file(&mut scratch, 0, &junk, stamp()).unwrap();
    let reused = scratch.set.stream.start_cluster;
    v.unlink(&dir, "scratch", stamp()).unwrap();
    let made = v.create_dir(&dir, "fresh", stamp()).unwrap();
    // The new directory must land on the cluster just freed, or the test
    // proves nothing about clearing.
    assert_eq!(made.set.stream.start_cluster, reused);
    let inner = v.chain_of(&made.set);
    assert_eq!(v.read_dir(&inner).unwrap().len(), 0, "an uncleared cluster listed a name");
    assert!(v.dir_is_empty(&inner).unwrap());
}

#[test]
fn a_directory_with_anything_in_it_will_not_be_removed() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let made = v.create_dir(&dir, "full", stamp()).unwrap();
    let inner = DirHandle::child(&dir, made.set.offset);
    v.create_file(&inner, "child", stamp()).unwrap();
    assert_eq!(v.rmdir(&dir, "full", stamp()).unwrap_err(), Errno::Enotempty);
    v.unlink(&inner, "child", stamp()).unwrap();
    v.rmdir(&dir, "full", stamp()).unwrap();
    assert!(names(&v).is_empty());
}

#[test]
fn the_two_removals_refuse_each_others_kind() {
    let mut v = test_image::empty();
    let dir = root(&v);
    v.create_file(&dir, "f", stamp()).unwrap();
    v.create_dir(&dir, "d", stamp()).unwrap();
    assert_eq!(v.unlink(&dir, "d", stamp()).unwrap_err(), Errno::Eisdir);
    assert_eq!(v.rmdir(&dir, "f", stamp()).unwrap_err(), Errno::Enotdir);
}

#[test]
fn a_deferred_unlink_keeps_clusters_until_the_owner_releases_them() {
    let mut v = test_image::empty();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "open.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[0x5a; CLUSTER], stamp()).unwrap();
    let before = v.free_clusters();
    let chains = v.unlink_name(&dir, "open.bin", stamp()).unwrap();
    assert_eq!(v.free_clusters(), before,
        "unlink released clusters before the inode lifetime ended");
    assert_eq!(v.read_whole(&made).unwrap(), alloc::vec![0x5a; CLUSTER]);
    for chain in &chains { v.free_chain(chain).unwrap(); }
    assert_eq!(v.free_clusters(), before + 1,
        "final owner release did not return the detached cluster");
}

#[test]
fn freeing_clusters_discards_each_contiguous_run() {
    let mut opts = crate::opts::Options::defaults();
    opts.discard = true;
    opts.settle();
    let image = test_image::Builder::new().finish();
    let mut v = Volume::mount_with(image, opts).unwrap();
    let dir = root(&v);
    let mut made = v.create_file(&dir, "discard.bin", stamp()).unwrap();
    v.write_file(&mut made, 0, &[0x5a; CLUSTER * 2], stamp()).unwrap();
    let chain = Chain::new(made.set.stream.start_cluster,
                           (made.set.stream.size / v.geometry().cluster_bytes()) as u32,
                           made.set.stream.flags);
    let first_sector = v.geometry().cluster_sector(chain.dir).unwrap();
    let sectors = u64::from(v.geometry().sectors_per_cluster) * 2;
    v.free_chain(&chain).unwrap();
    let image = v.into_source();
    assert_eq!(image.erased(), alloc::vec![(first_sector, sectors)]);
}

