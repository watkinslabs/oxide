use super::*;

#[test]
fn a_write_through_the_filesystem_is_deferred_and_still_reads_back() {
    // The mount installs the way back at `adopt_data_pages`. Remove that call
    // and the layer below refuses to dirty a page it cannot place, so the
    // write below fails outright.
    let (fs, _dev, ino) = with_file();
    let page = vec![0xA5u8; BLKSIZE];
    assert_eq!(fs.write(ino, 0, &page).unwrap(), BLKSIZE);
    assert_eq!(fs.volume.lock().dirty_data_pages(ino), 1, "the write was not deferred");
    assert_eq!(fs.read_all(ino).unwrap(), page);
}

#[test]
fn syncing_the_file_places_it_and_a_remount_finds_it() {
    let (fs, dev, ino) = with_file();
    let page = vec![0xA5u8; BLKSIZE];
    fs.write(ino, 0, &page).unwrap();
    fs.sync_file(ino, false).unwrap();
    assert_eq!(fs.volume.lock().dirty_data_pages(ino), 0, "the sync left the page pending");
    fs.checkpoint().unwrap();
    let again = remount(&dev);
    assert_eq!(again.read_all(ino).unwrap(), page);
}

#[test]
fn swapfile_hook_returns_the_pinned_f2fs_block_view() {
    let (fs, _dev, ino) = with_file();
    let page = vec![0x5Cu8; BLKSIZE];
    let sec = u64::from(fs.volume.lock().blks_per_sec());
    fs.volume.lock().set_pin_file(ino, 1).unwrap();
    fs.volume.lock().expand_pinned(ino, 0, sec * BLKSIZE as u64).unwrap();
    assert_eq!(fs.write(ino, 0, &page).unwrap(), BLKSIZE);
    fs.sync_file(ino, false).unwrap();
    let file = fs.root_inode().unwrap().lookup("f").unwrap();
    let erased = file.swapfile_backing().unwrap().expect("f2fs owns swap activation");
    let backing = erased.downcast::<pmm::swap::SwapFileBacking>()
        .expect("the VFS hook uses the shared PMM backing ABI");
    let mut request = BlockRequest::new_read(0, 1, BLKSIZE as u32);
    backing.device.submit_sync(&mut request).unwrap();
    assert_eq!(request.buffer, page);
    assert!(backing.name.starts_with("f2fs:"));
}

#[test]
fn the_machines_flusher_places_this_mounts_pages() {
    // The proof that the mapping's own writeback target reaches this mount.
    // It is what the flusher and page reclaim use, and it is the only path
    // that does not start inside this filesystem — an unplaced page with no
    // way back is one the machine can neither write nor evict.
    let (fs, _dev, ino) = with_file();
    fs.write(ino, 0, &vec![0xA5u8; BLKSIZE]).unwrap();
    assert_eq!(fs.volume.lock().dirty_data_pages(ino), 1);
    // Far enough ahead that every dirty mapping on the machine has expired,
    // which is the condition the flusher writes back under.
    block::pagecache::flush_pass(u64::MAX);
    assert_eq!(fs.volume.lock().dirty_data_pages(ino), 0,
               "the flusher could not reach this mount");
}

/// REPRODUCTION probe for the unexplained one-off failure of
/// `syncing_the_file_places_it_and_a_remount_finds_it`: the machine's flusher
/// is PROCESS-WIDE, so a sibling test calling `flush_pass` places the pages of
/// every mount alive at that moment, including this one's, at a point this test
/// did not choose.
#[test]
fn a_page_placed_by_the_machines_flusher_still_survives_this_mounts_checkpoint() {
    let (fs, dev, ino) = with_file();
    let page = vec![0xA5u8; BLKSIZE];
    fs.write(ino, 0, &page).unwrap();
    // What a sibling test does to its own mount, which reaches this one too.
    block::pagecache::flush_pass(u64::MAX);
    assert_eq!(fs.volume.lock().dirty_data_pages(ino), 0, "the flusher did not reach this mount");
    fs.sync_file(ino, false).unwrap();
    fs.checkpoint().unwrap();
    let again = remount(&dev);
    assert_eq!(again.read_all(ino).unwrap(), page,
               "a page the machine's flusher placed did not survive the checkpoint");
}

