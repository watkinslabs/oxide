//! The file mapping, driven against a real volume.
//!
//! Every coherency property is asserted against the MEDIUM rather than
//! against the mapping's own counters. The technique is the one the
//! compressed-block cache's tests use and it is the only one that can fail
//! for the right reason: the image is edited BEHIND the mapping's back, so a
//! read that still returns the old bytes proves the mapping answered, and a
//! read that returns the new ones proves it did not.
//!
//! The load-bearing tests here are the four invalidations. Each one names the
//! single line that makes it pass; removing that line turns the named test
//! red and nothing else in the tree catches it.

use alloc::vec;
use alloc::vec::Vec;

use sectors::{MemImage, SectorSource};
use syscall::errno::Errno;

use crate::filemap::Cache;
use crate::mode::S_IFREG;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::map::Mapped;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 11);

/// A writable volume with one empty regular file, and that file's number.
/// # C: O(1 image)
fn volume() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let ino = v.create(ROOT_INO, b"f", &spec, None).unwrap();
    (v, ino)
}

/// One block of `byte`. # C: O(BLKSIZE)
fn filled(byte: u8) -> Vec<u8> { vec![byte; BLKSIZE] }

/// The whole of `ino`, however long it is. # C: O(file bytes)
fn read_all(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let i = v.read_inode(ino).unwrap();
    v.read_whole(&i, ino).unwrap()
}

/// Overwrite file page `index` of `ino` ON THE MEDIUM, under whatever the
/// mapping holds. Nothing in the filesystem is told, which is the point: a
/// later read that returns `byte` came from the device and one that does not
/// came from the mapping.
/// # C: O(BLKSIZE)
fn poke_page(v: &Volume<MemImage>, ino: u32, index: u64, byte: u8) -> u32 {
    let i = v.read_inode(ino).unwrap();
    let Mapped::At(addr) = v.map_block(&i, ino, index).unwrap() else { panic!("no block") };
    v.source_ref().poke(addr as usize * BLKSIZE, &filled(byte));
    addr
}

#[test]
fn a_second_read_of_a_page_is_served_without_the_medium() {
    let (mut v, ino) = volume();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    // Placed, so the page has an address for the edit below to aim at.
    v.sync_data().unwrap();
    assert_eq!(read_all(&v, ino), filled(0xA1));
    let before = v.data_cache_hits();
    poke_page(&v, ino, 0, 0xB2);
    // The mapping holds the page, so the edit under it is invisible.
    assert_eq!(read_all(&v, ino), filled(0xA1));
    assert!(v.data_cache_hits() > before, "the second read did not come from the mapping");
}

#[test]
fn a_write_drops_the_page_the_read_left_behind() {
    // The per-address invalidation: `note_mapping_change`. Remove the
    // `data_cache.forget` there and this returns the pre-write bytes.
    let (mut v, ino) = volume();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    assert_eq!(read_all(&v, ino), filled(0xA1));
    v.write_file(ino, 0, &filled(0xC3)).unwrap();
    assert_eq!(read_all(&v, ino), filled(0xC3));
}

#[test]
fn a_partial_write_patches_the_page_the_mapping_holds() {
    // A read-modify-write reads its base through the mapping. The patched
    // page must be the CURRENT contents, not a second copy of the offset.
    let (mut v, ino) = volume();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    assert_eq!(read_all(&v, ino), filled(0xA1));
    v.write_file(ino, 4, b"xyz").unwrap();
    let got = read_all(&v, ino);
    assert_eq!(&got[..4], &[0xA1; 4]);
    assert_eq!(&got[4..7], b"xyz");
    assert_eq!(&got[7..], &filled(0xA1)[7..]);
}

#[test]
fn shortening_a_file_drops_the_pages_past_the_new_end() {
    // The range invalidation: `forget_extents_from`, reached by the tail
    // trim. A whole node subtree goes at once there, so the per-address
    // notification never fires for the pages it takes with it and they would
    // stay resident under a file that no longer has those offsets. Remove the
    // `data_cache.forget_from` and the count stays at two.
    let (mut v, ino) = volume();
    let mut two = filled(0xA1);
    two.extend_from_slice(&filled(0xA2));
    v.write_file(ino, 0, &two).unwrap();
    assert_eq!(read_all(&v, ino), two);
    assert_eq!(v.data_cached_pages(), 2);
    v.truncate_file(ino, BLKSIZE as u64).unwrap();
    assert_eq!(v.data_cached_pages(), 1);
    // And the offset that went is a hole, which reads as zeroes rather than
    // as the bytes it used to hold.
    v.truncate_file(ino, 2 * BLKSIZE as u64).unwrap();
    let got = read_all(&v, ino);
    assert_eq!(&got[..BLKSIZE], &filled(0xA1)[..]);
    assert_eq!(&got[BLKSIZE..], &filled(0)[..]);
}

#[test]
fn a_pinned_file_rewritten_where_it_lies_serves_the_new_bytes() {
    // The in-place invalidation: `pinned_write_block`. A pinned block keeps
    // its address, so the mapping-change notification every other writer
    // funnels through never fires — this is the one write in the filesystem
    // that changes a page's contents without changing where it lives. Remove
    // the `data_cache.forget` there and the read returns the pre-write bytes
    // with nothing reporting an error.
    // A file is pinned while it is still empty and its blocks are laid down
    // by the pinned allocator; that is the only way to reach the in-place
    // writer at all.
    let (mut v, ino) = volume();
    v.set_pin_file(ino, 1).unwrap();
    v.expand_pinned(ino, 0, BLKSIZE as u64).unwrap();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    let i = v.read_inode(ino).unwrap();
    let Mapped::At(before) = v.map_block(&i, ino, 0).unwrap() else { panic!("no block") };
    assert_eq!(read_all(&v, ino), filled(0xA1));
    v.write_file(ino, 0, &filled(0xF6)).unwrap();
    let i = v.read_inode(ino).unwrap();
    let Mapped::At(after) = v.map_block(&i, ino, 0).unwrap() else { panic!("no block") };
    assert_eq!(before, after, "the fixture depends on the write being in place");
    assert_eq!(read_all(&v, ino), filled(0xF6));
}

#[test]
fn a_deleted_file_leaves_nothing_under_its_inode_number() {
    // The whole-inode invalidation: `free_inode`. An inode number goes back
    // to the pool the moment its last name and its last open are gone, so a
    // page left filed under it would answer for whatever file takes the id
    // next — and until then it would hold a deleted file's bytes resident.
    // Remove the `data_cache.forget_inode` there and the count stays at one.
    let (mut v, ino) = volume();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    assert_eq!(read_all(&v, ino), filled(0xA1));
    assert_eq!(v.data_cached_pages(), 1);
    v.remove(ROOT_INO, b"f", false, NOW).unwrap();
    assert_eq!(v.data_cached_pages(), 0);
}

#[test]
fn a_reused_inode_number_reads_its_new_file() {
    // The end the invalidation above exists to protect, driven the only way
    // this build recycles an id: the free-id pool hands one back after the
    // checkpoint that retired it, which is a fresh mount away.
    let (mut v, ino) = volume();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    assert_eq!(read_all(&v, ino), filled(0xA1));
    v.remove(ROOT_INO, b"f", false, NOW).unwrap();
    v.commit().unwrap();
    let mut v = Volume::mount_with(v.into_source(), crate::opts::Options::defaults(), true)
        .unwrap();
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let again = v.create(ROOT_INO, b"g", &spec, None).unwrap();
    assert_eq!(again, ino, "the fixture depends on the id being reused");
    v.write_file(again, 0, &filled(0xD4)).unwrap();
    assert_eq!(read_all(&v, again), filled(0xD4));
}

#[test]
fn a_relocated_block_is_still_the_same_page() {
    // Keying by file offset rather than by block address is what makes an
    // out-of-place rewrite of the SAME bytes invisible to the mapping. The
    // address changes and the contents do not, and a reader sees neither.
    let (mut v, ino) = volume();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.sync_data().unwrap();
    let i = v.read_inode(ino).unwrap();
    let Mapped::At(first) = v.map_block(&i, ino, 0).unwrap() else { panic!("no block") };
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.sync_data().unwrap();
    let i = v.read_inode(ino).unwrap();
    let Mapped::At(second) = v.map_block(&i, ino, 0).unwrap() else { panic!("no block") };
    assert_ne!(first, second, "the fixture depends on the write being out of place");
    assert_eq!(read_all(&v, ino), filled(0xA1));
}

#[test]
fn a_hole_is_not_filed_under_the_page_a_later_write_takes() {
    let (mut v, ino) = volume();
    v.write_file(ino, BLKSIZE as u64, &filled(0xA1)).unwrap();
    // Block zero is a hole; reading it must not leave anything behind that
    // survives the write that fills it.
    assert_eq!(&read_all(&v, ino)[..BLKSIZE], &filled(0)[..]);
    v.write_file(ino, 0, &filled(0xE5)).unwrap();
    assert_eq!(&read_all(&v, ino)[..BLKSIZE], &filled(0xE5)[..]);
}

#[test]
fn the_mapping_survives_a_remount_as_an_empty_one() {
    // The mapping is a MOUNT's, not a volume's: nothing about it is on the
    // medium, so the bytes a second mount reads are the medium's own.
    let (mut v, ino) = volume();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    v.commit().unwrap();
    let img = v.into_source();
    let v2 = Volume::mount_with(img, crate::opts::Options::defaults(), false).unwrap();
    assert_eq!(v2.data_cached_pages(), 0);
    assert_eq!(read_all(&v2, ino), filled(0xA1));
}

// --- the cache on its own, where the fetch can be made to do anything ---

#[test]
fn a_fetch_that_fails_reports_its_own_error_and_files_nothing() {
    // The cache speaks one error type and this filesystem speaks another. A
    // boundary that folded the two would report a full volume as a broken
    // disk; the round trip is what keeps the caller's errno.
    let c = Cache::new();
    assert_eq!(c.read(7, 0, || Err(Errno::Enospc)), Err(Errno::Enospc));
    assert_eq!(c.pages(), 0);
    // And the failure left nothing behind, so the next read still fetches.
    assert_eq!(c.read(7, 0, || Ok(filled(0x11))), Ok(filled(0x11)));
    assert_eq!(c.pages(), 1);
}

#[test]
fn a_fetch_of_the_wrong_length_is_refused_rather_than_padded() {
    // A short page filed here would answer a later read with zeroes the file
    // does not have.
    let c = Cache::new();
    assert_eq!(c.read(7, 0, || Ok(vec![0x22u8; 8])), Err(Errno::Eio));
    assert_eq!(c.pages(), 0);
}

#[test]
fn a_page_is_fetched_once_and_then_answered() {
    let c = Cache::new();
    assert_eq!(c.read(7, 3, || Ok(filled(0x33))), Ok(filled(0x33)));
    assert_eq!((c.hits(), c.misses()), (0, 1));
    assert_eq!(c.read(7, 3, || panic!("fetched twice")), Ok(filled(0x33)));
    assert_eq!((c.hits(), c.misses()), (1, 1));
}

#[test]
fn each_forget_drops_exactly_what_it_names() {
    let c = Cache::new();
    for i in 0..4u64 { c.read(7, i, || Ok(filled(0x40 + i as u8))).unwrap(); }
    for i in 0..4u64 { c.read(8, i, || Ok(filled(0x50 + i as u8))).unwrap(); }
    assert_eq!(c.pages(), 8);

    c.forget(7, 1);
    assert_eq!(c.pages(), 7);
    // The neighbours of a forgotten page are untouched.
    assert_eq!(c.read(7, 0, || panic!("dropped a neighbour")), Ok(filled(0x40)));
    assert_eq!(c.read(7, 2, || panic!("dropped a neighbour")), Ok(filled(0x42)));

    c.forget_from(7, 2);
    assert_eq!(c.pages(), 5);
    assert_eq!(c.read(7, 0, || panic!("dropped a page below the cut")), Ok(filled(0x40)));

    // Another inode's pages are another mapping's and are never touched.
    c.forget_inode(7);
    assert_eq!(c.pages(), 4);
    for i in 0..4u64 {
        assert_eq!(c.read(8, i, || panic!("dropped another inode's page")),
                   Ok(filled(0x50 + i as u8)));
    }
}

#[test]
fn erasing_a_files_blocks_takes_their_pages_with_them() {
    // The second in-place writer: a secure erase destroys a block's contents
    // where they lie, so the address does not change and the per-address
    // notification never fires. Remove the `data_cache.forget` in the erase
    // loop and the read after it returns the bytes the erase destroyed.
    let (mut v, ino) = volume();
    v.write_file(ino, 0, &filled(0xA1)).unwrap();
    assert_eq!(read_all(&v, ino), filled(0xA1));
    v.sec_trim_file(ino, 0, BLKSIZE as u64, crate::ioctl::uapi::TRIM_FILE_ZEROOUT).unwrap();
    assert_eq!(read_all(&v, ino), filled(0));
}
