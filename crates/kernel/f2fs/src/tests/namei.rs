//! Creating, removing and renaming names, proved by REMOUNTING.
//!
//! Almost every test here writes, checkpoints, and then mounts the image
//! again from its bytes. A change that only reached memory passes an in-mount
//! assertion and fails here, which is the whole difference between a
//! filesystem and a cache.

use super::*;
use crate::mode::{S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFREG};
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 500);

fn spec(mode: u16) -> NewInode {
    NewInode { mode, uid: 1000, gid: 1000, rdev: 0, now: NOW }
}

/// A writable volume with an empty root.
fn vol() -> Volume<MemImage> { test_image::with_root().mount_rw().unwrap() }

/// Commit, then mount the same bytes again — the only proof that a change
/// reached the medium.
fn remount(v: Volume<MemImage>) -> Volume<MemImage> {
    let mut v = v;
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// Look a name up from the root. # C: O(depth)
fn find(v: &Volume<MemImage>, name: &[u8]) -> Result<crate::DirEntry, Errno> {
    let root = v.root()?;
    v.lookup(&root, ROOT_INO, name)
}

#[test]
fn a_created_file_is_found_in_the_same_mount() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"hello", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(find(&v, b"hello").unwrap().ino, ino);
}

#[test]
fn a_created_file_survives_a_remount() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"hello", &spec(S_IFREG | 0o644), None).unwrap();
    let v = remount(v);
    let hit = find(&v, b"hello").unwrap();
    assert_eq!(hit.ino, ino);
    assert_eq!(hit.file_type, FT_REG_FILE);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(inode.mode, S_IFREG | 0o644);
    assert_eq!(inode.uid, 1000);
    assert_eq!(inode.links, 1);
    assert_eq!(inode.size, 0);
    assert_eq!(inode.mtime, NOW);
}

#[test]
fn a_created_file_carries_its_creation_time_and_parent() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o600), None).unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(inode.crtime, Some(NOW));
    assert_eq!(inode.pino, ROOT_INO);
}

#[test]
fn a_second_name_the_same_is_refused() {
    let mut v = vol();
    v.create(ROOT_INO, b"dup", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(v.create(ROOT_INO, b"dup", &spec(S_IFREG | 0o644), None).err(),
               Some(Errno::Eexist));
}

#[test]
fn a_read_only_mount_refuses_to_create() {
    let mut v = test_image::with_root().mount().unwrap();
    assert_eq!(v.create(ROOT_INO, b"x", &spec(S_IFREG | 0o644), None).err(), Some(Errno::Erofs));
}

#[test]
fn creating_under_something_that_is_not_a_directory_is_refused() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(v.create(ino, b"x", &spec(S_IFREG | 0o644), None).err(), Some(Errno::Enotdir));
}

#[test]
fn many_names_all_survive_a_remount() {
    // Enough to overflow the root's inline area and force it into blocks,
    // which is where the conversion and the bucket arithmetic get exercised.
    let mut v = vol();
    let names: Vec<Vec<u8>> =
        (0..90u32).map(|i| alloc::format!("file-{i:04}").into_bytes()).collect();
    for n in &names { v.create(ROOT_INO, n, &spec(S_IFREG | 0o644), None).unwrap(); }
    let v = remount(v);
    let root = v.root().unwrap();
    assert!(!root.inline_dentry(), "the root should have converted to blocks");
    for n in &names {
        assert!(find(&v, n).is_ok(), "lost {:?}", core::str::from_utf8(n));
    }
    assert_eq!(v.read_dir(&root, ROOT_INO).unwrap().len(), names.len() + 2);
}

#[test]
fn a_short_name_reusing_a_long_names_slots_does_not_resurrect_it() {
    // Deleting a long name frees the continuation slot it held. A short name
    // placed there must leave the records of every slot it does NOT occupy
    // reading as empty, or the listing reports a name nobody created.
    let mut v = vol();
    v.create(ROOT_INO, b"a-long-name-here", &spec(S_IFREG | 0o644), None).unwrap();
    v.remove(ROOT_INO, b"a-long-name-here", false, NOW).unwrap();
    v.create(ROOT_INO, b"s", &spec(S_IFREG | 0o644), None).unwrap();
    let v = remount(v);
    let root = v.root().unwrap();
    let names: Vec<Vec<u8>> =
        v.read_dir(&root, ROOT_INO).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, alloc::vec![b".".to_vec(), b"..".to_vec(), b"s".to_vec()]);
}

#[test]
fn a_long_name_placed_over_stale_slots_lists_once() {
    let mut v = vol();
    for n in [b"aaaaaaaaaaa".as_slice(), b"bbbbbbbbbbb", b"ccccccccccc"] {
        v.create(ROOT_INO, n, &spec(S_IFREG | 0o644), None).unwrap();
    }
    v.remove(ROOT_INO, b"bbbbbbbbbbb", false, NOW).unwrap();
    v.create(ROOT_INO, b"dddddddddddddddddddd", &spec(S_IFREG | 0o644), None).unwrap();
    let v = remount(v);
    let root = v.root().unwrap();
    let mut names: Vec<Vec<u8>> =
        v.read_dir(&root, ROOT_INO).unwrap().into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names.len(), 5, "{names:?}");
    assert!(names.contains(&b"dddddddddddddddddddd".to_vec()));
    assert!(!names.contains(&b"bbbbbbbbbbb".to_vec()));
}

/// The raw inline dentry area of a directory, and its layout.
fn inline_area(v: &Volume<MemImage>, ino: u32) -> (Vec<u8>, crate::dirent::Layout) {
    let (inode, node) = v.read_inode_ref(ino).unwrap();
    let (at, len) = inode.inline_data_span();
    (node.block[at..at + len].to_vec(), crate::dirent::Layout::inline(len))
}

#[test]
fn an_inserted_long_name_leaves_its_continuation_record_zeroed_on_the_medium() {
    // Deleting an entry clears only its bitmap bits — the record bytes stay,
    // exactly as the format leaves them. So a long name placed over a slot a
    // short name used must zero that slot's record itself, or the medium
    // carries a record for a name nobody created. Our own walker steps by the
    // slot COUNT and would never read it; a checker, or another
    // implementation that scans slot by slot, would.
    let mut v = vol();
    v.create(ROOT_INO, b"xx", &spec(S_IFREG | 0o644), None).unwrap();
    v.create(ROOT_INO, b"yy", &spec(S_IFREG | 0o644), None).unwrap();
    let (area, l) = inline_area(&v, ROOT_INO);
    // `.` and `..` hold slots 0 and 1, so the two names took 2 and 3.
    let victim = 3usize;
    let at = l.dentry_off(victim);
    assert_ne!(&area[at..at + SIZE_OF_DIR_ENTRY], &vec![0u8; SIZE_OF_DIR_ENTRY][..],
               "fixture did not put a record where the test needs one");
    v.remove(ROOT_INO, b"xx", false, NOW).unwrap();
    v.remove(ROOT_INO, b"yy", false, NOW).unwrap();
    // A name needing two slots now lands on slot 2 and covers slot 3.
    v.create(ROOT_INO, b"123456789", &spec(S_IFREG | 0o644), None).unwrap();
    let (area, l) = inline_area(&v, ROOT_INO);
    let at = l.dentry_off(victim);
    assert_eq!(&area[at..at + SIZE_OF_DIR_ENTRY], &vec![0u8; SIZE_OF_DIR_ENTRY][..],
               "the continuation slot still carries the deleted entry's record");
}

#[test]
fn deleting_an_entry_clears_only_its_bitmap_bits() {
    // The record is left alone, which is what the format does.
    let mut v = vol();
    v.create(ROOT_INO, b"zz", &spec(S_IFREG | 0o644), None).unwrap();
    let (before, l) = inline_area(&v, ROOT_INO);
    let at = l.dentry_off(2);
    let record = before[at..at + SIZE_OF_DIR_ENTRY].to_vec();
    v.remove(ROOT_INO, b"zz", false, NOW).unwrap();
    let (after, _) = inline_area(&v, ROOT_INO);
    assert_eq!(&after[at..at + SIZE_OF_DIR_ENTRY], &record[..]);
    assert!(!crate::dirent::layout::is_used(&after, 2), "the slot is still marked used");
}

#[test]
fn a_directory_is_created_with_its_own_two_entries() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"sub", &spec(S_IFDIR | 0o755), None).unwrap();
    let v = remount(v);
    let dir = v.read_inode(ino).unwrap();
    assert_eq!(crate::mode::file_type(dir.mode), vfs::FileType::Directory);
    assert_eq!(v.lookup(&dir, ino, b".").unwrap().ino, ino);
    assert_eq!(v.lookup(&dir, ino, b"..").unwrap().ino, ROOT_INO);
    assert!(v.dir_is_empty(&dir, ino).unwrap());
}

#[test]
fn creating_a_directory_raises_the_parents_link_count() {
    let mut v = vol();
    let before = v.root().unwrap().links;
    v.create(ROOT_INO, b"sub", &spec(S_IFDIR | 0o755), None).unwrap();
    let v = remount(v);
    assert_eq!(v.root().unwrap().links, before + 1);
}

#[test]
fn a_nested_directory_tree_survives_a_remount() {
    let mut v = vol();
    let a = v.create(ROOT_INO, b"a", &spec(S_IFDIR | 0o755), None).unwrap();
    let b = v.create(a, b"b", &spec(S_IFDIR | 0o755), None).unwrap();
    let c = v.create(b, b"c.txt", &spec(S_IFREG | 0o644), None).unwrap();
    let v = remount(v);
    let a_in = v.read_inode(a).unwrap();
    let b_in = v.read_inode(v.lookup(&a_in, a, b"b").unwrap().ino).unwrap();
    assert_eq!(v.lookup(&b_in, b, b"c.txt").unwrap().ino, c);
}

#[test]
fn a_symbolic_link_reads_back_its_target() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"l", &spec(S_IFLNK | 0o777), Some(b"/usr/share/x")).unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(crate::mode::file_type(inode.mode), vfs::FileType::Symlink);
    assert_eq!(v.read_link(&inode, ino).unwrap(), b"/usr/share/x".to_vec());
    assert_eq!(find(&v, b"l").unwrap().file_type, FT_SYMLINK);
}

#[test]
fn a_long_symbolic_link_target_lands_in_a_block_and_still_reads_back() {
    let target = alloc::format!("/{}", "d/".repeat(2000));
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"l", &spec(S_IFLNK | 0o777), Some(target.as_bytes())).unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert!(!inode.inline_data());
    assert_eq!(v.read_link(&inode, ino).unwrap(), target.as_bytes().to_vec());
}

#[test]
fn a_device_node_keeps_its_device_number() {
    let mut v = vol();
    let want = vfs::getattr::encode_dev(10, 300);
    let mut s = spec(S_IFCHR | 0o600);
    s.rdev = want;
    let ino = v.create(ROOT_INO, b"dev", &s, None).unwrap();
    let v = remount(v);
    let (inode, node) = v.read_inode_ref(ino).unwrap();
    assert!(crate::mode::has_rdev(inode.mode));
    assert_eq!(crate::mode::rdev(inode.addr_base(), &node.block), want);
    assert_eq!(find(&v, b"dev").unwrap().file_type, FT_CHRDEV);
}

#[test]
fn a_pipe_is_created_with_no_device_number() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"p", &spec(S_IFIFO | 0o600), None).unwrap();
    let v = remount(v);
    assert_eq!(crate::mode::file_type(v.read_inode(ino).unwrap().mode), vfs::FileType::Fifo);
    assert_eq!(find(&v, b"p").unwrap().file_type, FT_FIFO);
}

#[test]
fn an_unlinked_file_is_gone_after_a_remount() {
    let mut v = vol();
    v.create(ROOT_INO, b"gone", &spec(S_IFREG | 0o644), None).unwrap();
    v.remove(ROOT_INO, b"gone", false, NOW).unwrap();
    let v = remount(v);
    assert_eq!(find(&v, b"gone").err(), Some(Errno::Enoent));
}

#[test]
fn unlinking_frees_the_inodes_blocks() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"big", &spec(S_IFREG | 0o644), None).unwrap();
    v.write_file(ino, 0, &vec![7u8; 3 * BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    v.commit().unwrap();
    let used = v.space().free;
    v.remove(ROOT_INO, b"big", false, NOW).unwrap();
    // The name going parks the inode; the EVICTION is what frees it and
    // gives back what it held. The two are separate events, and a descriptor
    // may sit between them.
    v.evict_inode(ino).unwrap();
    v.commit().unwrap();
    assert!(v.space().free > used, "the eviction freed nothing");
}

#[test]
fn unlinking_a_directory_with_unlink_is_refused() {
    let mut v = vol();
    v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    assert_eq!(v.remove(ROOT_INO, b"d", false, NOW).err(), Some(Errno::Eisdir));
}

#[test]
fn removing_a_file_with_rmdir_is_refused() {
    let mut v = vol();
    v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(v.remove(ROOT_INO, b"f", true, NOW).err(), Some(Errno::Enotdir));
}

#[test]
fn removing_a_directory_that_holds_a_name_is_refused() {
    let mut v = vol();
    let d = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    v.create(d, b"x", &spec(S_IFREG | 0o644), None).unwrap();
    assert_eq!(v.remove(ROOT_INO, b"d", true, NOW).err(), Some(Errno::Enotempty));
}

#[test]
fn removing_an_empty_directory_lowers_the_parents_link_count() {
    let mut v = vol();
    let before = v.root().unwrap().links;
    v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    v.remove(ROOT_INO, b"d", true, NOW).unwrap();
    let v = remount(v);
    assert_eq!(v.root().unwrap().links, before);
    assert_eq!(find(&v, b"d").err(), Some(Errno::Enoent));
}

#[test]
fn the_two_dot_names_cannot_be_removed() {
    let mut v = vol();
    assert_eq!(v.remove(ROOT_INO, b".", true, NOW).err(), Some(Errno::Einval));
    assert_eq!(v.remove(ROOT_INO, b"..", true, NOW).err(), Some(Errno::Einval));
}

#[test]
fn a_second_name_shares_one_inode_and_raises_the_link_count() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"one", &spec(S_IFREG | 0o644), None).unwrap();
    v.write_file(ino, 0, b"shared").unwrap();
    v.sync_data().unwrap();
    v.link(ROOT_INO, b"two", ino, NOW).unwrap();
    let v = remount(v);
    assert_eq!(find(&v, b"two").unwrap().ino, ino);
    assert_eq!(v.read_inode(ino).unwrap().links, 2);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.read_whole(&inode, ino).unwrap(), b"shared".to_vec());
}

#[test]
fn removing_one_of_two_names_keeps_the_file() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"one", &spec(S_IFREG | 0o644), None).unwrap();
    v.write_file(ino, 0, b"kept").unwrap();
    v.sync_data().unwrap();
    v.link(ROOT_INO, b"two", ino, NOW).unwrap();
    v.remove(ROOT_INO, b"one", false, NOW).unwrap();
    let v = remount(v);
    assert_eq!(find(&v, b"one").err(), Some(Errno::Enoent));
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(inode.links, 1);
    assert_eq!(v.read_whole(&inode, ino).unwrap(), b"kept".to_vec());
}

#[test]
fn a_directory_cannot_be_given_a_second_name() {
    let mut v = vol();
    let d = v.create(ROOT_INO, b"d", &spec(S_IFDIR | 0o755), None).unwrap();
    assert_eq!(v.link(ROOT_INO, b"d2", d, NOW).err(), Some(Errno::Eperm));
}

#[test]
fn permission_bits_and_owner_survive_a_remount() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    v.set_attr(ino, Some(0o4711), Some((7, 8)), NOW).unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(crate::mode::perm(inode.mode), 0o4711);
    assert_eq!(crate::mode::file_type(inode.mode), vfs::FileType::Regular);
    assert_eq!((inode.uid, inode.gid), (7, 8));
}

#[test]
fn stored_times_survive_a_remount() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(S_IFREG | 0o644), None).unwrap();
    v.set_times(ino, (111, 1), (222, 2)).unwrap();
    let v = remount(v);
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(inode.atime, (111, 1));
    assert_eq!(inode.mtime, (222, 2));
}

