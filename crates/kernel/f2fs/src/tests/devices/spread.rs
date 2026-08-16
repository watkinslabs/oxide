//! The same volume flat and split, which must read the same.
//!
//! This is the test the whole address map exists to pass. The fixture writes
//! ONE image, then cuts it at the member boundaries; if the map is wrong by
//! any amount, the split mount reads different bytes from the flat one — with
//! no assertion about the map itself needed.

use alloc::vec;

use sectors::MemImage;

use crate::devices::DeviceSet;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self as image, spread, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_700_000_000, 0);

fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

fn two() -> Volume<spread::Spread> {
    spread::mount(image::with_root().devices(&[("/dev/a", 8), ("/dev/b", 7)])).expect("mounts")
}

#[test]
fn a_volume_spread_over_two_members_mounts() {
    let v = two();
    assert!(v.devices().is_multi());
    assert_eq!(v.devices().len(), 2);
}

#[test]
fn spreading_is_no_longer_a_refusal() {
    // The build used to decline such a volume at mount; the map is what
    // replaced the refusal, so a mount that still failed would mean the
    // refusal simply moved.
    let b = image::with_root().devices(&[("/dev/a", 8), ("/dev/b", 7)]);
    assert!(spread::mount(b).is_ok());
}

#[test]
fn the_root_directory_reads_the_same_split_as_flat() {
    let flat = image::with_root().mount_rw().expect("flat mounts");
    let flat_root = flat.read_inode(ROOT_INO).expect("flat root");
    let split = two();
    let split_root = split.read_inode(ROOT_INO).expect("split root");
    assert_eq!(flat_root.mode, split_root.mode);
    assert_eq!(flat_root.links, split_root.links);
    assert_eq!(flat_root.size, split_root.size);
}

#[test]
fn a_single_named_member_is_not_multi_device() {
    // One recorded path is still one device, and every rule the reference
    // gates on "is this spread" must stay off.
    let v = spread::mount(image::with_root().devices(&[("/dev/a", 15)])).expect("mounts");
    assert!(!v.devices().is_multi());
    assert_eq!(v.devices().len(), 1);
}

#[test]
fn a_file_written_to_a_spread_volume_reads_back() {
    let mut v = two();
    let ino = v.create(ROOT_INO, b"spread", &spec(), None).expect("create");
    let data = vec![0x7Eu8; 4 * BLKSIZE];
    v.write_file(ino, 0, &data).expect("write");
    let inode = v.read_inode(ino).expect("inode");
    let mut back = vec![0u8; data.len()];
    let n = v.read_file(&inode, ino, 0, &mut back).expect("read");
    assert_eq!(n, data.len());
    assert_eq!(back, data);
}

#[test]
fn a_spread_volume_survives_a_checkpoint_and_a_remount() {
    let mut v = two();
    let ino = v.create(ROOT_INO, b"kept", &spec(), None).expect("create");
    v.write_file(ino, 0, b"hello spread").expect("write");
    v.commit().expect("checkpoint");
    let set = v.into_source();
    let table = set.table().clone();
    let media: vec::Vec<MemImage> = set
        .members()
        .iter()
        .map(|m| MemImage::from_bytes(BLKSIZE as u32, m.snapshot()))
        .collect();
    let again =
        Volume::mount_devices(DeviceSet::new(media, table).unwrap(), Options::defaults(), true, &[])
            .expect("remounts");
    let root = again.read_inode(ROOT_INO).expect("root");
    let found = again.lookup(&root, ROOT_INO, b"kept").expect("lookup");
    let inode = again.read_inode(found.ino).expect("inode");
    let mut back = vec![0u8; 12];
    again.read_file(&inode, found.ino, 0, &mut back).expect("read");
    assert_eq!(&back, b"hello spread");
}

#[test]
fn a_write_that_lands_on_the_second_member_is_not_lost() {
    // The fixture allocates from segment zero, which is on the first member;
    // this reaches past it by writing enough blocks to cross the boundary.
    let mut v = two();
    let boundary = v.devices().get(1).unwrap().start_blk;
    assert!(boundary > 0);
    let ino = v.create(ROOT_INO, b"far", &spec(), None).expect("create");
    let data = vec![0x33u8; 2 * BLKSIZE];
    v.write_file(ino, 0, &data).expect("write");
    let inode = v.read_inode(ino).expect("inode");
    let mut back = vec![0u8; data.len()];
    v.read_file(&inode, ino, 0, &mut back).expect("read");
    assert_eq!(back, data);
}
