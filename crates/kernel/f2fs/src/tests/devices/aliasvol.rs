//! An aliasing file on a MOUNTED volume: which member it names, whether the
//! inode is handed out at all, and what the command that asks answers.
//!
//! The unit tests beside this one drive the resolution over a table with no
//! volume. What they cannot show is that anything CONSULTS it — an inode whose
//! extent matches no member has to be refused where inodes are read, and the
//! command has to answer off the file rather than off a constant.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::devices::{DeviceSet, DevTable};
use crate::flags::{F2FS_DEVICE_ALIAS_FL, FEATURE_DEVICE_ALIAS, PIN_FILE};
use crate::ioctl::entry::{handle, Answer};
use crate::ioctl::perm::Ctx;
use crate::ioctl::req::Extra;
use crate::ioctl::uapi::{GET_DEV_ALIAS_FILE, SET_PIN_FILE};
use crate::opts::Options;
use crate::test_image::{self as image, spread, ROOT_INO};
use crate::uapi::{I_EXT_BLK, I_EXT_FOFS, I_EXT_LEN, SUPER_OFFSET, SUPER_SIZE};
use crate::volume::Volume;

const SPLIT: [(&str, u32); 2] = [("/dev/a", 8), ("/dev/b", 7)];
const ALIAS_INO: u32 = 9;
const PLAIN_INO: u32 = 10;

fn put32(b: &mut [u8], at: usize, v: u32) { b[at..at + 4].copy_from_slice(&v.to_le_bytes()); }

fn root_ctx() -> Ctx {
    Ctx {
        cap_sys_admin: true, fmode_read: true, fmode_write: true, o_direct: false,
        owner_or_capable: true, mnt_writable: true, writecount: 1, dirty_pages: 0,
        mmapped: false, dst: crate::ioctl::DstFd::Unusable,
    }
}

/// The member spans of the split this file uses, read off a finished image.
fn table() -> DevTable {
    let bytes = image::Builder::new().devices(&SPLIT).finish();
    let sb = crate::sb::parse(&bytes[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE]).expect("parses");
    DevTable::scan(&sb)
}

/// A spread volume carrying one aliasing inode whose extent is `blk..blk+len`.
fn volume(blk: u32, len: u32, pinned: bool) -> Result<Volume<spread::Spread>, Errno> {
    let mut b = image::with_root();
    b.feature |= FEATURE_DEVICE_ALIAS;
    let mut s = image::nodes::Spec::file(ALIAS_INO);
    s.flags |= F2FS_DEVICE_ALIAS_FL;
    if pinned { s.inline |= PIN_FILE; }
    image::nodes::add_sparse_with(&mut b, s, &[]);
    // An ordinary pinned file beside it, so every refusal below can be shown
    // to be the alias's rather than the command's.
    let mut plain = image::nodes::Spec::file(PLAIN_INO);
    plain.inline |= PIN_FILE;
    image::nodes::add_sparse_with(&mut b, plain, &[]);
    image::nodes::patch_inode(&mut b, ALIAS_INO, |blk_bytes| {
        put32(blk_bytes, I_EXT_FOFS, 0);
        put32(blk_bytes, I_EXT_BLK, blk);
        put32(blk_bytes, I_EXT_LEN, len);
    });
    let b = b.devices(&SPLIT);
    let (media, t) = spread::members(b);
    let set = DeviceSet::new(media, t)?;
    Volume::mount_devices(set, Options::defaults(), true, &[]).map(|v| *v)
}

/// The span of member `i`, as an extent.
fn span(i: usize) -> (u32, u32) {
    let t = table();
    let d = t.get(i).unwrap().clone();
    (d.start_blk, d.end_blk - d.start_blk + 1)
}

fn send(v: &mut Volume<spread::Spread>, ino: u32, cmd: u32, payload: &[u8])
    -> Result<Answer, Errno> {
    handle(v, ino, cmd, payload, &Extra::default(), &root_ctx())
}

fn payload_of(a: &Answer) -> Vec<u8> {
    match a {
        Answer::Done(r) => r.payload.clone().expect("a payload"),
        Answer::NotBuilt(u) => match *u {},
    }
}

/// The whole point: the command answers the FILE, not a constant.
#[test]
fn the_command_says_yes_for_a_file_that_stands_for_a_member() {
    let (blk, len) = span(1);
    let mut v = volume(blk, len, true).expect("mounts");
    let a = send(&mut v, ALIAS_INO, GET_DEV_ALIAS_FILE, &[]).unwrap();
    assert_eq!(payload_of(&a), 1u32.to_le_bytes());
    // And no for an ordinary file on the same volume.
    let b = send(&mut v, ROOT_INO, GET_DEV_ALIAS_FILE, &[]).unwrap();
    assert_eq!(payload_of(&b), 0u32.to_le_bytes());
}

/// An extent that is not a member's whole span describes blocks that are not
/// a device, so the inode is not handed out at all.
#[test]
fn an_alias_of_nothing_is_refused_when_the_inode_is_read() {
    let (blk, len) = span(1);
    let v = volume(blk, len - 1, true).expect("mounts");
    assert_eq!(v.read_inode(ALIAS_INO), Err(Errno::Eio));
    // The volume itself still mounts and its other inodes still read, so the
    // refusal is of the one file rather than of the volume.
    assert!(v.read_inode(ROOT_INO).is_ok());
}

/// Member zero holds the metadata; aliasing it would hand away the superblock.
#[test]
fn an_alias_of_the_metadata_member_is_refused() {
    let (blk, len) = span(0);
    let v = volume(blk, len, true).expect("mounts");
    assert_eq!(v.read_inode(ALIAS_INO), Err(Errno::Eio));
}

/// An unpinned alias would be moved by the cleaner; the flag check catches it
/// before the extent is ever consulted.
#[test]
fn an_unpinned_alias_is_refused() {
    let (blk, len) = span(1);
    let v = volume(blk, len, false).expect("mounts");
    assert_eq!(v.read_inode(ALIAS_INO), Err(Errno::Eio));
}

/// Unpinning an alias would leave a file whose blocks may move while
/// something outside the filesystem still addresses them.
#[test]
fn an_alias_cannot_be_unpinned() {
    let (blk, len) = span(1);
    let mut v = volume(blk, len, true).expect("mounts");
    assert_eq!(send(&mut v, ALIAS_INO, SET_PIN_FILE, &0u32.to_le_bytes()).map(|_| ()),
               Err(Errno::Eopnotsupp));
    // An ordinary pinned file may be, so the refusal is the alias's and not
    // the command's.
    send(&mut v, PLAIN_INO, SET_PIN_FILE, &0u32.to_le_bytes()).expect("an ordinary file unpins");
}
