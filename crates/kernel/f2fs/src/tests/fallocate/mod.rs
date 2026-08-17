//! `fallocate`, one mode at a time.
//!
//! Module manifest:
//! - `gate`:     the refusal ladder, with no volume behind it.
//! - `punch`:    holes punched, and what the remounted bytes say.
//! - `zero`:     ranges zeroed, with and without keeping the size.
//! - `collapse`: gaps closed.
//! - `insert`:   gaps opened.
//! - `expand`:   plain allocation, pinned and not.
//! - `entry`:    the one entry point's dispatch and its refusals.

use super::*;

mod entry;
mod punch;
mod zero;
mod collapse;
mod insert;
mod expand;

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;

pub const NOW: (u64, u32) = (1_800_000_000, 7);

pub fn spec() -> NewInode { NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW } }

/// A volume with one file of `blocks` blocks, each filled with its own index.
pub fn with_file(blocks: usize) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().expect("mount");
    let ino = v.create(ROOT_INO, b"f", &spec(), None).expect("create");
    let body = pattern(blocks);
    v.write_file(ino, 0, &body).expect("write");
    v.commit().expect("commit");
    (v, ino)
}

/// `blocks` blocks, block `i` filled with a byte that is never zero.
///
/// Never zero because zero is what a hole reads as: a pattern that put a zero
/// block in the file would make a block LOST look exactly like a block moved
/// correctly, which is the one thing these tests exist to tell apart.
pub fn pattern(blocks: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..blocks { out.extend(vec![byte_for(i); BLKSIZE]); }
    out
}

/// The byte block `i` is filled with. # C: O(1)
pub fn byte_for(i: usize) -> u8 { (i % 255) as u8 + 1 }

/// The file's bytes as the MEDIUM holds them: written out, mounted again, and
/// read back. A change that only reached memory is invisible here, which is
/// what makes this the proof rather than a read through the same mount.
pub fn remounted(v: Volume<MemImage>, ino: u32, len: usize) -> (Volume<MemImage>, Vec<u8>) {
    let bytes = v.into_source().snapshot();
    let img = MemImage::from_bytes(BLKSIZE as u32, bytes);
    let v = Volume::mount_with(img, Options::defaults(), true).expect("remount");
    let mut out = vec![0u8; len];
    let inode = v.read_inode(ino).expect("inode");
    let got = v.read_file(&inode, ino, 0, &mut out).expect("read");
    out.truncate(got);
    (v, out)
}

/// Commit, remount, and hand back the file's whole contents.
pub fn settled(mut v: Volume<MemImage>, ino: u32) -> (Volume<MemImage>, Vec<u8>) {
    v.commit().expect("commit");
    let size = v.read_inode(ino).expect("inode").size as usize;
    remounted(v, ino, size)
}
