//! Reading file bytes: whole, partial, multi-block, and the sparse hole that
//! must never be fetched from the medium.

use alloc::vec::Vec;

use crate::opts::Options;
use crate::test_image::Builder;
use crate::volume::Volume;

#[test]
fn a_whole_small_file_reads_back_exactly() {
    let img = Builder::new().file("a", b"hello, squashfs").build();
    let vol = Volume::mount_with(img, Options::defaults()).unwrap();
    let root = vol.read_inode(vol.root_reference()).unwrap();
    let hit = vol.lookup(&root, "a").unwrap();
    let node = vol.read_inode(hit.reference).unwrap();
    assert_eq!(vol.read_whole(&node).unwrap(), b"hello, squashfs");
}

#[test]
fn a_file_spanning_several_blocks_reads_back_exactly() {
    // Three whole blocks worth, plus a short tail — no fragment, so the
    // tail is just a smaller final data block.
    let bs = 4096u32;
    let data_builder = Builder::new().block_size(bs);
    let mut data = Vec::new();
    for i in 0..(bs as usize * 3 + 17) { data.push((i % 251) as u8); }
    let img = data_builder.file("big", &data).build();
    let vol = Volume::mount_with(img, Options::defaults()).unwrap();
    let root = vol.read_inode(vol.root_reference()).unwrap();
    let hit = vol.lookup(&root, "big").unwrap();
    let node = vol.read_inode(hit.reference).unwrap();
    assert_eq!(vol.read_whole(&node).unwrap(), data);
}

#[test]
fn a_partial_read_at_an_offset_returns_the_right_slice() {
    let img = Builder::new().file("a", b"0123456789").build();
    let vol = Volume::mount_with(img, Options::defaults()).unwrap();
    let root = vol.read_inode(vol.root_reference()).unwrap();
    let hit = vol.lookup(&root, "a").unwrap();
    let node = vol.read_inode(hit.reference).unwrap();
    let mut buf = [0u8; 4];
    let n = vol.read_file(&node, 3, &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(&buf, b"3456");
}

#[test]
fn a_read_past_the_end_produces_nothing() {
    let img = Builder::new().file("a", b"0123456789").build();
    let vol = Volume::mount_with(img, Options::defaults()).unwrap();
    let root = vol.read_inode(vol.root_reference()).unwrap();
    let hit = vol.lookup(&root, "a").unwrap();
    let node = vol.read_inode(hit.reference).unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(vol.read_file(&node, 10, &mut buf).unwrap(), 0);
}

/// A sparse block is never fetched — reading one produces zero bytes without
/// the medium holding any bytes for it at all.
#[test]
fn a_sparse_hole_reads_as_zeroes() {
    let bs = 4096u32;
    let img = Builder::new().block_size(bs).hole_file("hole", u64::from(bs) * 2).build();
    let vol = Volume::mount_with(img, Options::defaults()).unwrap();
    let root = vol.read_inode(vol.root_reference()).unwrap();
    let hit = vol.lookup(&root, "hole").unwrap();
    let node = vol.read_inode(hit.reference).unwrap();
    let got = vol.read_whole(&node).unwrap();
    assert_eq!(got.len(), (bs as usize) * 2);
    assert!(got.iter().all(|b| *b == 0));
}

#[test]
fn an_empty_file_reads_back_empty() {
    let img = Builder::new().file("empty", b"").build();
    let vol = Volume::mount_with(img, Options::defaults()).unwrap();
    let root = vol.read_inode(vol.root_reference()).unwrap();
    let hit = vol.lookup(&root, "empty").unwrap();
    let node = vol.read_inode(hit.reference).unwrap();
    assert!(vol.read_whole(&node).unwrap().is_empty());
}
