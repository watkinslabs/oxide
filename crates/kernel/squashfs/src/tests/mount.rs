//! Mounting a real fixture through [`Volume::mount_with`], and the medium-vs-
//! image-length refusal that only a live source (not a bare byte slice) can
//! prove.

use crate::opts::Options;
use crate::superblock::SuperError;
use crate::test_image::Builder;
use crate::volume::{MountError, Volume};

use sectors::MemImage;

#[test]
fn a_built_fixture_mounts() {
    let img = Builder::new().file("a", b"hello, squashfs").build();
    let vol = Volume::mount_with(img, Options::defaults()).unwrap();
    assert_eq!(vol.superblock().major, 4);
    assert!(!vol.has_xattrs());
}

#[test]
fn root_reference_resolves_to_the_root_directory() {
    let img = Builder::new().file("a", b"x").build();
    let vol = Volume::mount_with(img, Options::defaults()).unwrap();
    let root = vol.read_inode(vol.root_reference()).unwrap();
    assert_eq!(root.ino, crate::test_image::ROOT_INO);
}

/// The image claims more bytes than the medium can actually produce — the
/// superblock's own `bytes_used` check only catches this against the
/// STATED length; a live source is what proves the medium itself is short.
#[test]
fn a_medium_shorter_than_the_image_claims_is_refused() {
    let bytes = Builder::new().file("a", b"hello").build_bytes();
    let short = MemImage::from_bytes(1, bytes[..bytes.len() - 1].to_vec());
    let Err(err) = Volume::mount_with(short, Options::defaults()) else { panic!("mounted") };
    assert_eq!(err, MountError::Truncated);
}

#[test]
fn a_non_squashfs_medium_is_refused_at_the_superblock() {
    let mut bytes = Builder::new().file("a", b"hello").build_bytes();
    bytes[0] = !bytes[0];
    let img = MemImage::from_bytes(1, bytes);
    let Err(err) = Volume::mount_with(img, Options::defaults()) else { panic!("mounted") };
    assert_eq!(err, MountError::Super(SuperError::BadMagic));
}

#[test]
fn empty_root_mounts_and_lists_nothing() {
    let img = Builder::new().build();
    let vol = Volume::mount_with(img, Options::defaults()).unwrap();
    let root = vol.read_inode(vol.root_reference()).unwrap();
    assert!(vol.read_dir(&root).unwrap().is_empty());
}
