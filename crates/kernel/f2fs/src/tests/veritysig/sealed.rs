//! A real signed file, sealed and read back through the ordinary paths.

use super::fixtures::{unhex, CA_DER, OTHER_CA_DER, OTHER_SIG, SEALED_DIGEST, SEALED_SIG};
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{BLKSIZE, XATTR_INDEX_VERITY};
use crate::verity::signature::Policy;
use crate::verity::uapi::{HASH_ALG_SHA256, XATTR_NAME};
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 7);
const LOG_BS: u8 = 12;
const SALT: &[u8] = b"oxide";

/// Exactly the file the fixture signature was produced over. Any change here
/// changes the measurement and the signature stops matching — which is the
/// point: the signature is over the file, not over the shape of the test.
fn contents() -> Vec<u8> { (0..3 * BLKSIZE).map(|i| (i % 251) as u8).collect() }

fn with_file() -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let ino = v.create(ROOT_INO, b"f", &spec, None).unwrap();
    v.write_file(ino, 0, &contents()).unwrap();
    (v, ino)
}

fn trusting(der: &str) -> Policy {
    let mut p = Policy::new();
    p.trust(&unhex(der)).expect("parses");
    p
}

fn read_all(v: &Volume<MemImage>, ino: u32) -> Result<Vec<u8>, Errno> {
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; inode.size as usize];
    v.read_file(&inode, ino, 0, &mut buf)?;
    Ok(buf)
}

fn remount(mut v: Volume<MemImage>, policy: Policy) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let mut v = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes),
                                   Options::defaults(), true).unwrap();
    v.set_verity_policy(policy);
    v
}

#[test]
fn the_measurement_of_the_sealed_file_is_the_one_the_signature_is_over() {
    // If this drifts, every test below is measuring something the fixture
    // does not sign, and the failures would look like signature bugs.
    let (mut v, ino) = with_file();
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, SALT).unwrap();
    let inode = v.read_inode(ino).unwrap();
    assert_eq!(v.verity_info(&inode, ino).unwrap().file_digest, unhex(SEALED_DIGEST));
}

#[test]
fn a_signed_file_seals_and_reads_back() {
    let (mut v, ino) = with_file();
    v.set_verity_policy(trusting(CA_DER));
    v.enable_verity_signed(ino, HASH_ALG_SHA256, LOG_BS, SALT, &unhex(SEALED_SIG)).unwrap();
    assert_eq!(read_all(&v, ino).unwrap(), contents());
    // And after the mount that sealed it is gone, so the signature is read
    // off the medium rather than remembered.
    let v = remount(v, trusting(CA_DER));
    assert!(v.read_inode(ino).unwrap().verity());
    assert_eq!(read_all(&v, ino).unwrap(), contents());
}

#[test]
fn the_signature_is_stored_with_the_descriptor_and_comes_back_whole() {
    let (mut v, ino) = with_file();
    let sig = unhex(SEALED_SIG);
    v.set_verity_policy(trusting(CA_DER));
    v.enable_verity_signed(ino, HASH_ALG_SHA256, LOG_BS, SALT, &sig).unwrap();
    let v = remount(v, trusting(CA_DER));
    let inode = v.read_inode(ino).unwrap();
    let attr = v.verity_attr(&inode, ino).unwrap();
    let loc = crate::verity::location::parse(&attr).unwrap();
    let desc = v.read_past_end(&inode, ino, loc.pos, loc.size as usize).unwrap();
    let d = crate::verity::descriptor::parse(&desc).unwrap();
    assert_eq!(d.sig_size as usize, sig.len());
    assert_eq!(crate::verity::descriptor::signature(&desc, &d).unwrap(), sig);
}

#[test]
fn a_signature_over_another_measurement_is_refused_at_sealing() {
    // A real signature by the trusted key, over a different file. Sealing
    // must refuse it rather than write a file nobody can then open.
    let (mut v, ino) = with_file();
    v.set_verity_policy(trusting(CA_DER));
    assert_eq!(
        v.enable_verity_signed(ino, HASH_ALG_SHA256, LOG_BS, SALT, &unhex(OTHER_SIG)).err(),
        Some(Errno::Ekeyrejected));
    // The file is untouched: no flag, no record, and the tree the attempt
    // wrote past the end is gone again. The block count is NOT the probe for
    // that — it is only stamped onto the inode when a seal completes, so it
    // reads unchanged whether the blocks were freed or not.
    let inode = v.read_inode(ino).unwrap();
    assert!(!inode.verity());
    let tree_at = crate::verity::metadata_pos(inode.size);
    assert_eq!(v.read_past_end(&inode, ino, tree_at, BLKSIZE).err(), Some(Errno::Eio),
               "the refused attempt left its hash tree on the file");
    assert_eq!(v.verity_attr(&inode, ino).err(), Some(Errno::Enodata));
    assert_eq!(read_all(&v, ino).unwrap(), contents());
    // And a second attempt, this time with the right signature, works.
    v.enable_verity_signed(ino, HASH_ALG_SHA256, LOG_BS, SALT, &unhex(SEALED_SIG)).unwrap();
    assert_eq!(read_all(&v, ino).unwrap(), contents());
}

#[test]
fn sealing_under_an_empty_keyring_refuses_a_signature_it_cannot_check() {
    let (mut v, ino) = with_file();
    assert_eq!(
        v.enable_verity_signed(ino, HASH_ALG_SHA256, LOG_BS, SALT, &unhex(SEALED_SIG)).err(),
        Some(Errno::Enokey));
    assert!(!v.read_inode(ino).unwrap().verity());
}

#[test]
fn a_signed_file_is_unreadable_on_a_mount_that_trusts_no_one() {
    // The signature is checked on every mount, not stamped once at sealing.
    let (mut v, ino) = with_file();
    v.set_verity_policy(trusting(CA_DER));
    v.enable_verity_signed(ino, HASH_ALG_SHA256, LOG_BS, SALT, &unhex(SEALED_SIG)).unwrap();
    let v = remount(v, Policy::trusting_nothing());
    assert_eq!(read_all(&v, ino).err(), Some(Errno::Enokey));
}

#[test]
fn a_signed_file_is_unreadable_on_a_mount_trusting_the_wrong_authority() {
    let (mut v, ino) = with_file();
    v.set_verity_policy(trusting(CA_DER));
    v.enable_verity_signed(ino, HASH_ALG_SHA256, LOG_BS, SALT, &unhex(SEALED_SIG)).unwrap();
    let v = remount(v, trusting(OTHER_CA_DER));
    assert_eq!(read_all(&v, ino).err(), Some(Errno::Enokey));
}

#[test]
fn a_tampered_signature_on_the_medium_is_caught_on_the_next_mount() {
    // The control for the whole feature: without the check the read succeeds
    // whatever the signature says, which is the state this replaces.
    let (mut v, ino) = with_file();
    v.set_verity_policy(trusting(CA_DER));
    v.enable_verity_signed(ino, HASH_ALG_SHA256, LOG_BS, SALT, &unhex(SEALED_SIG)).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let attr = v.verity_attr(&inode, ino).unwrap();
    let loc = crate::verity::location::parse(&attr).unwrap();
    let mut desc = v.read_past_end(&inode, ino, loc.pos, loc.size as usize).unwrap();
    let last = desc.len() - 1;
    desc[last] ^= 0x01;
    let index = loc.pos / BLKSIZE as u64;
    let skew = (loc.pos % BLKSIZE as u64) as usize;
    v.write_one_block(ino, index, skew, &desc).unwrap();
    let v = remount(v, trusting(CA_DER));
    assert_eq!(read_all(&v, ino).err(), Some(Errno::Ekeyrejected));
}

#[test]
fn an_unsigned_file_is_unreadable_where_signatures_are_required() {
    let (mut v, ino) = with_file();
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, SALT).unwrap();
    let mut demanding = trusting(CA_DER);
    demanding.set_require(true);
    let v = remount(v, demanding);
    assert_eq!(read_all(&v, ino).err(), Some(Errno::Eperm));
    // The same file reads where they are not.
    let v = remount(v, trusting(CA_DER));
    assert_eq!(read_all(&v, ino).unwrap(), contents());
}

#[test]
fn requiring_signatures_leaves_an_ordinary_file_alone() {
    // The requirement is about verity files. A file with no seal is not a
    // file with a missing signature.
    let (mut v, ino) = with_file();
    let mut demanding = Policy::trusting_nothing();
    demanding.set_require(true);
    v.set_verity_policy(demanding);
    assert!(!v.read_inode(ino).unwrap().verity());
    assert_eq!(read_all(&v, ino).unwrap(), contents());
    // And the record is still invisible by name on a signed file.
    v.set_verity_policy(trusting(CA_DER));
    v.enable_verity_signed(ino, HASH_ALG_SHA256, LOG_BS, SALT, &unhex(SEALED_SIG)).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let attrs = crate::xattr::list(&v.xattr_area(&inode, ino).unwrap()).unwrap();
    assert!(attrs.iter().any(|a| a.index == XATTR_INDEX_VERITY && a.name == XATTR_NAME));
    assert_eq!(v.get_xattr(&inode, ino, "user.v").err(), Some(Errno::Enodata));
}
