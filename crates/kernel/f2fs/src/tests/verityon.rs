//! Sealing a file under a hash tree, and the tree catching a change to it.
//!
//! Every test here goes through the real sealing path and the real read path,
//! so a break in either shows up as a read that returns the wrong answer
//! rather than as a helper disagreeing with a helper. The corruption tests
//! are the positive controls: each one reinstates a specific defect — a
//! flipped data byte, a flipped tree byte, a root that describes another
//! file — and requires the read to be refused.

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{BLKSIZE, XATTR_INDEX_VERITY};
use crate::verity::merkle;
use crate::verity::uapi::{HASH_ALG_SHA256, HASH_ALG_SHA512, SHA256_DIGEST_SIZE, XATTR_NAME};
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 7);
/// The tree's block size for these fixtures: the filesystem's own.
const LOG_BS: u8 = 12;

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// A writable volume holding one file of `bytes`, and that file's number.
fn with_data(bytes: &[u8]) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    if !bytes.is_empty() { v.write_file(ino, 0, bytes).unwrap(); }
    (v, ino)
}

/// Read the whole of a sealed file through the ordinary path.
fn read_all(v: &Volume<MemImage>, ino: u32) -> Result<Vec<u8>, Errno> {
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; inode.size as usize];
    v.read_file(&inode, ino, 0, &mut buf)?;
    Ok(buf)
}

#[test]
fn a_sealed_file_reads_back_its_own_bytes() {
    let data: Vec<u8> = (0..3 * BLKSIZE).map(|i| (i % 251) as u8).collect();
    let (mut v, ino) = with_data(&data);
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    assert_eq!(read_all(&v, ino).unwrap(), data);
}

#[test]
fn sealing_leaves_the_size_alone() {
    // The size is what separates the data from the metadata. If writing the
    // tree extended it, the tree would become part of the file's contents and
    // the next reader would locate the metadata somewhere else entirely.
    let (mut v, ino) = with_data(&vec![9u8; 5000]);
    let before = v.read_inode(ino).unwrap().size;
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    assert_eq!(v.read_inode(ino).unwrap().size, before);
}

#[test]
fn sealing_charges_the_metadata_blocks() {
    // The tree occupies real blocks. A count that ignored them would let a
    // file report less space than it holds.
    let (mut v, ino) = with_data(&vec![9u8; 4 * BLKSIZE]);
    let before = v.read_inode(ino).unwrap().blocks;
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    assert!(v.read_inode(ino).unwrap().blocks > before);
}

#[test]
fn the_seal_survives_a_remount() {
    let data: Vec<u8> = (0..2 * BLKSIZE + 17).map(|i| (i % 97) as u8).collect();
    let (mut v, ino) = with_data(&data);
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let v2 = Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes),
                                Options::defaults(), true).unwrap();
    assert!(v2.read_inode(ino).unwrap().verity());
    assert_eq!(read_all(&v2, ino).unwrap(), data);
}

#[test]
fn sealing_twice_is_refused() {
    let (mut v, ino) = with_data(b"once");
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    assert_eq!(v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").err(), Some(Errno::Eexist));
}

#[test]
fn a_salt_changes_the_root() {
    // The salt is mixed into every hash, so the same bytes under a different
    // salt seal to a different root. A root that ignored the salt would let
    // one file's tree attest to another's.
    let (mut v, a) = with_data(&vec![3u8; 2 * BLKSIZE]);
    let ra = v.enable_verity(a, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    let b = v.create(ROOT_INO, b"g", &spec(), None).unwrap();
    v.write_file(b, 0, &vec![3u8; 2 * BLKSIZE]).unwrap();
    let rb = v.enable_verity(b, HASH_ALG_SHA256, LOG_BS, b"pepper").unwrap();
    assert_ne!(ra, rb);
    assert_eq!(read_all(&v, b).unwrap(), vec![3u8; 2 * BLKSIZE]);
}

#[test]
fn a_salted_file_still_verifies() {
    let data: Vec<u8> = (0..9000).map(|i| (i % 13) as u8).collect();
    let (mut v, ino) = with_data(&data);
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"a-salt-of-some-length").unwrap();
    assert_eq!(read_all(&v, ino).unwrap(), data);
}

#[test]
fn a_wider_digest_still_verifies() {
    // The arity is the block size over the DIGEST size, so a wider digest
    // gives a shallower fan-out and a differently shaped tree.
    let data: Vec<u8> = (0..5 * BLKSIZE).map(|i| (i % 31) as u8).collect();
    let (mut v, ino) = with_data(&data);
    v.enable_verity(ino, HASH_ALG_SHA512, LOG_BS, b"").unwrap();
    assert_eq!(read_all(&v, ino).unwrap(), data);
}

#[test]
fn an_empty_file_seals_to_a_zero_root() {
    // No blocks means nothing to attest to; a hash of nothing would still be
    // a hash, and would disagree with every other reader of the format.
    let (mut v, ino) = with_data(b"");
    let root = v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    assert_eq!(root, vec![0u8; SHA256_DIGEST_SIZE]);
}

#[test]
fn a_deep_tree_verifies_every_block() {
    // Two levels, so the walk has to descend through an interior block
    // instead of reading the root's entry directly.
    let per = BLKSIZE / SHA256_DIGEST_SIZE;
    let blocks = per + 3;
    let data: Vec<u8> = (0..blocks * BLKSIZE).map(|i| (i % 211) as u8).collect();
    let (mut v, ino) = with_data(&data);
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    let p = merkle::Params::new(HASH_ALG_SHA256, LOG_BS, b"", (blocks * BLKSIZE) as u64).unwrap();
    assert_eq!(p.num_levels, 2);
    let inode = v.read_inode(ino).unwrap();
    // Every block, not just the first: a path computed for one index and
    // reused for the rest would pass a single-block test.
    for i in 0..blocks {
        let mut buf = vec![0u8; BLKSIZE];
        v.read_file(&inode, ino, (i * BLKSIZE) as u64, &mut buf).unwrap();
        assert_eq!(&buf[..], &data[i * BLKSIZE..(i + 1) * BLKSIZE]);
    }
}

// ------------------------------------------------------- positive controls

#[test]
fn a_flipped_data_byte_is_caught() {
    // The control for the whole feature: without verification this read
    // succeeds and returns the altered byte.
    let data: Vec<u8> = (0..3 * BLKSIZE).map(|i| (i % 251) as u8).collect();
    let (mut v, ino) = with_data(&data);
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    // Read the block, change one byte, put it back underneath the seal.
    let inode = v.read_inode(ino).unwrap();
    let mut block = vec![0u8; BLKSIZE];
    v.read_file(&inode, ino, BLKSIZE as u64, &mut block).unwrap();
    block[10] ^= 0xff;
    v.write_one_block(ino, 1, 0, &block).unwrap();
    assert_eq!(read_all(&v, ino).err(), Some(Errno::Eio));
    // Unaltered blocks still read: the refusal is per block, not per file.
    let inode = v.read_inode(ino).unwrap();
    let mut good = vec![0u8; BLKSIZE];
    assert!(v.read_file(&inode, ino, 0, &mut good).is_ok());
}

#[test]
fn a_flipped_tree_byte_is_caught() {
    // An interior block is checked against its parent before any hash inside
    // it is believed. Trusting a well-formed tree block would pass this.
    let data: Vec<u8> = (0..4 * BLKSIZE).map(|i| (i % 251) as u8).collect();
    let (mut v, ino) = with_data(&data);
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    let inode = v.read_inode(ino).unwrap();
    let tree_at = crate::verity::metadata_pos(inode.size);
    let mut block = v.read_past_end(&inode, ino, tree_at, BLKSIZE).unwrap();
    block[0] ^= 0x01;
    v.write_one_block(ino, tree_at / BLKSIZE as u64, 0, &block).unwrap();
    assert_eq!(read_all(&v, ino).err(), Some(Errno::Eio));
}

#[test]
fn a_root_from_another_file_is_caught() {
    // The descriptor is the anchor. A reader that took the tree's own top
    // block as the root would accept a tree substituted wholesale.
    let data: Vec<u8> = (0..2 * BLKSIZE).map(|i| (i % 251) as u8).collect();
    let (mut v, ino) = with_data(&data);
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    let inode = v.read_inode(ino).unwrap();
    let attr = v.verity_attr(&inode, ino).unwrap();
    let loc = crate::verity::location::parse(&attr).unwrap();
    let mut desc = v.read_past_end(&inode, ino, loc.pos, loc.size as usize).unwrap();
    desc[crate::verity::uapi::D_ROOT_HASH] ^= 0xff;
    let index = loc.pos / BLKSIZE as u64;
    let skew = (loc.pos % BLKSIZE as u64) as usize;
    v.write_one_block(ino, index, skew, &desc).unwrap();
    assert_eq!(read_all(&v, ino).err(), Some(Errno::Eio));
}

#[test]
fn a_missing_descriptor_refuses_the_read() {
    // The flag says the bytes are attested. With nothing to attest against,
    // serving them anyway is the exact failure verification exists to stop.
    let (mut v, ino) = with_data(&vec![1u8; 100]);
    v.enable_verity(ino, HASH_ALG_SHA256, LOG_BS, b"").unwrap();
    let inode = v.read_inode(ino).unwrap();
    let area = v.xattr_area(&inode, ino).unwrap();
    let attrs: Vec<_> = crate::xattr::list(&area)
        .unwrap()
        .into_iter()
        .filter(|a| !(a.index == XATTR_INDEX_VERITY && a.name == XATTR_NAME))
        .collect();
    v.store_xattrs(ino, &attrs).unwrap();
    assert_eq!(read_all(&v, ino).err(), Some(Errno::Enodata));
}
