//! The per-inode verity info: the measurement it computes, the map of
//! already-checked hash blocks, and the cache that holds one per inode.

use super::{Cache, Info, Verified};
use crate::verity::descriptor::{self, Descriptor};
use crate::verity::VerityError;
use crate::verity::uapi::{DESCRIPTOR_SIZE, HASH_ALG_SHA256, HASH_ALG_SHA512, MAX_ROOT_HASH,
                          MAX_SALT, D_SIG_SIZE, U32_LEN};

const BLOCK: u64 = 4096;
const LOG_BS: u8 = 12;

fn desc(alg: u8, data_size: u64, salt: &[u8], sig_size: u32) -> Descriptor {
    let mut d = Descriptor {
        version: crate::verity::uapi::DESCRIPTOR_VERSION,
        hash_algorithm: alg,
        log_blocksize: LOG_BS,
        salt_size: salt.len() as u8,
        sig_size,
        data_size,
        root_hash: [0u8; MAX_ROOT_HASH],
        salt: [0u8; MAX_SALT],
    };
    for i in 0..32 { d.root_hash[i] = 0x10 + i as u8; }
    d.salt[..salt.len()].copy_from_slice(salt);
    d
}

#[test]
fn the_measurement_is_the_hash_of_the_descriptor_not_of_the_root() {
    // The root says nothing about the salt, the block size or the length the
    // tree was built over. A measurement that was just the root would let a
    // tree be re-described as another file's and still measure the same.
    let d = desc(HASH_ALG_SHA256, BLOCK * 4, b"", 0);
    let i = Info::new(&d, BLOCK * 4).unwrap();
    assert_eq!(i.file_digest.len(), 32);
    assert_ne!(i.file_digest, i.root_hash);

    let mut salted = d.clone();
    salted.salt_size = 4;
    salted.salt[..4].copy_from_slice(b"salt");
    assert_ne!(Info::new(&salted, BLOCK * 4).unwrap().file_digest, i.file_digest);

    let other_size = desc(HASH_ALG_SHA256, BLOCK * 5, b"", 0);
    assert_ne!(Info::new(&other_size, BLOCK * 5).unwrap().file_digest, i.file_digest);
}

#[test]
fn the_measurement_ignores_the_signature_length() {
    // A file must measure the same before and after a signature is attached
    // to it, or a signature could never be added to something already
    // published — and the signature is over the measurement, which would
    // otherwise be circular.
    let unsigned = Info::new(&desc(HASH_ALG_SHA256, BLOCK, b"", 0), BLOCK).unwrap();
    let signed = Info::new(&desc(HASH_ALG_SHA256, BLOCK, b"", 512), BLOCK).unwrap();
    assert_eq!(unsigned.file_digest, signed.file_digest);
}

#[test]
fn the_measurement_is_the_hash_of_exactly_the_fixed_part_with_the_length_zeroed() {
    // Stated as bytes rather than derived from the code under test: the
    // measurement is an on-disk contract, and a build that agreed only with
    // itself would sign digests no other reader computes.
    let d = desc(HASH_ALG_SHA256, BLOCK * 3, b"pepper", 900);
    let mut bytes = descriptor::encode(&d, &[]);
    bytes.truncate(DESCRIPTOR_SIZE);
    bytes[D_SIG_SIZE..D_SIG_SIZE + U32_LEN].fill(0);
    assert_eq!(bytes.len(), DESCRIPTOR_SIZE);
    let mut h = crypt::Sha256::new();
    h.update(&bytes);
    assert_eq!(Info::new(&d, BLOCK * 3).unwrap().file_digest, h.finish().to_vec());
}

#[test]
fn a_wider_digest_measures_wider() {
    let i = Info::new(&desc(HASH_ALG_SHA512, BLOCK * 4, b"", 0), BLOCK * 4).unwrap();
    assert_eq!(i.file_digest.len(), 64);
    assert_eq!(i.root_hash.len(), 64);
}

#[test]
fn the_verified_map_holds_one_bit_per_tree_block() {
    // Not one per data block, and not one per page: the walk indexes tree
    // blocks, so a map sized any other way records the wrong thing.
    let d = desc(HASH_ALG_SHA256, BLOCK * 200, b"", 0);
    let i = Info::new(&d, BLOCK * 200).unwrap();
    let blocks = (i.params.tree_size >> i.params.log_blocksize) as usize;
    assert!(blocks > 1);
    assert_eq!(i.verified.bits(), blocks);
    assert_eq!(i.verified.count(), 0);
}

#[test]
fn a_bit_is_set_only_where_it_is_set() {
    let mut v = Verified::new(200);
    assert!(!v.test(0));
    v.set(0);
    v.set(63);
    v.set(64);
    v.set(199);
    assert_eq!(v.count(), 4);
    for i in [0u64, 63, 64, 199] { assert!(v.test(i), "bit {i}"); }
    for i in [1u64, 62, 65, 198] { assert!(!v.test(i), "bit {i}"); }
    // Past the end is not verified, and asking does not widen the map.
    assert!(!v.test(200));
    v.set(200);
    assert_eq!(v.count(), 4);
}

#[test]
fn a_file_of_one_block_has_no_tree_and_so_no_map() {
    let i = Info::new(&desc(HASH_ALG_SHA256, BLOCK, b"", 0), BLOCK).unwrap();
    assert_eq!(i.params.num_levels, 0);
    assert_eq!(i.verified.bits(), 0);
}

#[test]
fn the_cache_hands_back_what_it_was_given() {
    let mut c = Cache::new();
    assert!(c.is_empty());
    let i = Info::new(&desc(HASH_ALG_SHA256, BLOCK * 4, b"", 0), BLOCK * 4).unwrap();
    let digest = i.file_digest.clone();
    c.insert(7, i);
    assert_eq!(c.len(), 1);
    assert_eq!(c.get(7, BLOCK * 4).unwrap().file_digest, digest);
    assert!(c.get(8, BLOCK * 4).is_none());
}

#[test]
fn an_entry_survives_being_written_through() {
    // The map is the point of the cache: a bit set during one read must be
    // there for the next one.
    let mut c = Cache::new();
    c.insert(7, Info::new(&desc(HASH_ALG_SHA256, BLOCK * 200, b"", 0), BLOCK * 200).unwrap());
    assert!(c.get(7, BLOCK * 200).unwrap().verified.bits() >= 2);
    c.get(7, BLOCK * 200).unwrap().verified.set(1);
    assert!(c.get(7, BLOCK * 200).unwrap().verified.test(1));
}

#[test]
fn an_entry_for_a_file_of_another_length_is_dropped_rather_than_used() {
    // An inode number is reused once the file it named is gone. Serving a new
    // file's blocks against an old file's tree is the failure this guards.
    let mut c = Cache::new();
    c.insert(7, Info::new(&desc(HASH_ALG_SHA256, BLOCK * 4, b"", 0), BLOCK * 4).unwrap());
    assert!(c.get(7, BLOCK * 5).is_none());
    assert!(c.is_empty(), "the stale entry is dropped, not merely ignored");
}

#[test]
fn forgetting_and_clearing_take_entries_out() {
    let mut c = Cache::new();
    for ino in 1..4u32 {
        c.insert(ino, Info::new(&desc(HASH_ALG_SHA256, BLOCK, b"", 0), BLOCK).unwrap());
    }
    c.forget(2);
    assert_eq!(c.len(), 2);
    assert!(c.get(2, BLOCK).is_none());
    c.clear();
    assert!(c.is_empty());
}

#[test]
fn an_unreadable_descriptor_makes_no_info() {
    let mut bad = desc(HASH_ALG_SHA256, BLOCK, b"", 0);
    bad.hash_algorithm = 99;
    assert_eq!(Info::new(&bad, BLOCK).err(), Some(VerityError::UnsupportedHash));
    let mut narrow = desc(HASH_ALG_SHA512, BLOCK, b"", 0);
    narrow.log_blocksize = 6;
    assert_eq!(Info::new(&narrow, BLOCK).err(), Some(VerityError::BadBlockSize));
}

#[test]
fn a_sub_block_tree_sizes_its_map_by_its_own_block() {
    // The map is indexed in TREE blocks, which need not be the filesystem's.
    // A map sized in filesystem blocks would be four times too short at the
    // smallest tree block size, and the walk would silently re-verify.
    let data = BLOCK * 64;
    for log_bs in 10u8..=12 {
        let mut d = desc(HASH_ALG_SHA256, data, b"", 0);
        d.log_blocksize = log_bs;
        let i = Info::new(&d, data).unwrap();
        assert_eq!(i.params.block_size, 1usize << log_bs);
        assert_eq!(i.verified.bits(), (i.params.tree_size >> log_bs) as usize,
                   "log_bs {log_bs}");
    }
}
