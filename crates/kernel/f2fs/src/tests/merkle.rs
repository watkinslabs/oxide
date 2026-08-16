//! Tree geometry, and the two details that silently invert or shift it.
//!
//! The end-to-end sealing tests prove a tree this build writes is a tree this
//! build reads. They cannot prove it is the tree the FORMAT describes — a
//! writer and a reader that share a mistake agree with each other perfectly.
//! These pin the geometry itself: the level order, the arity, the level
//! offsets, and the salt padding, each stated as a number rather than derived
//! from the code under test.

use super::*;
use crate::verity::uapi::{HASH_ALG_SHA256, HASH_ALG_SHA512, SHA256_DIGEST_SIZE,
                          SHA512_DIGEST_SIZE};
use crate::verity::VerityError;
use alloc::vec;

const BS: u8 = 12;
const BLOCK: u64 = 4096;

fn p(size: u64) -> Params { Params::new(HASH_ALG_SHA256, BS, b"", size).unwrap() }

#[test]
fn a_file_of_one_block_or_less_has_no_tree() {
    // Its own hash is the root; a level above one block would hold one hash
    // and never terminate.
    assert_eq!(p(0).num_levels, 0);
    assert_eq!(p(1).num_levels, 0);
    assert_eq!(p(BLOCK).num_levels, 0);
    assert!(is_flat(&p(BLOCK)));
}

#[test]
fn the_arity_is_the_block_over_the_digest() {
    // 4096 / 32 = 128 hashes per block, so log_arity is 7. A constant here
    // would put every hash at the wrong offset for the wider digest.
    assert_eq!(p(BLOCK * 2).log_arity, 7);
    let wide = Params::new(HASH_ALG_SHA512, BS, b"", BLOCK * 2).unwrap();
    assert_eq!(wide.log_arity, 6);
    assert_eq!(wide.digest_size, SHA512_DIGEST_SIZE);
}

#[test]
fn a_level_is_added_only_when_the_one_below_needs_more_than_one_block() {
    // 128 data blocks fit in a single level-0 block, so the tree is one level.
    // 129 need two, which need a level above them.
    assert_eq!(p(BLOCK * 128).num_levels, 1);
    assert_eq!(p(BLOCK * 129).num_levels, 2);
    assert_eq!(p(BLOCK * 128 * 128).num_levels, 2);
    assert_eq!(p(BLOCK * (128 * 128 + 1)).num_levels, 3);
}

#[test]
fn the_root_is_stored_first_and_level_zero_last() {
    // Level num_levels-1 is the root and sits at block zero; level 0, the one
    // directly above the data, is stored last. Numbering the other way
    // inverts the whole tree and every verification fails.
    let q = p(BLOCK * 129);
    assert_eq!(q.num_levels, 2);
    assert_eq!(q.level_start[1], 0, "the root is not first");
    assert_eq!(q.level_start[0], 1, "level zero does not follow the root");
    // Two blocks at level 0 (129 hashes), one at level 1.
    assert_eq!(q.tree_size, 3 * BLOCK);
}

#[test]
fn a_three_level_tree_lays_its_levels_out_root_first() {
    let blocks = 128u64 * 128 + 1;
    let q = p(BLOCK * blocks);
    assert_eq!(q.num_levels, 3);
    let l0 = blocks.div_ceil(128);        // 129
    let l1 = l0.div_ceil(128);            // 2
    assert_eq!(q.level_start[2], 0);
    assert_eq!(q.level_start[1], 1);
    assert_eq!(q.level_start[0], 1 + l1);
    assert_eq!(q.tree_size, (1 + l1 + l0) * BLOCK);
}

#[test]
fn the_path_names_one_block_and_offset_per_level() {
    let q = p(BLOCK * 129);
    // Data block 0's hash is the first entry of the first level-0 block.
    assert_eq!(q.path(0)[0], (q.level_start[0], 0));
    // Data block 1's hash is the next entry of the same block.
    assert_eq!(q.path(1)[0], (q.level_start[0], SHA256_DIGEST_SIZE));
    // Data block 128 starts the SECOND level-0 block, back at offset zero.
    assert_eq!(q.path(128)[0], (q.level_start[0] + 1, 0));
    // And both are covered by the root, at different offsets.
    assert_eq!(q.path(0)[1], (0, 0));
    assert_eq!(q.path(128)[1], (0, SHA256_DIGEST_SIZE));
}

#[test]
fn the_salt_is_padded_to_the_hashs_compression_block() {
    // Not used as written: the algorithm buffers nothing between the salt and
    // the data, so a short salt is zero-filled to 64 bytes for sha256 and 128
    // for sha512. Hashing with the raw salt gives a different digest for
    // every block of every salted file.
    let short = Params::new(HASH_ALG_SHA256, BS, b"abc", BLOCK * 2).unwrap();
    assert_eq!(short.padded_salt().unwrap().len(), 64);
    let wide = Params::new(HASH_ALG_SHA512, BS, b"abc", BLOCK * 2).unwrap();
    assert_eq!(wide.padded_salt().unwrap().len(), 128);
    // A salt longer than one compression block rounds up to the next.
    let long = Params::new(HASH_ALG_SHA256, BS, &[7u8; 70], BLOCK * 2).unwrap();
    assert_eq!(long.padded_salt().unwrap().len(), 128);
    // No salt means no prefix at all, not a block of zeroes.
    assert!(p(BLOCK * 2).padded_salt().unwrap().is_empty());
}

#[test]
fn an_unsalted_digest_is_the_plain_hash_of_the_block() {
    let q = p(BLOCK * 2);
    let block = vec![0xA5u8; BLOCK as usize];
    let mut h = crypt::Sha256::new();
    h.update(&block);
    assert_eq!(q.hash_block(&block).unwrap().as_bytes(), &h.finish()[..]);
}

#[test]
fn a_salted_digest_is_the_hash_of_the_padded_salt_then_the_block() {
    let q = Params::new(HASH_ALG_SHA256, BS, b"abc", BLOCK * 2).unwrap();
    let block = vec![0xA5u8; BLOCK as usize];
    let mut salt = vec![0u8; 64];
    salt[..3].copy_from_slice(b"abc");
    let mut h = crypt::Sha256::new();
    h.update(&salt);
    h.update(&block);
    assert_eq!(q.hash_block(&block).unwrap().as_bytes(), &h.finish()[..]);
}

#[test]
fn an_unknown_algorithm_or_block_size_is_refused() {
    assert_eq!(Params::new(99, BS, b"", BLOCK).err(), Some(VerityError::UnsupportedHash));
    // Below the format's floor, and above this build's block.
    assert_eq!(Params::new(HASH_ALG_SHA256, 9, b"", BLOCK).err(), Some(VerityError::BadBlockSize));
    assert_eq!(Params::new(HASH_ALG_SHA256, 13, b"", BLOCK).err(), Some(VerityError::BadBlockSize));
}

#[test]
fn a_tree_deeper_than_the_format_admits_is_refused() {
    // Rather than walked with a truncated path, which would compare a leaf
    // hash against an interior block and reject every read of a huge file.
    assert_eq!(Params::new(HASH_ALG_SHA256, 10, b"", u64::MAX).err(),
               Some(VerityError::TooManyLevels));
}

#[test]
fn a_root_of_the_wrong_width_is_refused_rather_than_compared() {
    let q = p(BLOCK * 2);
    let data = vec![0u8; BLOCK as usize];
    let short = [0u8; 8];
    let r = verify_block(&q, &short, 0, &data, |_| Ok(vec![0u8; BLOCK as usize]));
    assert_eq!(r.err(), Some(VerityError::Corrupted));
}
