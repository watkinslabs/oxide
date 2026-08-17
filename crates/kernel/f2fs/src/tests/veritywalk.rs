//! The walk, driven against trees built here rather than by the filesystem.
//!
//! The end-to-end sealing tests prove a tree this build writes is a tree this
//! build reads — which a writer and a reader sharing a mistake also prove.
//! These build the tree from the format's own rules and then attack it: a
//! flipped hash, a substituted block, a root from another file, a block past
//! the end. Each one must be refused, and the refusal must survive the
//! caching that exists to skip work.

use super::verify_block;
use crate::verity::info::Verified;
use crate::verity::merkle::Params;
use crate::verity::uapi::{HASH_ALG_SHA256, HASH_ALG_SHA512};
use crate::verity::VerityError;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;

/// A tree laid out exactly as the format stores it: root first, level 0 last,
/// every block whole.
struct Tree {
    blocks: Vec<u8>,
    root: Vec<u8>,
}

impl Tree {
    /// # C: O(data)
    fn build(p: &Params, data: &[u8]) -> Self {
        let bs = p.block_size;
        let mut blocks = vec![0u8; p.tree_size as usize];
        let nblocks = (data.len() as u64).div_ceil(bs as u64) as usize;
        let mut below: Vec<Vec<u8>> = Vec::new();
        for i in 0..nblocks {
            let mut b = vec![0u8; bs];
            let at = i * bs;
            let take = (data.len() - at).min(bs);
            b[..take].copy_from_slice(&data[at..at + take]);
            below.push(p.hash_block(&b).unwrap().as_bytes().to_vec());
        }
        if below.is_empty() { below.push(vec![0u8; p.digest_size]); }
        for level in 0..p.num_levels {
            let per = 1usize << p.log_arity;
            let mut above = Vec::new();
            for (n, chunk) in below.chunks(per).enumerate() {
                let at = (p.level_start[level] as usize + n) * bs;
                for (k, d) in chunk.iter().enumerate() {
                    blocks[at + k * p.digest_size..at + (k + 1) * p.digest_size]
                        .copy_from_slice(d);
                }
                above.push(p.hash_block(&blocks[at..at + bs]).unwrap().as_bytes().to_vec());
            }
            below = above;
        }
        Self { blocks, root: below[0].clone() }
    }

    /// One tree block by index. # C: O(block)
    fn block(&self, i: u64, bs: usize) -> Vec<u8> {
        let at = i as usize * bs;
        self.blocks[at..at + bs].to_vec()
    }
}

/// Data whose every block differs from every other. A file of one repeated
/// byte would make a substituted block indistinguishable from the real one.
fn data_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i / 97 + i) % 251) as u8).collect()
}

fn params(alg: u8, log_bs: u8, salt: &[u8], len: usize) -> Params {
    Params::new(alg, log_bs, salt, len as u64).unwrap()
}

/// Check every block of a file, counting the tree blocks read.
fn check_all(p: &Params, t: &Tree, data: &[u8], v: &mut Verified) -> (bool, u32) {
    let reads = Cell::new(0u32);
    let bs = p.block_size;
    let nblocks = data.len().div_ceil(bs);
    for i in 0..nblocks {
        let mut b = vec![0u8; bs];
        let at = i * bs;
        let take = (data.len() - at).min(bs);
        b[..take].copy_from_slice(&data[at..at + take]);
        let ok = verify_block(p, &t.root, v, i as u64, &b, |idx| {
            reads.set(reads.get() + 1);
            Ok(t.block(idx, bs))
        }).unwrap();
        if !ok { return (false, reads.get()); }
    }
    (true, reads.get())
}

#[test]
fn a_tree_built_to_the_format_verifies_every_block() {
    let data = data_of(300 * 4096);
    let p = params(HASH_ALG_SHA256, 12, b"", data.len());
    assert_eq!(p.num_levels, 2);
    let t = Tree::build(&p, &data);
    let mut v = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    assert!(check_all(&p, &t, &data, &mut v).0);
}

#[test]
fn the_cache_cuts_the_reads_and_not_the_checking() {
    // The whole reason the walk climbs instead of descending. Every block is
    // still verified; the upper tree is simply not re-read once it is known.
    let data = data_of(300 * 4096);
    let p = params(HASH_ALG_SHA256, 12, b"", data.len());
    let t = Tree::build(&p, &data);
    let mut cold = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    let (ok, first) = check_all(&p, &t, &data, &mut cold);
    assert!(ok);
    let (ok, second) = check_all(&p, &t, &data, &mut cold);
    assert!(ok, "a warm map must not change the verdict");
    assert!(second < first, "warm {second} is not below cold {first}");
    // Warm, the root is never re-read: only the level directly above the data
    // is fetched, one block per arity's worth of data blocks.
    let leaf_blocks = (data.len() as u64).div_ceil(4096).div_ceil(1 << p.log_arity);
    assert_eq!(second as u64, data.len().div_ceil(4096) as u64, "one read per data block");
    assert!(leaf_blocks >= 2, "the fixture needs more than one leaf hash block");
}

#[test]
fn every_hash_block_the_walk_passed_is_recorded() {
    let data = data_of(300 * 4096);
    let p = params(HASH_ALG_SHA256, 12, b"", data.len());
    let t = Tree::build(&p, &data);
    let mut v = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    assert!(check_all(&p, &t, &data, &mut v).0);
    // The whole tree is on some block's path, so every block ends up checked.
    assert_eq!(v.count() as u64, p.tree_size >> p.log_blocksize);
}

#[test]
fn a_flipped_data_byte_is_caught_cold_and_warm() {
    let data = data_of(300 * 4096);
    let p = params(HASH_ALG_SHA256, 12, b"", data.len());
    let t = Tree::build(&p, &data);
    let mut bad = data.clone();
    bad[5 * 4096 + 11] ^= 0x01;
    // Cold: nothing cached, the walk climbs to the root.
    let mut v = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    assert!(!check_all(&p, &t, &bad, &mut v).0);
    // Warm: the upper tree is trusted, and the leaf comparison still fires.
    // A cache that short-circuited the data block itself would pass here.
    let mut warm = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    assert!(check_all(&p, &t, &data, &mut warm).0);
    assert!(!check_all(&p, &t, &bad, &mut warm).0);
}

#[test]
fn a_flipped_interior_hash_is_caught() {
    // The block is well formed and its parent does not agree with it. A walk
    // that trusted a readable block would pass this.
    let data = data_of(300 * 4096);
    let p = params(HASH_ALG_SHA256, 12, b"", data.len());
    let mut t = Tree::build(&p, &data);
    let leaf0 = p.level_start[0] as usize * p.block_size;
    t.blocks[leaf0] ^= 0x01;
    let mut v = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    assert!(!check_all(&p, &t, &data, &mut v).0);
}

#[test]
fn a_block_that_failed_is_not_recorded_as_verified() {
    // The bit means "compared against its parent and matched". Setting it on
    // a block that was merely READ would poison the map: the second read
    // through that block would skip the comparison and return forged bytes.
    // So the same corrupt tree must be refused as many times as it is asked.
    let data = data_of(300 * 4096);
    let p = params(HASH_ALG_SHA256, 12, b"", data.len());
    let mut t = Tree::build(&p, &data);
    let leaf0 = p.level_start[0] as usize * p.block_size;
    t.blocks[leaf0] ^= 0x01;
    let mut v = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    let b = data[..4096].to_vec();
    for attempt in 0..3 {
        let ok = verify_block(&p, &t.root, &mut v, 0, &b, |i| Ok(t.block(i, 4096))).unwrap();
        assert!(!ok, "attempt {attempt} accepted a tree that had just been refused");
    }
    // The block that FAILED is the one that must not be recorded. Blocks
    // above it on the path did match their parents and are legitimately
    // marked — the descent got that far before the mismatch.
    assert!(!v.test(p.level_start[0]), "a refused block was recorded as verified");
    assert!(v.test(p.level_start[p.num_levels - 1]), "the root block did match and should be");
}

#[test]
fn a_root_from_another_file_is_caught() {
    let data = data_of(8 * 4096);
    let p = params(HASH_ALG_SHA256, 12, b"", data.len());
    let t = Tree::build(&p, &data);
    let other = Tree::build(&p, &data_of(8 * 4096 - 1));
    assert_ne!(t.root, other.root);
    let mut v = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    let b = data[..4096].to_vec();
    let ok = verify_block(&p, &other.root, &mut v, 0, &b, |i| Ok(t.block(i, 4096)))
        .unwrap();
    assert!(!ok);
    // And nothing was recorded as verified on the way to that answer.
    assert_eq!(v.count(), 0);
}

#[test]
fn a_whole_tree_substituted_with_its_own_root_is_still_caught() {
    // The descriptor is the anchor. Swapping in a consistent tree for other
    // content must fail, because the root the descriptor names is unchanged.
    let data = data_of(8 * 4096);
    let p = params(HASH_ALG_SHA256, 12, b"", data.len());
    let real = Tree::build(&p, &data);
    let forged_data = data_of(8 * 4096).iter().map(|b| b ^ 0xff).collect::<Vec<_>>();
    let forged = Tree::build(&p, &forged_data);
    let mut v = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    let b = forged_data[..4096].to_vec();
    let ok = verify_block(&p, &real.root, &mut v, 0, &b, |i| Ok(forged.block(i, 4096)))
        .unwrap();
    assert!(!ok);
}

#[test]
fn a_block_wholly_past_the_end_must_be_zero() {
    // The tree covers the file's length. The rest of the last page is visible
    // to anything that maps the file, so it is required to hold nothing
    // rather than left unchecked.
    let len = 4096 + 100;
    let p = params(HASH_ALG_SHA256, 10, b"", len);
    let data = data_of(len);
    let t = Tree::build(&p, &data);
    let mut v = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    // Block 4 starts at 4096 and holds live data; block 5 starts at 5120,
    // past the end.
    let zeros = vec![0u8; 1024];
    let read = |i: u64| Ok(t.block(i, 1024));
    assert!(verify_block(&p, &t.root, &mut v, 5, &zeros, read).unwrap());
    let mut dirty = zeros.clone();
    dirty[0] = 1;
    assert!(!verify_block(&p, &t.root, &mut v, 5, &dirty, read).unwrap());
}

#[test]
fn a_tree_block_narrower_than_the_filesystems_verifies() {
    // The reader claims to handle a tree block below the filesystem's. Proven
    // here at every admitted size, over a file whose length is not a whole
    // number of blocks at any of them.
    let len = 200 * 4096 + 777;
    let data = data_of(len);
    for log_bs in 10u8..=12 {
        let p = params(HASH_ALG_SHA256, log_bs, b"", len);
        assert!(p.num_levels >= 2, "log_bs {log_bs} needs a deep enough tree");
        let t = Tree::build(&p, &data);
        let mut v = Verified::new((p.tree_size >> p.log_blocksize) as usize);
        assert!(check_all(&p, &t, &data, &mut v).0, "log_bs {log_bs}");
        // And a change is still caught at that size.
        let mut bad = data.clone();
        bad[3 * (1 << log_bs)] ^= 0x80;
        let mut w = Verified::new((p.tree_size >> p.log_blocksize) as usize);
        assert!(!check_all(&p, &t, &bad, &mut w).0, "log_bs {log_bs} missed a change");
    }
}

#[test]
fn a_narrow_tree_block_with_a_wide_digest_verifies() {
    // Arity two at the floor: 1024 bytes holds sixteen SHA-512 digests, so
    // the tree is much deeper and every level offset moves.
    let len = 40 * 1024 + 3;
    let data = data_of(len);
    let p = params(HASH_ALG_SHA512, 10, b"", len);
    assert_eq!(p.log_arity, 4);
    let t = Tree::build(&p, &data);
    let mut v = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    assert!(check_all(&p, &t, &data, &mut v).0);
}

#[test]
fn a_root_or_block_of_the_wrong_width_is_refused_rather_than_compared() {
    let data = data_of(8 * 4096);
    let p = params(HASH_ALG_SHA256, 12, b"", data.len());
    let t = Tree::build(&p, &data);
    let mut v = Verified::new((p.tree_size >> p.log_blocksize) as usize);
    let b = data[..4096].to_vec();
    assert_eq!(verify_block(&p, &[0u8; 8], &mut v, 0, &b, |i| Ok(t.block(i, 4096))).err(),
               Some(VerityError::Corrupted));
    assert_eq!(verify_block(&p, &t.root, &mut v, 0, &b[..10], |i| Ok(t.block(i, 4096)))
                   .err(),
               Some(VerityError::BadBlockSize));
    // A tree block of the wrong width is a corrupt tree, not a short read to
    // pad out.
    assert_eq!(verify_block(&p, &t.root, &mut v, 0, &b, |_| Ok(vec![0u8; 100])).err(),
               Some(VerityError::BadBlockSize));
}
