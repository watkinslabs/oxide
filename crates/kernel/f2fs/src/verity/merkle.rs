//! Checking a data block against the hash tree that attests to it.
//!
//! Locating the tree, which `location` and `descriptor` do, only stops the
//! tree being served AS data. It proves nothing about the data. Attestation is
//! this: hash the block, walk from the root down comparing each level's hash
//! block against the hash the level above holds for it, and require the leaf
//! entry to equal the block's own hash.
//!
//! Three details decide whether the walk agrees with the writer, and each one
//! silently produces a mismatch on every block if it is wrong:
//!
//! - **The tree is stored ROOT FIRST.** Level `num_levels - 1` is the root and
//!   sits at block zero; level 0, the one directly above the data, is stored
//!   last. Numbering the levels the other way inverts the whole tree.
//! - **The salt is zero-padded to the hash's COMPRESSION BLOCK**, not used as
//!   written, so the digest of a salted file differs from the digest of the
//!   same bytes salted naively.
//! - **A level's block count is the level below rounded up by the arity**, and
//!   the arity is the block size over the digest size — not a constant.

use alloc::vec::Vec;

use super::uapi::{HASH_ALG_SHA256, HASH_ALG_SHA512, SHA256_DIGEST_SIZE, SHA512_DIGEST_SIZE};
use super::VerityError;

/// Levels the format admits. A file needing more is refused rather than
/// walked with a truncated path.
pub const MAX_LEVELS: usize = 8;
/// Narrowest tree block the format admits.
pub const MIN_LOG_BLOCKSIZE: u8 = 10;
/// Widest, which is this build's page and file block.
pub const MAX_LOG_BLOCKSIZE: u8 = 12;
/// Widest digest any admitted algorithm produces.
pub const MAX_DIGEST_SIZE: usize = SHA512_DIGEST_SIZE;

/// A digest, carried by value so nothing allocates per block.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Digest {
    bytes: [u8; MAX_DIGEST_SIZE],
    len: usize,
}

impl Digest {
    /// # C: O(1)
    pub fn as_bytes(&self) -> &[u8] { &self.bytes[..self.len] }
}

/// The geometry a file's tree is laid out under.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Params {
    pub hash_alg: u8,
    pub digest_size: usize,
    pub log_blocksize: u8,
    pub block_size: usize,
    /// Hashes one tree block holds, as a log: the block size over the digest
    /// size.
    pub log_arity: u32,
    pub num_levels: usize,
    /// Where each level begins, in tree blocks. Index 0 is the level above
    /// the data; the last index is the root.
    pub level_start: [u64; MAX_LEVELS],
    /// Bytes the whole tree occupies.
    pub tree_size: u64,
    pub salt: Vec<u8>,
}

/// Bytes the compression function of `alg` consumes at a time. # C: O(1)
pub fn block_of_alg(alg: u8) -> Result<usize, VerityError> {
    match alg {
        HASH_ALG_SHA256 => Ok(64),
        HASH_ALG_SHA512 => Ok(128),
        _ => Err(VerityError::UnsupportedHash),
    }
}

/// Digest width of `alg`. # C: O(1)
pub fn digest_of_alg(alg: u8) -> Result<usize, VerityError> {
    match alg {
        HASH_ALG_SHA256 => Ok(SHA256_DIGEST_SIZE),
        HASH_ALG_SHA512 => Ok(SHA512_DIGEST_SIZE),
        _ => Err(VerityError::UnsupportedHash),
    }
}

impl Params {
    /// Derive the geometry for a file of `data_size` bytes.
    /// # C: O(levels)
    pub fn new(hash_alg: u8, log_blocksize: u8, salt: &[u8], data_size: u64)
        -> Result<Self, VerityError> {
        let digest_size = digest_of_alg(hash_alg)?;
        if !(MIN_LOG_BLOCKSIZE..=MAX_LOG_BLOCKSIZE).contains(&log_blocksize) {
            return Err(VerityError::BadBlockSize);
        }
        let block_size = 1usize << log_blocksize;
        // A block that cannot hold two hashes gives an arity of one, and a
        // tree of arity one never terminates.
        if block_size < 2 * digest_size { return Err(VerityError::BadBlockSize); }
        let log_digestsize = digest_size.trailing_zeros();
        if 1usize << log_digestsize != digest_size {
            return Err(VerityError::UnsupportedHash);
        }
        let log_arity = u32::from(log_blocksize) - log_digestsize;

        let mut blocks_in_level = [0u64; MAX_LEVELS];
        let mut num_levels = 0usize;
        let mut blocks = data_size.div_ceil(block_size as u64);
        while blocks > 1 {
            if num_levels >= MAX_LEVELS { return Err(VerityError::TooManyLevels); }
            blocks = blocks.div_ceil(1u64 << log_arity);
            blocks_in_level[num_levels] = blocks;
            num_levels += 1;
        }
        // Root first: the last level computed is the root and starts at zero.
        let mut level_start = [0u64; MAX_LEVELS];
        let mut offset = 0u64;
        for level in (0..num_levels).rev() {
            level_start[level] = offset;
            offset += blocks_in_level[level];
        }
        Ok(Params {
            hash_alg,
            digest_size,
            log_blocksize,
            block_size,
            log_arity,
            num_levels,
            level_start,
            tree_size: offset << log_blocksize,
            salt: salt.to_vec(),
        })
    }

    /// The salt as the hash actually consumes it: zero-padded up to the
    /// compression block, so the algorithm buffers nothing between the salt
    /// and the data. # C: O(salt)
    pub fn padded_salt(&self) -> Result<Vec<u8>, VerityError> {
        if self.salt.is_empty() { return Ok(Vec::new()); }
        let unit = block_of_alg(self.hash_alg)?;
        let mut out = self.salt.clone();
        out.resize(self.salt.len().div_ceil(unit) * unit, 0);
        Ok(out)
    }

    /// The digest of one block, salted the way the writer salted it.
    /// # C: O(block bytes)
    pub fn hash_block(&self, block: &[u8]) -> Result<Digest, VerityError> {
        let salt = self.padded_salt()?;
        let mut bytes = [0u8; MAX_DIGEST_SIZE];
        match self.hash_alg {
            HASH_ALG_SHA256 => {
                let mut h = crypt::Sha256::new();
                h.update(&salt);
                h.update(block);
                bytes[..SHA256_DIGEST_SIZE].copy_from_slice(&h.finish());
            }
            HASH_ALG_SHA512 => {
                let mut h = crypt::Sha512::new();
                h.update(&salt);
                h.update(block);
                bytes[..SHA512_DIGEST_SIZE].copy_from_slice(&h.finish());
            }
            _ => return Err(VerityError::UnsupportedHash),
        }
        Ok(Digest { bytes, len: self.digest_size })
    }

    /// Where the hash for data block `index` sits: the tree block holding it
    /// at each level, and the offset inside that block.
    ///
    /// Returned bottom-up, so entry zero is the level directly above the data.
    /// # C: O(levels)
    pub fn path(&self, index: u64) -> Vec<(u64, usize)> {
        let mut out = Vec::with_capacity(self.num_levels);
        let mut hidx = index;
        for level in 0..self.num_levels {
            let next = hidx >> self.log_arity;
            let hblock = self.level_start[level] + next;
            let hoffset = ((hidx as usize) << self.digest_size.trailing_zeros())
                & (self.block_size - 1);
            out.push((hblock, hoffset));
            hidx = next;
        }
        out
    }
}

/// Whether `data` really is the content of data block `index`.
///
/// `read_tree_block` is handed a tree-block index and returns that block's
/// bytes. The walk descends from the ROOT: each level's block is checked
/// against the hash the level above holds for it before any hash inside it is
/// believed, so a forged interior block is caught by its parent rather than
/// trusted because it is well-formed.
/// # C: O(levels) blocks hashed
pub fn verify_block<F>(p: &Params, root: &[u8], index: u64, data: &[u8], mut read_tree_block: F)
    -> Result<bool, VerityError>
where
    F: FnMut(u64) -> Result<Vec<u8>, VerityError>,
{
    if root.len() != p.digest_size { return Err(VerityError::Corrupted); }
    if data.len() != p.block_size { return Err(VerityError::BadBlockSize); }
    let path = p.path(index);
    let mut want: Vec<u8> = root.to_vec();
    for level in (0..p.num_levels).rev() {
        let (hblock_idx, hoffset) = path[level];
        let block = read_tree_block(hblock_idx)?;
        if block.len() != p.block_size {
            return Err(VerityError::BadBlockSize);
        }
        if p.hash_block(&block)?.as_bytes() != want.as_slice() { return Ok(false); }
        let end = hoffset + p.digest_size;
        want = block.get(hoffset..end).ok_or(VerityError::Corrupted)?.to_vec();
    }
    Ok(p.hash_block(data)?.as_bytes() == want.as_slice())
}

/// A file small enough to need no tree at all: its single block's hash IS the
/// root. # C: O(1)
pub fn is_flat(p: &Params) -> bool { p.num_levels == 0 }

#[cfg(test)]
#[path = "../tests/merkle.rs"]
mod tests;
