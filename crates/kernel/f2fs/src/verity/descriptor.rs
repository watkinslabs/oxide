//! The descriptor itself: what the file's hash tree was built with, and the
//! root it hashes to.
//!
//! Every field here is an input to reproducing the tree. A wrong block size
//! or a wrong salt length does not fail — it produces a different root hash
//! from the same bytes, which reads as a file that has been tampered with.
//! So each field is checked against what the format admits, and the declared
//! data size is checked against the inode's, because a descriptor built over
//! a different length of file describes a different file.

use alloc::vec::Vec;

use super::uapi::*;
use super::VerityError;

/// One descriptor.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Descriptor {
    pub version: u8,
    pub hash_algorithm: u8,
    pub log_blocksize: u8,
    /// Bytes of salt actually used, out of the fixed field.
    pub salt_size: u8,
    /// Bytes of built-in signature following the fixed part.
    pub sig_size: u32,
    /// Length of file the tree was built over. Must be the inode's own size.
    pub data_size: u64,
    pub root_hash: [u8; MAX_ROOT_HASH],
    pub salt: [u8; MAX_SALT],
}

impl Descriptor {
    /// Bytes of digest the named algorithm produces. # C: O(1)
    pub fn digest_size(&self) -> Result<usize, VerityError> {
        match self.hash_algorithm {
            HASH_ALG_SHA256 => Ok(SHA256_DIGEST_SIZE),
            HASH_ALG_SHA512 => Ok(SHA512_DIGEST_SIZE),
            _ => Err(VerityError::UnsupportedHash),
        }
    }

    /// Bytes of one tree block. # C: O(1)
    pub fn block_size(&self) -> u64 { 1u64 << self.log_blocksize }

    /// The salt as used, rather than the fixed field it sits in. # C: O(1)
    pub fn salt_used(&self) -> &[u8] { &self.salt[..self.salt_size as usize] }

    /// The root hash as used. # C: O(1)
    pub fn root_used(&self) -> Result<&[u8], VerityError> {
        Ok(&self.root_hash[..self.digest_size()?])
    }
}

fn le32(b: &[u8], at: usize) -> u32 {
    let mut v = [0u8; U32_LEN];
    v.copy_from_slice(&b[at..at + U32_LEN]);
    u32::from_le_bytes(v)
}

fn le64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; U64_LEN];
    v.copy_from_slice(&b[at..at + U64_LEN]);
    u64::from_le_bytes(v)
}

/// Read a descriptor out of the bytes at its location.
///
/// `bytes` is the whole record the location described, signature included;
/// anything shorter than the fixed part is a descriptor this build cannot
/// read rather than one to read partially.
/// # C: O(1)
pub fn parse(bytes: &[u8]) -> Result<Descriptor, VerityError> {
    if bytes.len() < DESCRIPTOR_SIZE { return Err(VerityError::TruncatedDescriptor); }
    if bytes.len() > MAX_DESCRIPTOR_SIZE { return Err(VerityError::DescriptorTooLarge); }
    let mut root_hash = [0u8; MAX_ROOT_HASH];
    root_hash.copy_from_slice(&bytes[D_ROOT_HASH..D_ROOT_HASH + MAX_ROOT_HASH]);
    let mut salt = [0u8; MAX_SALT];
    salt.copy_from_slice(&bytes[D_SALT..D_SALT + MAX_SALT]);
    let d = Descriptor {
        version: bytes[D_VERSION],
        hash_algorithm: bytes[D_HASH_ALGORITHM],
        log_blocksize: bytes[D_LOG_BLOCKSIZE],
        salt_size: bytes[D_SALT_SIZE],
        sig_size: le32(bytes, D_SIG_SIZE),
        data_size: le64(bytes, D_DATA_SIZE),
        root_hash,
        salt,
    };
    if d.version != DESCRIPTOR_VERSION { return Err(VerityError::UnknownFormat); }
    if bytes[D_RESERVED..DESCRIPTOR_SIZE].iter().any(|&b| b != 0) {
        return Err(VerityError::ReservedSet);
    }
    if d.salt_size as usize > MAX_SALT { return Err(VerityError::BadSalt); }
    if d.sig_size as usize > bytes.len() - DESCRIPTOR_SIZE {
        return Err(VerityError::SignatureOverflow);
    }
    Ok(d)
}

/// The built-in signature appended to a descriptor, if any. # C: O(1)
pub fn signature(bytes: &[u8], d: &Descriptor) -> Result<Vec<u8>, VerityError> {
    let end = DESCRIPTOR_SIZE + d.sig_size as usize;
    Ok(bytes.get(DESCRIPTOR_SIZE..end).ok_or(VerityError::SignatureOverflow)?.to_vec())
}

/// Whether the descriptor describes THIS inode.
///
/// The declared length is the one field that ties a descriptor to a file. A
/// descriptor whose length disagrees was built over other content, so it is
/// refused rather than used against the bytes at hand.
/// # C: O(1)
pub fn check(d: &Descriptor, inode_size: u64) -> Result<(), VerityError> {
    let digest = d.digest_size()?;
    if d.log_blocksize < MIN_LOG_BLOCKSIZE { return Err(VerityError::BadBlockSize); }
    if d.block_size() < MIN_DIGESTS_PER_BLOCK * digest as u64 { return Err(VerityError::BadBlockSize); }
    if d.data_size != inode_size { return Err(VerityError::SizeMismatch); }
    Ok(())
}

/// Bytes the hash tree occupies for a file of `data_size`.
///
/// Each level hashes the level below into blocks of digests until one block
/// is left; the tree is every level but the data, stored root first. This is
/// what separates the tree from the descriptor that follows it, so a caller
/// computing it wrongly reads the tail of the tree as the descriptor.
/// # C: O(levels)
pub fn tree_size(d: &Descriptor, data_size: u64) -> Result<u64, VerityError> {
    let digest = d.digest_size()? as u64;
    let block = d.block_size();
    if block < MIN_DIGESTS_PER_BLOCK * digest { return Err(VerityError::BadBlockSize); }
    let per_block = block / digest;
    let mut blocks = data_size.div_ceil(block);
    let mut total = 0u64;
    let mut levels = 0u32;
    while blocks > 1 {
        if levels >= MAX_LEVELS { return Err(VerityError::TooManyLevels); }
        blocks = blocks.div_ceil(per_block);
        total = total.saturating_add(blocks);
        levels += 1;
    }
    Ok(total.saturating_mul(block))
}

/// Levels the tree has for a file of `data_size`. # C: O(levels)
pub fn tree_levels(d: &Descriptor, data_size: u64) -> Result<u32, VerityError> {
    let digest = d.digest_size()? as u64;
    let block = d.block_size();
    if block < MIN_DIGESTS_PER_BLOCK * digest { return Err(VerityError::BadBlockSize); }
    let per_block = block / digest;
    let mut blocks = data_size.div_ceil(block);
    let mut levels = 0u32;
    while blocks > 1 {
        if levels >= MAX_LEVELS { return Err(VerityError::TooManyLevels); }
        blocks = blocks.div_ceil(per_block);
        levels += 1;
    }
    Ok(levels)
}

/// Lay a descriptor down as its fixed part, signature appended.
///
/// The inverse of `parse`, so a record this writes is a record this reads:
/// the reserved tail stays zero and the two variable-width fields are written
/// into their fixed slots rather than packed, which is what keeps the offsets
/// of everything after them constant.
/// # C: O(signature bytes)
pub fn encode(d: &Descriptor, sig: &[u8]) -> Vec<u8> {
    let mut out = alloc::vec![0u8; DESCRIPTOR_SIZE];
    out[D_VERSION] = d.version;
    out[D_HASH_ALGORITHM] = d.hash_algorithm;
    out[D_LOG_BLOCKSIZE] = d.log_blocksize;
    out[D_SALT_SIZE] = d.salt_size;
    out[D_SIG_SIZE..D_SIG_SIZE + U32_LEN].copy_from_slice(&(sig.len() as u32).to_le_bytes());
    out[D_DATA_SIZE..D_DATA_SIZE + U64_LEN].copy_from_slice(&d.data_size.to_le_bytes());
    out[D_ROOT_HASH..D_ROOT_HASH + MAX_ROOT_HASH].copy_from_slice(&d.root_hash);
    out[D_SALT..D_SALT + MAX_SALT].copy_from_slice(&d.salt);
    out.extend_from_slice(sig);
    out
}
