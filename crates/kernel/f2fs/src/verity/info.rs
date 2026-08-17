//! What a verity inode's metadata comes to, held once instead of re-derived
//! per block.
//!
//! Locating and parsing a descriptor costs a walk of the file's block index,
//! a read past the file's own length, and a parse. Doing that for every block
//! a read touches makes the metadata cost proportional to the DATA, which is
//! the opposite of what a hash tree is for. The reference keeps this beside
//! the inode for as long as the inode lives; so does this.
//!
//! The second half is the same argument one level down. A hash block near the
//! root is on the path of a very large number of data blocks, so a reader
//! that re-verifies it every time re-hashes the whole upper tree per block. A
//! bit per tree block records that the block has already been checked AGAINST
//! ITS PARENT, which is what lets the walk stop climbing.
//!
//! The bit means "verified", never "read": setting it on a block that was
//! merely fetched would make the tree attest to itself.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::descriptor::Descriptor;
use super::merkle::Params;
use super::uapi::{DESCRIPTOR_SIZE, D_SIG_SIZE, HASH_ALG_SHA256, HASH_ALG_SHA512, U32_LEN};
use super::VerityError;

/// Bits per word of the verified-block map.
const WORD_BITS: usize = 64;

/// One bit per hash block, recording whether that block has been checked
/// against the level above it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Verified {
    words: Vec<u64>,
    bits: usize,
}

impl Verified {
    /// # C: O(bits)
    pub fn new(bits: usize) -> Self {
        Self { words: alloc::vec![0u64; bits.div_ceil(WORD_BITS)], bits }
    }

    /// # C: O(1)
    pub fn bits(&self) -> usize { self.bits }

    /// Whether block `i` has been checked. An index outside the tree is not
    /// verified, and asking about one is a bug in the walk rather than a
    /// reason to widen the map. # C: O(1)
    pub fn test(&self, i: u64) -> bool {
        let i = i as usize;
        if i >= self.bits { return false; }
        self.words[i / WORD_BITS] & (1u64 << (i % WORD_BITS)) != 0
    }

    /// # C: O(1)
    pub fn set(&mut self, i: u64) {
        let i = i as usize;
        if i >= self.bits { return; }
        self.words[i / WORD_BITS] |= 1u64 << (i % WORD_BITS);
    }

    /// How many blocks are recorded as checked. # C: O(words)
    pub fn count(&self) -> u32 { self.words.iter().map(|w| w.count_ones()).sum() }
}

/// Everything a verity inode needs to have its blocks attested.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Info {
    pub params: Params,
    /// The root the walk terminates at.
    pub root_hash: Vec<u8>,
    /// The digest of the descriptor itself — what a signature signs and what
    /// a measurement reports. Not the root hash: the root says nothing about
    /// the salt, the block size or the length the tree was built over, so
    /// signing it would leave all three unattested.
    pub file_digest: Vec<u8>,
    /// The length the descriptor was resolved against. A cached entry is only
    /// for the file it was built from, and this is what says so.
    pub data_size: u64,
    pub verified: Verified,
}

impl Info {
    /// Derive everything from a descriptor and accept it under `policy`.
    ///
    /// The signature is checked HERE rather than at the first read, because
    /// this is the moment the descriptor becomes the thing every later read
    /// is measured against. Building the info and then checking would leave a
    /// window in which an unsigned root is already installed.
    /// # C: O(descriptor + chain * rsa)
    pub fn open(d: &Descriptor, sig: &[u8], data_size: u64, policy: &super::Policy)
        -> Result<Self, VerityError> {
        let info = Self::new(d, data_size)?;
        super::signature::verify(policy, d.hash_algorithm, &info.file_digest, sig)?;
        Ok(info)
    }

    /// Derive everything from a descriptor that has already been checked
    /// against the inode it belongs to, asking nothing about signatures.
    /// # C: O(descriptor + levels)
    pub fn new(d: &Descriptor, data_size: u64) -> Result<Self, VerityError> {
        let params = Params::new(d.hash_algorithm, d.log_blocksize, d.salt_used(), data_size)?;
        let root_hash = d.root_used()?.to_vec();
        let file_digest = file_digest(d)?;
        let blocks = (params.tree_size >> params.log_blocksize) as usize;
        Ok(Self { params, root_hash, file_digest, data_size, verified: Verified::new(blocks) })
    }
}

/// The digest of the descriptor, taken over its FIXED part with the signature
/// length zeroed.
///
/// Both details are load-bearing. Hashing the appended signature would make
/// the digest depend on the signature over it, which cannot be satisfied;
/// leaving the length field set would make an unsigned copy of the same file
/// measure differently from a signed one, so a signature could never be added
/// to a file already published.
/// # C: O(descriptor)
pub fn file_digest(d: &Descriptor) -> Result<Vec<u8>, VerityError> {
    let mut bytes = super::descriptor::encode(d, &[]);
    bytes.truncate(DESCRIPTOR_SIZE);
    bytes[D_SIG_SIZE..D_SIG_SIZE + U32_LEN].fill(0);
    match d.hash_algorithm {
        HASH_ALG_SHA256 => {
            let mut h = crypt::Sha256::new();
            h.update(&bytes);
            Ok(h.finish().to_vec())
        }
        HASH_ALG_SHA512 => {
            let mut h = crypt::Sha512::new();
            h.update(&bytes);
            Ok(h.finish().to_vec())
        }
        _ => Err(VerityError::UnsupportedHash),
    }
}

/// The verity info held for each inode a mount has read.
///
/// Keyed by inode number, with the length the entry was built for kept
/// beside it: an inode number is reused once the file it named is gone, and
/// serving a new file's blocks against an old file's tree would fail every
/// read — or, if the trees happened to agree in shape, pass a check that
/// proved nothing.
#[derive(Default)]
pub struct Cache {
    entries: BTreeMap<u32, Info>,
}

impl Cache {
    /// # C: O(1)
    pub fn new() -> Self { Self { entries: BTreeMap::new() } }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.entries.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// The entry for this inode, if it is for THIS file. # C: O(log n)
    pub fn get(&mut self, ino: u32, data_size: u64) -> Option<&mut Info> {
        match self.entries.get(&ino) {
            Some(i) if i.data_size == data_size => self.entries.get_mut(&ino),
            Some(_) => { self.entries.remove(&ino); None }
            None => None,
        }
    }

    /// # C: O(log n)
    pub fn insert(&mut self, ino: u32, info: Info) -> &mut Info {
        self.entries.insert(ino, info);
        self.entries.get_mut(&ino).expect("just inserted")
    }

    /// Drop what is held for one inode. Called wherever the file behind the
    /// number changes, which for a sealed file is only its sealing.
    /// # C: O(log n)
    pub fn forget(&mut self, ino: u32) { self.entries.remove(&ino); }

    /// # C: O(n)
    pub fn clear(&mut self) { self.entries.clear(); }
}

#[cfg(test)]
#[path = "../tests/verityinfo.rs"]
mod tests;
