//! The shape of a compressed cluster: how many blocks it covers, which of its
//! addresses hold data, and what the stored image's header says.
//!
//! The cluster size is `1 << i_log_cluster_size`, never the stored log itself.
//! Reading the log as a count makes every cluster four blocks wide at most and
//! silently misaligns every cluster after the first — a file that reads as a
//! shuffle of its own contents rather than as an error.
//!
//! The data blocks are the run that STARTS at the slot after the sentinel and
//! ends at the first empty slot. Counting the whole cluster instead hands the
//! codec whatever the empty slots decode to; counting only the first block
//! truncates every image that needed more than one.

use crate::uapi::{le32, BLKSIZE, COMPRESS_ADDR, NEW_ADDR, NULL_ADDR};

use super::algo::{self, Algorithm, CompressError, MAX_COMPRESS_LOG_SIZE, MIN_COMPRESS_LOG_SIZE};

/// Words of reservation between the header's checksum and the codec's bytes.
pub const COMPRESS_DATA_RESERVED_SIZE: usize = 4;
/// Byte offset of the compressed length within the stored image.
pub const CLEN_OFF: usize = 0;
/// Byte offset of the checksum within the stored image.
pub const CHKSUM_OFF: usize = 4;
/// The header ahead of every stored image: length, checksum, reservation.
pub const COMPRESS_HEADER_SIZE: usize = 8 + COMPRESS_DATA_RESERVED_SIZE * 4;

/// What one file's compression is: the codec, the cluster width, and the flag
/// word that says whether a checksum is present.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Geometry {
    algorithm: Algorithm,
    log: u8,
    flag: u16,
}

impl Geometry {
    /// The geometry an inode's three stored fields describe.
    ///
    /// Both refusals happen here rather than at the first read: a cluster
    /// width the format does not admit and a codec this build cannot unpack
    /// are properties of the file, not of one cluster.
    /// # C: O(1)
    pub fn new(algorithm: u8, log_cluster_size: u8, compress_flag: u16)
        -> Result<Self, CompressError> {
        if log_cluster_size < MIN_COMPRESS_LOG_SIZE || log_cluster_size > MAX_COMPRESS_LOG_SIZE {
            return Err(CompressError::BadClusterSize(log_cluster_size));
        }
        Ok(Geometry { algorithm: algo::algorithm(algorithm)?, log: log_cluster_size, flag: compress_flag })
    }

    /// The codec this file's clusters are written with. # C: O(1)
    pub fn algorithm(&self) -> Algorithm { self.algorithm }

    /// The log of the cluster width, as stored. # C: O(1)
    pub fn log_cluster_size(&self) -> u8 { self.log }

    /// File blocks per cluster. # C: O(1)
    pub fn blocks(&self) -> usize { 1usize << self.log }

    /// Plain bytes per cluster, which is what every cluster decompresses to
    /// regardless of how much of it the file's size covers. # C: O(1)
    pub fn bytes(&self) -> usize { self.blocks() * BLKSIZE }

    /// Whether each cluster carries a checksum over its compressed bytes.
    /// # C: O(1)
    pub fn checksummed(&self) -> bool { algo::checksummed(self.flag) }

    /// The level the file was written at. # C: O(1)
    pub fn level(&self) -> u8 { algo::level(self.flag) }

    /// Which cluster a file block index falls in. # C: O(1)
    pub fn cluster_of(&self, block_index: u64) -> u64 { block_index >> self.log }

    /// The first file block index of the cluster holding `block_index`.
    /// # C: O(1)
    pub fn first_block(&self, block_index: u64) -> u64 {
        (block_index >> self.log) << self.log
    }

    /// Where a file block's bytes begin inside its decompressed cluster.
    /// # C: O(1)
    pub fn offset_in_cluster(&self, block_index: u64) -> usize {
        ((block_index - self.first_block(block_index)) as usize) * BLKSIZE
    }
}

/// Whether a stored address names real data rather than an empty slot.
///
/// Both empty spellings read as no data: never written, and reserved by an
/// allocation whose bytes have not landed.
/// # C: O(1)
pub fn is_data_addr(addr: u32) -> bool { addr != NULL_ADDR && addr != NEW_ADDR }

/// The addresses of a cluster's stored image, given the cluster's whole run of
/// addresses in file-block order.
///
/// An empty result is a cluster whose blocks were released: the sentinel is
/// there and nothing follows it, and the cluster reads as zeroes.
/// # C: O(cluster blocks)
pub fn data_blocks(addrs: &[u32]) -> Result<&[u32], CompressError> {
    let head = *addrs.first().ok_or(CompressError::NotCompressed)?;
    if head != COMPRESS_ADDR { return Err(CompressError::NotCompressed); }
    let mut n = 0usize;
    for &a in &addrs[1..] {
        // A second sentinel inside one cluster means the run of addresses was
        // not laid out as a cluster at all.
        if a == COMPRESS_ADDR { return Err(CompressError::BadLayout); }
        if !is_data_addr(a) { break; }
        n += 1;
    }
    // Live addresses after the run has ended are the same defect seen from the
    // other side: the image is not the contiguous run the reader assumes.
    if addrs[1 + n..].iter().any(|&a| is_data_addr(a)) { return Err(CompressError::BadLayout); }
    Ok(&addrs[1..1 + n])
}

/// The header ahead of a stored image.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Header {
    /// Bytes of codec output, which is what the codec is told to read — never
    /// the whole of the blocks the image occupies.
    pub clen: usize,
    /// The checksum over those bytes, meaningful only when the file's flag
    /// word asks for one.
    pub chksum: u32,
}

/// The header of a stored image, and the codec bytes it introduces.
///
/// A length past the end of the blocks the cluster stores is the one check
/// that keeps a damaged header from handing a codec a slice of the next
/// cluster.
/// # C: O(1)
pub fn header(image: &[u8]) -> Result<(Header, &[u8]), CompressError> {
    if image.len() < COMPRESS_HEADER_SIZE { return Err(CompressError::BadHeader); }
    let clen = le32(image, CLEN_OFF).ok_or(CompressError::BadHeader)? as usize;
    let chksum = le32(image, CHKSUM_OFF).ok_or(CompressError::BadHeader)?;
    let body = image.get(COMPRESS_HEADER_SIZE..).ok_or(CompressError::BadHeader)?;
    let cdata = body.get(..clen).ok_or(CompressError::BadHeader)?;
    Ok((Header { clen, chksum }, cdata))
}
