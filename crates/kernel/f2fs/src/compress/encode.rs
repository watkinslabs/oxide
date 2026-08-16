//! A cluster's plain bytes into the image the medium stores.
//!
//! Compression is not always an improvement, and the format says so in terms
//! of BLOCKS rather than bytes: an image that still needs every block of the
//! cluster has saved nothing, and one that needs more has cost space while
//! making the file slower to read. So the budget handed to the codec is
//! exactly what fits in one block fewer than the cluster, header included, and
//! a codec that cannot stay inside it is not a failure — it is the ordinary
//! answer for data that does not compress, and the cluster is stored plain.
//!
//! The header's length is the only thing that says where the codec's bytes
//! stop: the last block is padded out with zeroes, and a reader that handed
//! the padding to the codec would be decoding bytes the writer never wrote.

use alloc::vec;
use alloc::vec::Vec;

use crate::checksum;
use crate::uapi::BLKSIZE;

use super::algo::{Algorithm, CompressError};
use super::cluster::{Geometry, CHKSUM_OFF, CLEN_OFF, COMPRESS_HEADER_SIZE};
use super::{lz4_enc, lzo_enc};

/// One cluster's stored image, whole blocks of it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Image {
    /// The header, the codec's bytes, and the last block's zero padding.
    pub bytes: Vec<u8>,
    /// Bytes of codec output, which is what the header records.
    pub clen: usize,
    /// Blocks the image occupies, always at least one fewer than the cluster.
    pub blocks: usize,
}

/// What a cluster's bytes became.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Stored {
    Compressed(Image),
    /// Compression did not save a whole block, so the cluster keeps its plain
    /// blocks and no sentinel.
    Plain,
}

/// The most codec output a cluster may carry.
///
/// One block of the cluster is given up so that a compressed cluster always
/// occupies fewer blocks than a plain one; the header comes out of what is
/// left, because it is stored in those same blocks.
/// # C: O(1)
pub fn max_clen(g: &Geometry) -> usize {
    (g.blocks() - 1) * BLKSIZE - COMPRESS_HEADER_SIZE
}

/// Compress one whole cluster.
///
/// `plain` is exactly `Geometry::bytes()`; a cluster is compressed as a whole
/// even when the file's size stops part way through it, because the stored
/// image describes the cluster and not the file.
/// # C: O(cluster bytes)
pub fn compress_cluster(g: &Geometry, plain: &[u8]) -> Result<Stored, CompressError> {
    if plain.len() != g.bytes() { return Err(CompressError::NotAWholeCluster); }
    let budget = max_clen(g);
    let mut cdata = vec![0u8; budget];
    let produced = match g.algorithm() {
        Algorithm::Lz4 => lz4_enc::compress(plain, &mut cdata),
        Algorithm::Lzo => lzo_enc::compress(plain, &mut cdata, false),
        Algorithm::LzoRle => lzo_enc::compress(plain, &mut cdata, true),
        other => return Err(CompressError::UnsupportedAlgorithm(other)),
    };
    // A codec that ran out of budget has said the data does not compress; the
    // cluster is stored plain rather than as an image that will not fit.
    let Some(clen) = produced else { return Ok(Stored::Plain) };
    if clen == 0 || clen > budget { return Ok(Stored::Plain); }
    Ok(Stored::Compressed(image(g, &cdata[..clen])))
}

/// Wrap codec output in the header the reader expects, padded to blocks.
/// # C: O(image bytes)
pub fn image(g: &Geometry, cdata: &[u8]) -> Image {
    let clen = cdata.len();
    let blocks = (clen + COMPRESS_HEADER_SIZE).div_ceil(BLKSIZE);
    let mut bytes = vec![0u8; blocks * BLKSIZE];
    bytes[CLEN_OFF..CLEN_OFF + 4].copy_from_slice(&(clen as u32).to_le_bytes());
    // A checksum is written only when the file asks for one; the word is zero
    // otherwise, and a reader that checked it regardless would refuse every
    // cluster written by a file that does not keep them.
    let chksum = if g.checksummed() { checksum::crc32(cdata) } else { 0 };
    bytes[CHKSUM_OFF..CHKSUM_OFF + 4].copy_from_slice(&chksum.to_le_bytes());
    bytes[COMPRESS_HEADER_SIZE..COMPRESS_HEADER_SIZE + clen].copy_from_slice(cdata);
    Image { bytes, clen, blocks }
}
