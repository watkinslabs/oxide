//! A cluster's stored blocks into the cluster's plain bytes.
//!
//! One cluster always yields a WHOLE cluster of bytes. The codec is not
//! allowed to decide otherwise: a short result means the stored image and the
//! recorded cluster width disagree, and padding it out would hand the file
//! zeroes it never contained. Where the file actually stops is the inode's
//! size, applied by the caller after this.
//!
//! The checksum is advisory in the same way it is on the medium: a mismatch
//! says the volume needs checking, and the bytes are still what the codec
//! produced. Refusing the read instead would make one damaged checksum word
//! hide a file that is otherwise intact.

use alloc::vec;
use alloc::vec::Vec;

use crate::checksum;

use super::algo::{Algorithm, CompressError};
use super::cluster::{header, Geometry};
use super::{lz4, lzo};

/// What became of the checksum over a cluster's compressed bytes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Chksum {
    /// The file does not ask for one.
    Absent,
    Ok,
    Mismatch { stored: u32, computed: u32 },
}

/// One cluster's worth of plain bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Cluster {
    /// Exactly `Geometry::bytes()` of them.
    pub data: Vec<u8>,
    pub chksum: Chksum,
}

/// Decompress one cluster.
///
/// `image` is the cluster's stored blocks joined in address order, which is
/// what the addresses from `data_blocks` read back to. An EMPTY image is a
/// cluster whose blocks were released: the sentinel is on the medium and
/// nothing follows it, and the cluster reads as zeroes.
/// # C: O(cluster bytes)
pub fn decompress_cluster(g: &Geometry, image: &[u8]) -> Result<Cluster, CompressError> {
    let rlen = g.bytes();
    if image.is_empty() { return Ok(Cluster { data: vec![0u8; rlen], chksum: Chksum::Absent }); }
    let (h, cdata) = header(image)?;
    let mut data = vec![0u8; rlen];
    let produced = match g.algorithm() {
        Algorithm::Lz4 => lz4::decompress(cdata, &mut data).map_err(|_| CompressError::Decode)?,
        Algorithm::Lzo | Algorithm::LzoRle => {
            lzo::decompress(cdata, &mut data).map_err(|_| CompressError::Decode)?
        }
        // Reached only if the support table and this dispatch disagree; the
        // geometry refuses an unpackable codec when the file is opened.
        other => return Err(CompressError::UnsupportedAlgorithm(other)),
    };
    if produced != rlen { return Err(CompressError::ShortOutput); }
    let chksum = if g.checksummed() {
        let computed = checksum::crc32(cdata);
        if computed == h.chksum { Chksum::Ok } else { Chksum::Mismatch { stored: h.chksum, computed } }
    } else {
        Chksum::Absent
    };
    Ok(Cluster { data, chksum })
}
