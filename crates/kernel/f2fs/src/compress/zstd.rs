//! Zstandard clusters, through the shared codec.
//!
//! Unlike LZ4 and LZO, whose bitstreams are decoded by this crate's own
//! readers, Zstandard is a framed format with entropy tables and a shared
//! implementation already exists. This module is the adapter and nothing else:
//! it says what a cluster's budget means to that encoder, what a stored level
//! means, and how the two error vocabularies line up.
//!
//! Two properties of the format matter to a cluster and are easy to get wrong:
//!
//! - **A cluster is not one block.** The widest cluster the format admits is
//!   256 blocks, a megabyte, and a Zstandard block tops out at 128 KiB — so a
//!   wide cluster is a MULTI-block frame, and an encoder that emitted one
//!   block per frame would write something a conforming decoder still reads
//!   but at a ratio the level asked to avoid.
//! - **The decode must be bounded by the cluster.** A frame carries no honest
//!   statement of its decoded size, and three header bytes name 128 KiB of
//!   run-length output. The destination is exactly one cluster and the codec
//!   is told so, which is the same bound the reference puts on its output
//!   buffer; without it a crafted image names terabytes and the mount tries
//!   to allocate them.

use ::zstd as codec;

use super::algo::CompressError;

/// The level a file carries when it was written without asking for one.
///
/// The stored byte is zero in that case, and zero is not a Zstandard level:
/// the format's own floor is below zero, so the byte cannot spell it, and a
/// writer that passed the zero through would be asking for a level the codec
/// does not have.
pub const DEFAULT_LEVEL: u8 = 1;

/// The highest stored level that still asks for the cheapest search.
///
/// The bands below are where the format's own reference implementation
/// changes match-finder strategy — a fast single-pass search up to the first
/// boundary, a lazy search to the second, an optimal parse above it. The
/// encoder here has three efforts and no more, so a level is mapped onto the
/// band it belongs to rather than onto a depth nothing here honours.
pub const FAST_MAX_LEVEL: u8 = 4;
/// The highest stored level that asks for the middle search.
pub const DEFAULT_MAX_LEVEL: u8 = 12;

/// The effort a stored level asks for. # C: O(1)
pub fn effort(level: u8) -> codec::Level {
    match if level == 0 { DEFAULT_LEVEL } else { level } {
        0..=FAST_MAX_LEVEL => codec::Level::Fast,
        l if l <= DEFAULT_MAX_LEVEL => codec::Level::Default,
        _ => codec::Level::Best,
    }
}

/// Compress one cluster into `dst`, returning the frame's length.
///
/// `None` is the ordinary answer for data that does not compress into the
/// caller's budget, matching what the other encoders here report: the caller
/// stores the cluster plain rather than an image that will not fit.
/// # C: O(cluster bytes)
pub fn compress(src: &[u8], dst: &mut [u8], level: u8) -> Option<usize> {
    codec::compress_into(src, dst, effort(level)).ok()
}

/// Decompress one cluster's codec bytes into `dst`, returning what came out.
///
/// `dst` is a whole cluster and is the ceiling: a frame that decodes to more
/// than one cluster is refused mid-decode rather than after it.
/// # C: O(cluster bytes)
pub fn decompress(src: &[u8], dst: &mut [u8]) -> Result<usize, CompressError> {
    codec::decompress_into(src, dst).map_err(|_| CompressError::Decode)
}
