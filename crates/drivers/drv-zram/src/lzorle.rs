//! Linux LZO-RLE version-one adapter over the shared LZO1X owner.

use alloc::vec::Vec;

use block::{BlockError, KResult};

/// Produce one version-one LZO-RLE stream through the per-CPU workspace.
/// # C: O(input bytes)
pub(crate) fn compress(input: &[u8], lzo: &crate::lzo::Streams) -> KResult<Vec<u8>> {
    lzo.compress_rle(input)
}

/// Decode one complete version-zero or version-one LZO1X stream.
/// # C: O(page bytes)
pub(crate) fn decompress(input: &[u8], output: &mut [u8]) -> KResult<()> {
    let size = lzo1x::decode::decompress(input, output).map_err(|_| BlockError::Eio)?;
    if size == output.len() { Ok(()) } else { Err(BlockError::Eio) }
}
