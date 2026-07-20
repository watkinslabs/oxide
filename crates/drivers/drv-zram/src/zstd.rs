//! Linux zram Zstandard backend using standard RFC 8878 frames.

use alloc::vec::Vec;

use block::{BlockError, KResult};
use structured_zstd::decoding::FrameDecoder;
use structured_zstd::encoding::{CompressionLevel, compress_slice_to_vec};

/// Generic zcomp value meaning this backend selects its upstream default.
const PARAM_NOT_SET: i32 = crate::deflate::PARAM_NOT_SET;

fn configured_level(level: i32) -> KResult<CompressionLevel> {
    let level = if level == PARAM_NOT_SET { CompressionLevel::DEFAULT_LEVEL } else { level };
    if !(CompressionLevel::MIN_LEVEL..=CompressionLevel::MAX_LEVEL).contains(&level) {
        return Err(BlockError::Einval);
    }
    Ok(CompressionLevel::from_level(level))
}

/// Validate the selected zstd level before zram allocates its device state.
/// # C: O(1)
pub(super) fn validate_initialization(level: i32) -> KResult<()> {
    configured_level(level)?;
    Ok(())
}

/// Compress a page as one standard Zstandard frame.
/// # C: O(page bytes × selected compression level)
pub(super) fn compress(bytes: &[u8], level: i32) -> KResult<Vec<u8>> {
    Ok(compress_slice_to_vec(bytes, configured_level(level)?))
}

/// Decode exactly one Zstandard frame into one zram page.
/// # C: O(frame bytes + page bytes)
pub(super) fn decompress(bytes: &[u8], page: &mut [u8]) -> KResult<()> {
    let written = FrameDecoder::new().decode_all(bytes, page).map_err(|_| BlockError::Eio)?;
    if written != page.len() { return Err(BlockError::Eio); }
    Ok(())
}
