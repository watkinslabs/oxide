//! Linux zram raw-DEFLATE backend built with zlib-compatible stream semantics.

use alloc::vec::Vec;

use block::{BlockError, KResult};
use zlib_rs::{DeflateConfig, ReturnCode, compress_bound, compress_slice};

/// Linux zram's deflate backend default (`backend_deflate.c`).
pub(super) const PARAM_NOT_SET: i32 = i32::MIN;
pub(super) const DEFAULT_COMPRESSION_LEVEL: i32 = -1;
const DEFAULT_WINDOW_BITS: i32 = -11;
const MIN_WINDOW_BITS: i32 = -15;
const MAX_WINDOW_BITS: i32 = -9;
const MIN_COMPRESSION_LEVEL: i32 = -1;
const MAX_COMPRESSION_LEVEL: i32 = 9;

fn configured_window_bits(bits: i32) -> KResult<i32> {
    let bits = if bits == PARAM_NOT_SET { DEFAULT_WINDOW_BITS } else { bits };
    if (MIN_WINDOW_BITS..=MAX_WINDOW_BITS).contains(&bits) { Ok(bits) }
    else { Err(BlockError::Einval) }
}

/// Resolve the raw zlib history window owned by a compressor configuration.
/// # C: O(1)
pub(super) fn window_bits(level: i32, bits: i32) -> KResult<i32> {
    configured_level(level)?;
    configured_window_bits(bits)
}

fn configured_level(level: i32) -> KResult<i32> {
    let level = if level == PARAM_NOT_SET { DEFAULT_COMPRESSION_LEVEL } else { level };
    if (MIN_COMPRESSION_LEVEL..=MAX_COMPRESSION_LEVEL).contains(&level) { Ok(level) }
    else { Err(BlockError::Einval) }
}

/// Validate zlib's raw-deflate initialization parameters before device setup.
/// # C: O(1)
pub(super) fn validate_initialization(level: i32, bits: i32) -> KResult<()> {
    window_bits(level, bits)?;
    Ok(())
}

/// Compress one zram page using Linux's raw zlib stream configuration.
/// # C: O(page bytes × configured zlib level)
pub(super) fn compress(bytes: &[u8], level: i32, bits: i32) -> KResult<Vec<u8>> {
    let config = DeflateConfig { level: configured_level(level)?, window_bits: window_bits(level, bits)?, ..DeflateConfig::default() };
    let mut output = alloc::vec![0; compress_bound(bytes.len())];
    let (encoded, result) = compress_slice(&mut output, bytes, config);
    if result != ReturnCode::Ok { return Err(BlockError::Einval); }
    Ok(encoded.to_vec())
}
