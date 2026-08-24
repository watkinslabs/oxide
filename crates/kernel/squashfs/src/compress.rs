//! Which decompressor an image's compressor identifier names, and what it does
//! to one block.
//!
//! Two rules hold for every codec here, and both exist because a compressed
//! block's declared output length comes off the medium:
//!
//! - The destination is sized by the CALLER, from the format's own rules; the
//!   codec never grows it.
//! - A block that decodes to a different length than the caller expected is an
//!   error, not a short read. A tail block is the one case where less is
//!   correct, and the caller states that by asking for exactly the tail's
//!   length.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::uapi::comp;

/// A codec an image may be built with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Codec {
    Zlib,
    Lzo,
    Lz4,
    Zstd,
}

/// Why an image's compressor cannot be used.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// The identifier names a codec the format defines but this build has no
    /// decoder for. The mount refuses; it does not fall back.
    Unsupported(u16),
    /// The identifier is not one the format defines at all.
    Unknown(u16),
}

impl Codec {
    /// Resolve an image's compressor identifier.
    ///
    /// LZMA and XZ are refused with [`CodecError::Unsupported`] and not with
    /// [`CodecError::Unknown`]: the format defines them, and the distinction is
    /// what tells a reader whose image is merely unreadable here from one whose
    /// superblock is corrupt.
    /// # C: O(1)
    pub fn from_id(id: u16) -> Result<Self, CodecError> {
        match id {
            comp::ZLIB => Ok(Self::Zlib),
            comp::LZO => Ok(Self::Lzo),
            comp::LZ4 => Ok(Self::Lz4),
            comp::ZSTD => Ok(Self::Zstd),
            comp::LZMA | comp::XZ => Err(CodecError::Unsupported(id)),
            other => Err(CodecError::Unknown(other)),
        }
    }

    /// The name a log line reports. # C: O(1)
    pub fn name(self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Lzo => "lzo",
            Self::Lz4 => "lz4",
            Self::Zstd => "zstd",
        }
    }

    /// Decompress `src` into AT MOST `max` bytes, returning what came out.
    ///
    /// `max` is the ceiling the FORMAT gives for this kind of block — the
    /// metadata block size, or the image's data block size — never a number
    /// read off the medium. A block that would produce more is corrupt and
    /// fails inside the backend's own bounds check, before anything is written
    /// past the allocation.
    /// # C: O(max)
    pub fn decompress_bounded(self, src: &[u8], max: usize) -> Result<Vec<u8>, Errno> {
        if src.is_empty() || max == 0 { return Err(Errno::Eio); }
        let out = match self {
            Self::Zlib => zlib(src, max)?,
            Self::Lzo => lzo(src, max)?,
            Self::Lz4 => lz4(src, max)?,
            Self::Zstd => zstd_block(src, max)?,
        };
        if out.len() > max { return Err(Errno::Eio); }
        Ok(out)
    }

    /// Decompress `src` into EXACTLY `out_len` bytes.
    ///
    /// Used where the format states the decompressed length rather than
    /// bounding it; a different count means the wrong bytes were handed over.
    /// # C: O(out_len)
    pub fn decompress_exact(self, src: &[u8], out_len: usize) -> Result<Vec<u8>, Errno> {
        let out = self.decompress_bounded(src, out_len)?;
        if out.len() != out_len { return Err(Errno::Eio); }
        Ok(out)
    }
}

/// A zlib-wrapped DEFLATE stream, bounded by the expected output length so a
/// crafted stream cannot make the decoder write past it.
/// Keep the backend's DEFLATE workspace out of the filesystem caller. The
/// Linux uses the same `noinline_for_stack` discipline around large working
/// sets: zlib's bounded inflate state is materially larger than the
/// metadata/namei working set around it.
#[inline(never)]
fn zlib(src: &[u8], out_len: usize) -> Result<Vec<u8>, Errno> {
    let mut out = alloc::vec![0u8; out_len];
    let (decoded, status) = zlib_rs::decompress_slice(
        &mut out,
        src,
        zlib_rs::InflateConfig { window_bits: 15 },
    );
    if status != zlib_rs::ReturnCode::Ok { return Err(Errno::Eio); }
    let decoded_len = decoded.len();
    out.truncate(decoded_len);
    Ok(out)
}

#[inline(never)]
fn lzo(src: &[u8], out_len: usize) -> Result<Vec<u8>, Errno> {
    let mut out = alloc::vec![0u8; out_len];
    let got = lzo1x::decode::decompress(src, &mut out).map_err(|_| Errno::Eio)?;
    out.truncate(got);
    Ok(out)
}

#[inline(never)]
fn lz4(src: &[u8], out_len: usize) -> Result<Vec<u8>, Errno> {
    let mut out = alloc::vec![0u8; out_len];
    let got = lz4_flex::block::decompress_into(src, &mut out).map_err(|_| Errno::Eio)?;
    out.truncate(got);
    Ok(out)
}

#[inline(never)]
fn zstd_block(src: &[u8], out_len: usize) -> Result<Vec<u8>, Errno> {
    let mut out = alloc::vec![0u8; out_len];
    let got = zstd::decompress_into(src, &mut out).map_err(|_| Errno::Eio)?;
    out.truncate(got);
    Ok(out)
}

#[cfg(test)]
#[path = "tests/compress.rs"]
mod tests;
