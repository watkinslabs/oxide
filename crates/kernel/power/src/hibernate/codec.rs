//! Bounded persistent-image compression chunks per `32b§8`.

extern crate alloc;
use alloc::vec::Vec;

use super::format::PAGE_SIZE;
use super::image::{Compression, Error};

pub const CHUNK_PAGES: usize = 32;
pub const CHUNK_BYTES: usize = CHUNK_PAGES * PAGE_SIZE;
pub const LENGTH_BYTES: usize = core::mem::size_of::<u64>();
const ENCODE_BYTES: usize = lz4_flex::block::get_maximum_output_size(CHUNK_BYTES);

/// Largest accepted encoded payload for one full logical chunk. # C: O(1)
pub const fn worst_size(bytes: usize) -> usize { bytes + bytes / 16 + 64 + 3 + 2 }

pub struct Encoder {
    encoded: Vec<u8>,
    lzo: lzo1x::encode::Workspace,
}

impl Encoder {
    /// Allocate one reusable bounded encoder workspace. # C: O(CHUNK_BYTES)
    pub fn new() -> Self {
        Self { encoded: alloc::vec![0u8; ENCODE_BYTES],
            lzo: lzo1x::encode::Workspace::new() }
    }

    /// Encode one nonempty bounded integral-page chunk. # C: O(bytes)
    pub fn encode(&mut self, codec: Compression, input: &[u8]) -> Result<&[u8], Error> {
        if input.is_empty() || input.len() > CHUNK_BYTES || input.len() % PAGE_SIZE != 0 {
            return Err(Error::Format);
        }
        let len = match codec {
            Compression::None => return Err(Error::Format),
            Compression::Lzo => lzo1x::encode::compress_with(input, &mut self.encoded, false,
                &mut self.lzo).ok_or(Error::Format)?,
            Compression::Lz4 => lz4_flex::block::compress_into(input, &mut self.encoded)
                .map_err(|_| Error::Format)?,
        };
        if len == 0 || len > worst_size(input.len()) { return Err(Error::Format); }
        Ok(&self.encoded[..len])
    }
}

pub struct Decoder { encoded: Vec<u8>, decoded: Vec<u8> }

impl Decoder {
    /// Allocate one reusable bounded decoder workspace. # C: O(CHUNK_BYTES)
    pub fn new() -> Self {
        Self { encoded: Vec::with_capacity(worst_size(CHUNK_BYTES)),
            decoded: alloc::vec![0u8; CHUNK_BYTES] }
    }

    /// Begin loading one exact encoded chunk. # C: O(1)
    pub fn begin(&mut self, encoded: usize) -> Result<(), Error> {
        if encoded == 0 || encoded > worst_size(CHUNK_BYTES) { return Err(Error::Format); }
        self.encoded.clear();
        self.encoded.try_reserve(encoded.saturating_sub(self.encoded.capacity()))
            .map_err(|_| Error::Bounds)
    }

    /// Append persisted bytes to the current bounded chunk. # C: O(bytes)
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.encoded.len().checked_add(bytes.len()).ok_or(Error::Bounds)? > worst_size(CHUNK_BYTES) {
            return Err(Error::Format);
        }
        self.encoded.extend_from_slice(bytes);
        Ok(())
    }

    /// Number of encoded bytes currently loaded. # C: O(1)
    pub fn encoded_len(&self) -> usize { self.encoded.len() }

    /// Decode the loaded chunk and borrow the reusable output buffer. # C: O(CHUNK_BYTES)
    pub fn decode(&mut self, codec: Compression) -> Result<&[u8], Error> {
        let len = match codec {
            Compression::None => return Err(Error::Format),
            Compression::Lzo => lzo1x::decode::decompress(&self.encoded, &mut self.decoded)
                .map_err(|_| Error::Format)?,
            Compression::Lz4 => lz4_flex::block::decompress_into(&self.encoded, &mut self.decoded)
            .map_err(|_| Error::Format)?,
        };
        if len == 0 || len > CHUNK_BYTES || len % PAGE_SIZE != 0 { return Err(Error::Format); }
        Ok(&self.decoded[..len])
    }
}
