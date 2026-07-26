// Zstandard (RFC 8878) codec. In-tree replacement for the vendored
// `structured-zstd` crate, written for the kernel's constraints rather than a
// hosted allocator's.
//
// Two reasons it exists, both measured:
//
//   STACK. The vendored crate's `FrameCompressor` is ~15.4 KiB and
//   `FrameDecoder` ~13.6 KiB BY VALUE, and six of its functions have stack
//   frames over 8 KiB — on a 16 KiB kernel stack. `#[inline(never)]` does not
//   split them (`skizm.md` Step 6b). Here every table is heap-allocated behind
//   `Decoder`/`Encoder` and no frame carries one by value.
//
//   SCOPE. zram compresses one 4 KiB page at a time with no dictionary and no
//   streaming. The vendored crate carries 22 levels, seekable frames, long
//   distance matching and a dictionary builder, none of which zram reaches.
//
// The DECODER is complete: it reads any conforming zstd frame (raw / RLE /
// Huffman literals, all four FSE table modes, the three repeat offsets). The
// ENCODER emits a conforming subset — raw literals plus predefined-table FSE
// sequences — which every zstd decoder accepts. That asymmetry is deliberate:
// what we must READ is whatever exists, what we must WRITE is only what we
// choose to write.
//
// Module manifest:
//   uapi          format constants — magic, block types, size limits
//   tables        predefined FSE distributions, LL/ML/OF baseline+extra tables
//   bits          reverse bitstream reader and writer (RFC 8878 4.1)
//   fse           FSE decode-table construction and decoder
//   fse_encode    FSE encode-table construction and encoder
//   huff          Huff0 literal decoding
//   literals      literals section
//   sequences     sequences section decode and execution
//   frame         frame and block headers
//   decode        top-level decompression
//   encode        top-level compression
//   match_finder  hash-chain greedy matcher
//   xxhash        XXH64, for the optional frame checksum

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;

mod bits;
mod decode;
mod encode;
mod frame;
mod fse;
mod fse_encode;
mod huff;
mod literals;
mod match_finder;
mod sequences;
mod tables;
mod uapi;
mod xxhash;

pub use decode::{decompress, decompress_into, Decoder};
pub use encode::{compress, compress_into, max_compressed_len, Encoder, Level};
pub use uapi::MAGIC;

/// Every way a frame can fail to decode, or a buffer fail to hold a result.
///
/// Distinct variants rather than one `Corrupt`: zram reports decompression
/// failure as an I/O error on a swap page, and when that happens the variant is
/// the only evidence of which stage disagreed with the data.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    BadMagic,
    /// Frame header reserved bit set, or a field the format forbids.
    BadFrameHeader,
    /// Frame declares a window larger than this decoder will allocate.
    WindowTooLarge,
    /// Input ended inside a header, table or bitstream.
    Truncated,
    /// Block header names the reserved block type.
    ReservedBlockType,
    /// Block larger than the format's 128 KiB ceiling.
    BlockTooLarge,
    /// FSE accuracy log above the per-table maximum, or counts that do not sum
    /// to the table size.
    BadFseTable,
    /// Huffman weights that do not form a complete prefix code.
    BadHuffmanTable,
    /// A bitstream ran out before its symbols did.
    BitstreamOverrun,
    /// A match offset points before the start of the output produced so far.
    OffsetTooLarge,
    /// Sequences did not consume exactly the literals the block declared.
    LiteralsMismatch,
    /// Decoded size exceeds the caller's buffer.
    OutputFull,
    /// XXH64 trailer disagrees with the decoded content.
    ChecksumMismatch,
    /// Frame requires a dictionary. zram never writes one.
    DictionaryRequired,
}

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;
