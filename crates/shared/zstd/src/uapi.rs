// Zstandard wire-format constants (RFC 8878). Numbers only — no policy.

/// Frame magic, little-endian on the wire.
pub const MAGIC: u32 = 0xFD2F_B528;
/// Skippable-frame magic range: `MAGIC_SKIPPABLE_LOW ..= MAGIC_SKIPPABLE_LOW | 0xF`.
pub const MAGIC_SKIPPABLE_LOW: u32 = 0x184D_2A50;
pub const MAGIC_SKIPPABLE_MASK: u32 = 0xFFFF_FFF0;

/// Frame header descriptor bit layout.
pub const FHD_FRAME_CONTENT_SIZE_SHIFT: u8 = 6;
pub const FHD_SINGLE_SEGMENT: u8 = 1 << 5;
pub const FHD_RESERVED: u8 = 1 << 3;
pub const FHD_CONTENT_CHECKSUM: u8 = 1 << 2;
pub const FHD_DICTIONARY_ID_MASK: u8 = 0b11;

/// Window descriptor: `(exponent, mantissa)` -> window size.
pub const WINDOW_LOG_MIN: u32 = 10;
pub const WINDOW_MANTISSA_MASK: u8 = 0b111;
pub const WINDOW_EXPONENT_SHIFT: u8 = 3;

/// Largest window this decoder will honour. zram compresses one page, so a
/// conforming producer never asks for more than 1 MiB; the ceiling exists so a
/// corrupt header cannot ask the kernel for a gigabyte.
pub const WINDOW_LOG_MAX: u32 = 27;

/// Block header: 3 bytes, little-endian.
pub const BLOCK_HEADER_LEN: usize = 3;
pub const BLOCK_LAST_MASK: u32 = 1;
pub const BLOCK_TYPE_SHIFT: u32 = 1;
pub const BLOCK_TYPE_MASK: u32 = 0b11;
pub const BLOCK_SIZE_SHIFT: u32 = 3;
/// Format ceiling on one block's decompressed size.
pub const BLOCK_SIZE_MAX: usize = 128 * 1024;

pub const BLOCK_TYPE_RAW: u32 = 0;
pub const BLOCK_TYPE_RLE: u32 = 1;
pub const BLOCK_TYPE_COMPRESSED: u32 = 2;
pub const BLOCK_TYPE_RESERVED: u32 = 3;

/// Literals section header, first two bits.
pub const LITERALS_TYPE_RAW: u8 = 0;
pub const LITERALS_TYPE_RLE: u8 = 1;
pub const LITERALS_TYPE_HUFFMAN: u8 = 2;
pub const LITERALS_TYPE_HUFFMAN_REUSE: u8 = 3;
pub const LITERALS_TYPE_MASK: u8 = 0b11;
pub const LITERALS_SIZE_FORMAT_SHIFT: u8 = 2;
pub const LITERALS_SIZE_FORMAT_MASK: u8 = 0b11;
/// Format ceiling on one block's literals.
pub const LITERALS_MAX: usize = BLOCK_SIZE_MAX;

/// Sequence-count header escape thresholds.
pub const SEQ_COUNT_ONE_BYTE_MAX: u8 = 127;
pub const SEQ_COUNT_TWO_BYTE_MARKER: u8 = 255;
pub const SEQ_COUNT_TWO_BYTE_BASE: u32 = 0x7F00;

/// Symbol-compression-mode field: two bits per table, in the order
/// literal-lengths, offsets, match-lengths.
pub const SEQ_MODE_PREDEFINED: u8 = 0;
pub const SEQ_MODE_RLE: u8 = 1;
pub const SEQ_MODE_FSE: u8 = 2;
pub const SEQ_MODE_REPEAT: u8 = 3;
pub const SEQ_MODE_MASK: u8 = 0b11;
pub const SEQ_MODE_LL_SHIFT: u8 = 6;
pub const SEQ_MODE_OF_SHIFT: u8 = 4;
pub const SEQ_MODE_ML_SHIFT: u8 = 2;

/// Maximum FSE accuracy log, per table (RFC 8878 3.1.1.3.2.1).
pub const ACCURACY_LOG_MAX_LL: u32 = 9;
pub const ACCURACY_LOG_MAX_OF: u32 = 8;
pub const ACCURACY_LOG_MAX_ML: u32 = 9;
/// Maximum accuracy log for the Huffman weight table.
pub const ACCURACY_LOG_MAX_HUFF: u32 = 6;

/// Highest symbol each sequence table can encode.
pub const MAX_LL_CODE: u8 = 35;
pub const MAX_OF_CODE: u8 = 31;
pub const MAX_ML_CODE: u8 = 52;

/// Huffman: maximum code length, and hence table size.
pub const HUFF_MAX_BITS: u32 = 11;
pub const HUFF_MAX_SYMBOLS: usize = 256;

/// Xxh64 seed the frame checksum uses, and the width of the stored digest.
pub const CHECKSUM_SEED: u64 = 0;
pub const CHECKSUM_LEN: usize = 4;
