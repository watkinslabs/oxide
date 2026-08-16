//! Which codecs the format names, which of them this build unpacks, and how a
//! refusal is spelled.
//!
//! The stored algorithm is a bare number with no self-description, so a volume
//! written by a kernel with a codec this build lacks is indistinguishable from
//! one written by a codec that exists — until the bytes come out wrong. That
//! is why an unpackable codec and an unknown number are DIFFERENT errors: only
//! one of them means the volume is damaged, and returning the compressed bytes
//! as if they were the file is never an answer.

use syscall::errno::Errno;

/// The stored algorithm numbers.
pub const COMPRESS_LZO: u8 = 0;
pub const COMPRESS_LZ4: u8 = 1;
pub const COMPRESS_ZSTD: u8 = 2;
pub const COMPRESS_LZORLE: u8 = 3;
/// One past the last number the format defines.
pub const COMPRESS_MAX: u8 = 4;

/// Bit 0 of the flag word: every cluster carries a checksum over its
/// compressed bytes.
pub const COMPRESS_CHKSUM: u16 = 1 << 0;
/// The flag word's upper byte is the level the file was written at, not a flag.
pub const COMPRESS_LEVEL_OFFSET: u32 = 8;
/// The flag bits, once the level is taken off the top.
pub const COMPRESS_FLAG_MASK: u16 = (1 << COMPRESS_LEVEL_OFFSET) - 1;

/// What the format admits for the log of the cluster size, in blocks.
pub const MIN_COMPRESS_LOG_SIZE: u8 = 2;
pub const MAX_COMPRESS_LOG_SIZE: u8 = 8;

/// A codec, named rather than numbered.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Algorithm {
    Lzo,
    Lz4,
    Zstd,
    /// LZO's bitstream with a run-length extension for zeroes. The stream is
    /// decoded by the same reader; only the writer differs.
    LzoRle,
}

impl Algorithm {
    /// The codec a stored number names, or `None` when it names none. # C: O(1)
    pub fn from_stored(n: u8) -> Option<Self> {
        match n {
            COMPRESS_LZO => Some(Algorithm::Lzo),
            COMPRESS_LZ4 => Some(Algorithm::Lz4),
            COMPRESS_ZSTD => Some(Algorithm::Zstd),
            COMPRESS_LZORLE => Some(Algorithm::LzoRle),
            _ => None,
        }
    }

    /// The number this codec is stored as. # C: O(1)
    pub fn stored(self) -> u8 {
        match self {
            Algorithm::Lzo => COMPRESS_LZO,
            Algorithm::Lz4 => COMPRESS_LZ4,
            Algorithm::Zstd => COMPRESS_ZSTD,
            Algorithm::LzoRle => COMPRESS_LZORLE,
        }
    }

    /// Whether this build can turn this codec's bytes back into file bytes.
    ///
    /// A `false` here is the whole reason `UnsupportedAlgorithm` exists: the
    /// caller reports that the operation is not supported, which is true,
    /// instead of a corruption error, which would be a lie about the volume.
    /// # C: O(1)
    pub fn unpacks(self) -> bool {
        match self {
            Algorithm::Lzo | Algorithm::Lz4 | Algorithm::LzoRle => true,
            Algorithm::Zstd => false,
        }
    }
}

/// Why a cluster did not become file bytes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CompressError {
    /// The stored number names no codec the format defines.
    UnknownAlgorithm(u8),
    /// A codec the format defines and this build cannot unpack.
    UnsupportedAlgorithm(Algorithm),
    /// The log of the cluster size is outside what the format admits.
    BadClusterSize(u8),
    /// The cluster's first address is not the compressed-cluster sentinel.
    NotCompressed,
    /// The addresses do not describe a cluster: a second sentinel inside it,
    /// or a live address after the run of data blocks has ended.
    BadLayout,
    /// The header is absent, or its length claims more bytes than the cluster
    /// stores.
    BadHeader,
    /// The codec refused the bytes it was given.
    Decode,
    /// The codec produced something other than a whole cluster.
    ShortOutput,
    /// A writer offered something other than a whole cluster to compress.
    NotAWholeCluster,
}

impl CompressError {
    /// The errno a caller reports for this refusal.
    ///
    /// Only the unsupported codec is `EOPNOTSUPP`; every other case says the
    /// stored bytes are wrong, and a codec that refused its input says the
    /// read failed rather than that the metadata is bad.
    /// # C: O(1)
    pub fn errno(self) -> Errno {
        match self {
            CompressError::UnsupportedAlgorithm(_) => Errno::Eopnotsupp,
            CompressError::Decode | CompressError::ShortOutput => Errno::Eio,
            // Not a property of the volume: the caller handed over the wrong
            // number of bytes, which is a defect here rather than there.
            CompressError::NotAWholeCluster => Errno::Einval,
            _ => Errno::Euclean,
        }
    }
}

/// The codec a stored number names, refusing one this build cannot unpack.
/// # C: O(1)
pub fn algorithm(stored: u8) -> Result<Algorithm, CompressError> {
    let a = Algorithm::from_stored(stored).ok_or(CompressError::UnknownAlgorithm(stored))?;
    if !a.unpacks() { return Err(CompressError::UnsupportedAlgorithm(a)); }
    Ok(a)
}

/// The level the flag word carries, which is the writer's business and not
/// the reader's: no codec here needs it to decode. # C: O(1)
pub fn level(flag: u16) -> u8 { (flag >> COMPRESS_LEVEL_OFFSET) as u8 }

/// Whether the flag word asks for a per-cluster checksum. # C: O(1)
pub fn checksummed(flag: u16) -> bool { flag & COMPRESS_FLAG_MASK & COMPRESS_CHKSUM != 0 }
