//! Compressed clusters: a run of file blocks that share one compressed image.
//!
//! A compressed file's block index is not a block address. Blocks are grouped
//! into CLUSTERS of `1 << i_log_cluster_size` of them, and a cluster that was
//! compressed stores a sentinel in its FIRST address slot; the slots after it
//! hold the compressed image, and the rest of the cluster is empty. Two
//! mistakes are silent rather than loud:
//!
//! - **The sentinel is a plausible address.** Following it reads a block near
//!   the end of the device as if it were file data.
//! - **The empty slots are not a sparse file.** A cluster's unused tail reads
//!   as holes, so a reader that maps block by block returns zeroes for most of
//!   a perfectly ordinary file — no error anywhere.
//!
//! The image itself is a header — the compressed length, a checksum, and a
//! reservation — followed by the codec's own bytes. The length in the header
//! is authoritative: the codecs are told exactly that many bytes and the
//! trailing padding of the last block is not theirs to read. Output length is
//! authoritative in the other direction: a cluster always decompresses to the
//! WHOLE cluster, even when it is the file's last one and most of it is past
//! the end — the file's size, not the codec, decides where the bytes stop.
//!
//! Module manifest:
//! - `algo`:       the codec numbers, the flag word, and what this build unpacks.
//! - `cluster`:    the geometry, the header, and which addresses are data.
//! - `lz4`:        LZ4 block decoding.
//! - `lzo`:        LZO1X block decoding, with the zero-run extension.
//! - `decompress`: a cluster's stored blocks into its plain bytes.

pub mod algo;
pub mod cluster;
pub mod lz4;
pub mod lzo;
pub mod decompress;

pub use algo::{Algorithm, CompressError};
pub use cluster::{data_blocks, Geometry, Header, COMPRESS_HEADER_SIZE};
pub use decompress::{decompress_cluster, Chksum, Cluster};

#[cfg(test)]
#[path = "tests/compress.rs"]
mod tests;
