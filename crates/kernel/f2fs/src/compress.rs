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
//! - `zstd`:       Zstandard clusters, through the shared codec.
//! - `decompress`: a cluster's stored blocks into its plain bytes.
//! - `lz4_enc`:    LZ4 block encoding.
//! - `lzo_enc`:    LZO1X block encoding, both variants.
//! - `encode`:     a cluster's plain bytes into the image the medium stores.
//! - `plan`:       what a rewritten cluster's slots become, and the two counts.
//! - `policy`:     which codec, which level, and which names match a list.
//! - `newfile`:    whether a file being created is created compressed.
//! - `chattr`:     turning the mark on and off after the file exists.
//! - `begin`:      what a write takes and reserves, before anything is placed.
//! - `place`:      the codec, the shape and the addresses, one cluster at a time.
//! - `writeback`:  storing and shortening a compressed file, cluster at a time.
//! - `release`:    handing the saving back to the volume, and taking it again.
//! - `rewrite`:    rewriting every cluster of one file compressed or plain.
//! - `cache`:      the mount's cache of compressed blocks as the medium holds them.

pub mod algo;
pub mod cluster;
pub mod lz4;
pub mod lzo;
pub mod zstd;
pub mod decompress;
pub mod lz4_enc;
pub mod lzo_enc;
pub mod encode;
pub mod plan;
pub mod policy;
pub mod newfile;
pub mod chattr;
pub mod begin;
pub mod place;
pub mod writeback;
pub mod release;
pub mod rewrite;
pub mod cache;

pub use algo::{Algorithm, CompressError};
pub use cluster::{data_blocks, Geometry, Header, COMPRESS_HEADER_SIZE};
pub use decompress::{decompress_cluster, decompress_cluster_into, Chksum, Cluster};
pub use encode::{compress_cluster, max_clen, Image, Stored};
pub use newfile::{decide, NewFile};
pub use plan::Slot;

#[cfg(test)]
#[path = "tests/compress.rs"]
mod tests;
