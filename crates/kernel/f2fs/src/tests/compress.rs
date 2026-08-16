//! Compressed clusters, built byte by byte from the on-disk format.
//!
//! Module manifest:
//! - `build`:    stream and cluster builders, including a small LZ4 encoder.
//! - `lz4`:      the LZ4 sequence decoder, every boundary of it.
//! - `lzo`:      the LZO1X command decoder and the zero-run extension.
//! - `cluster`:  geometry, the stored header, and which addresses hold data.
//! - `dispatch`: codec policy, checksums, and whole clusters.

#[path = "compress/build.rs"]
mod build;
#[path = "compress/lz4.rs"]
mod lz4;
#[path = "compress/lzo.rs"]
mod lzo;
#[path = "compress/cluster.rs"]
mod cluster;
#[path = "compress/dispatch.rs"]
mod dispatch;
