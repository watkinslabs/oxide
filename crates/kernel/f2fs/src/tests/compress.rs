//! Compressed clusters, built byte by byte from the on-disk format.
//!
//! Module manifest:
//! - `build`:    stream and cluster builders, including a small LZ4 encoder.
//! - `lz4`:      the LZ4 sequence decoder, every boundary of it.
//! - `lzo`:      the LZO1X command decoder and the zero-run extension.
//! - `cluster`:  geometry, the stored header, and which addresses hold data.
//! - `dispatch`: codec policy, checksums, and whole clusters.
//! - `lz4_enc`:  LZ4 encoding, proved by the decoder.
//! - `lzo_enc`:  LZO1X encoding, both variants, proved by the decoder.
//! - `encode`:   whole clusters into the image the medium stores.
//! - `plan`:     what a rewritten cluster's slots become, and the two counts.
//! - `policy`:   which files get compressed, with which codec and level.
//! - `newinode`: what a newly created file is compressed with, by remounting.
//! - `write`:    writing a compressed file, proved by remounting.
//! - `defer`:    the deferred window: what a write reserves, what a placement decides.
//! - `truncate`: shortening one, proved by remounting.

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
#[path = "compress/lz4_enc.rs"]
mod lz4_enc;
#[path = "compress/lzo_enc.rs"]
mod lzo_enc;
#[path = "compress/encode.rs"]
mod encode;
#[path = "compress/plan.rs"]
mod plan;
#[path = "compress/policy.rs"]
mod policy;
#[path = "compress/newinode.rs"]
mod newinode;
#[path = "compress/write.rs"]
mod write;
#[path = "compress/defer.rs"]
mod defer;
#[path = "compress/truncate.rs"]
mod truncate;
