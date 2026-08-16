// The FUSE transport seam, as this filesystem sees it.
//
// The traits themselves live in the `fuse-transport` crate: the connection is a
// kernel filesystem and the virtio transport is a device driver, so neither may
// depend on the other and the seam has to sit below both. Re-exported here so
// every FUSE-side caller names one path.

pub use fuse_transport::{FuseReplySink, FuseTransportOps, FuseTransportRef};
