use alloc::sync::Arc;

/// Factory that mints the `/dev` node inode for a device (devtmpfs path).
/// Boxed + `Arc` so the registry, the `Device`, and the `DEVTMPFS_HOOK`
/// callback share one closure. `InodeRef` is the only `vfs` type drv names
/// (see Cargo.toml note on the acyclic drv->vfs edge). A device that wants a
/// bespoke `/dev` node (e.g. the mem pseudo-devices' custom `FileOps`) supplies
/// one; a plain char/block node is built from `dev_t` by devtmpfs when absent.
pub type NodeFactory = Arc<dyn Fn() -> vfs::InodeRef + Send + Sync>;
