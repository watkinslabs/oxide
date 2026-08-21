//! Ordered whole-system filesystem sync/freeze ownership for hibernation.

use alloc::sync::Arc;
use alloc::vec::Vec;

use power::{Error, KResult};
use vfs::superblock::SuperBlock;

/// Exact live superblocks frozen by one hibernation transaction.
#[must_use = "the transaction must retain this set until filesystems are thawed"]
pub struct FrozenFilesystems { supers: Vec<Arc<SuperBlock>> }

impl FrozenFilesystems {
    /// Freeze every currently live superblock in reverse registry order.
    /// A partial failure thaws exactly the successful prefix. # C: O(superblocks + dirty data)
    /// # Sleeps: yes
    pub fn freeze() -> KResult<Self> {
        let mut supers = vfs::superblock::fs_supers();
        let mut frozen: Vec<Arc<SuperBlock>> = Vec::new();
        frozen.try_reserve_exact(supers.len()).map_err(|_| Error::Nomem)?;
        while let Some(sb) = supers.pop() {
            if !vfs::superblock::sb_iterable(sb.is_mounted(), sb.s_root().is_some()) { continue; }
            if !sb.s_op.power_freeze_capable() { continue; }
            if let Err(error) = sb.freeze_super() {
                for prior in frozen.iter().rev() {
                    let _ = prior.thaw_super();
                }
                return Err(map_error(error));
            }
            frozen.push(sb);
        }
        Ok(Self { supers: frozen })
    }

    /// Thaw the exact frozen set in forward registry order. # C: O(superblocks)
    /// # Sleeps: yes
    pub fn thaw(mut self) {
        for sb in self.supers.drain(..).rev() {
            let _ = sb.thaw_super();
        }
    }
}

/// Synchronize every live superblock without retaining a second registry.
/// # C: O(superblocks + dirty data)
/// # Sleeps: yes
pub fn sync_all() -> KResult<()> {
    let mut result = Ok(());
    vfs::superblock::iterate_supers(|sb| {
        if result.is_ok() { result = sb.sync_filesystem().map_err(map_error); }
    });
    result
}

fn map_error(error: vfs::VfsError) -> Error {
    match error {
        vfs::VfsError::Ebusy => Error::Busy,
        vfs::VfsError::Enomem => Error::Nomem,
        vfs::VfsError::Eintr => Error::Intr,
        _ => Error::Io,
    }
}
