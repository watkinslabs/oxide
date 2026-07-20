use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockError, KResult};

use super::PAGE_BYTES;

/// One claimed block disk used to persist zram objects selected for writeback.
/// Its bitmap is in zram-page units, independent of the backing disk sector
/// size; every selected disk must therefore divide one PMM page exactly.
pub(crate) struct Backing {
    /// Canonical `/dev/<disk-name>` path rendered by Linux `backing_dev`.
    pub(crate) path: String,
    pub(crate) disk: Arc<block::registry::Disk>,
    pub(crate) blocks_per_page: u32,
    pub(crate) extents: Vec<bool>,
}

impl Backing {
    /// Hosted fixtures lack a VFS pathname resolver, so they bind their
    /// explicitly registered test disk by its synthetic `/dev` name. Kernel
    /// builds never compile this alternate lookup path.
    #[cfg(not(target_os = "oxide-kernel"))]
    pub(super) fn from_dev_text(text: &str) -> KResult<Self> {
        let text = text.strip_suffix('\n').unwrap_or(text);
        let Some(name) = text.strip_prefix("/dev/") else { return Err(BlockError::Einval); };
        if name.is_empty() || name.contains('/') { return Err(BlockError::Einval); }
        let disk = block::registry::by_name(name).ok_or(BlockError::Enxio)?;
        Self::from_disk(alloc::format!("/dev/{}", disk.name), disk)
    }

    /// Construct backing ownership from the block disk resolved by the VFS
    /// owner.  The driver never re-resolves a pathname or invents a second
    /// block-device identity. # C: O(backing pages)
    pub(super) fn from_disk(path: String, disk: Arc<block::registry::Disk>) -> KResult<Self> {
        let block_size = disk.dev.block_size() as u64;
        if block_size == 0 || PAGE_BYTES as u64 % block_size != 0 { return Err(BlockError::Einval); }
        let blocks_per_page = u32::try_from(PAGE_BYTES as u64 / block_size).map_err(|_| BlockError::Einval)?;
        let pages = usize::try_from(disk.dev.capacity_blocks() / blocks_per_page as u64).map_err(|_| BlockError::Einval)?;
        // Linux `backing_dev_store` refuses a zero-length block device with
        // EINVAL; it also prevents a zero-capacity recursive backing cycle.
        if pages == 0 { return Err(BlockError::Einval); }
        let mut extents = Vec::new();
        extents.try_reserve_exact(pages).map_err(|_| BlockError::Enomem)?;
        extents.resize(pages, false);
        Ok(Self { path, disk, blocks_per_page, extents })
    }

    pub(super) fn disk_name(&self) -> &str { &self.disk.name }
}

impl super::Zram {
    /// Select a VFS-resolved block disk as zram backing storage. # C: O(backing pages)
    pub fn set_backing_disk(&self, path: String, disk: Arc<block::registry::Disk>) -> KResult<()> {
        self.set_backing(Backing::from_disk(path, disk)?)
    }

    /// Bind a hosted fixture's explicitly registered backing disk. Production
    /// sysfs resolves its pathname in the caller's VFS context and invokes
    /// `set_backing_disk`, so it has no second device-resolution path.
    /// # C: O(backing pages)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub fn set_backing_dev_text(&self, text: &str) -> KResult<()> {
        self.set_backing(Backing::from_dev_text(text)?)
    }

    fn set_backing(&self, backing: Backing) -> KResult<()> {
        if self.initialized() { return Err(BlockError::Ebusy); }
        if backing.disk.driver == crate::ZRAM_BLOCK_DRIVER { return Err(BlockError::Einval); }
        let name = backing.disk_name().to_string();
        if !block::registry::claim(&name) { return Err(BlockError::Enxio); }
        let mut state = self.state.lock();
        if state.size != 0 {
            drop(state);
            let _ = block::registry::release(&name);
            return Err(BlockError::Ebusy);
        }
        let replaced = state.backing.replace(backing).map(|old| old.disk_name().to_string());
        drop(state);
        if let Some(old_name) = replaced { let _ = block::registry::release(&old_name); }
        Ok(())
    }
}
