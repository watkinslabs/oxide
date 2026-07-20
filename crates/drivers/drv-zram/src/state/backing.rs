use alloc::string::String;
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
    pub(super) fn from_dev_text(text: &str) -> KResult<Self> {
        let text = text.strip_suffix('\n').unwrap_or(text);
        let Some(name) = text.strip_prefix("/dev/") else { return Err(BlockError::Einval); };
        if name.is_empty() || name.contains('/') { return Err(BlockError::Einval); }
        let disk = block::registry::by_name(name).ok_or(BlockError::Enxio)?;
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
        let path = alloc::format!("/dev/{}", disk.name);
        Ok(Self { path, disk, blocks_per_page, extents })
    }
}
