//! zsmalloc ownership of PMM movable-frame isolation and replacement.

use block::{BlockError, KResult};
use movable::OwnerId;

use super::pool::ZsPool;

/// Canonical zsmalloc backend accounting, derived from live zspages only.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ZsPoolStats { pub(super) pages: usize, pub(super) zspages: usize, pub(super) objects: usize, pub(super) can_compact: bool }

impl ZsPool {
    /// Bind this pool to its sole PMM movable-owner identity before allocation. # C: O(1)
    pub(crate) fn bind_owner(&mut self, owner: OwnerId) -> KResult<()> {
        let hosted_fixture = self.owner == Some(OwnerId { slot: 0, generation: 0 });
        if (!hosted_fixture && self.owner.is_some()) || self.zspages.iter().any(Option::is_some) { return Err(BlockError::Ebusy); }
        self.owner = Some(owner);
        Ok(())
    }
    /// Current PMM movable-owner identity. # C: O(1)
    pub(crate) fn owner(&self) -> Option<OwnerId> { self.owner }
    /// Isolate one zspage frame so reset/free cannot retire it mid-migration. # C: O(zspages)
    pub(crate) fn isolate_frame(&mut self, pa: u64) -> bool {
        for page in self.zspages.iter_mut().flatten() {
            if let Some(index) = page.frames.iter().position(|frame| *frame == pa) {
                if page.isolated[index] { return false; }
                page.isolated[index] = true;
                return true;
            }
        }
        false
    }
    /// Copy and replace one PMM-isolated zspage frame without changing handles. # C: O(zspages)
    pub(crate) fn migrate_isolated_frame(&mut self, source: u64, destination: u64) -> KResult<()> {
        let provider = self.provider.ok_or(BlockError::Enomem)?;
        for page in self.zspages.iter_mut().flatten() {
            if let Some(index) = page.frames.iter().position(|frame| *frame == source) {
                if !page.isolated[index] { return Err(BlockError::Ebusy); }
                let source_ptr = (provider.page_ptr)(source).ok_or(BlockError::Eio)?;
                let destination_ptr = (provider.page_ptr)(destination).ok_or(BlockError::Eio)?;
                // SAFETY: PMM holds both frame locks and this pool has isolated the source membership until replacement commits.
                unsafe { core::ptr::copy_nonoverlapping(source_ptr, destination_ptr, hal::PAGE_SIZE_BYTES as usize); }
                page.frames[index] = destination;
                page.isolated[index] = false;
                return Ok(());
            }
        }
        Err(BlockError::Eio)
    }
    /// Return one failed PMM migration frame to normal zspage ownership. # C: O(zspages)
    pub(crate) fn putback_frame(&mut self, pa: u64) {
        for page in self.zspages.iter_mut().flatten() {
            if let Some(index) = page.frames.iter().position(|frame| *frame == pa) { page.isolated[index] = false; return; }
        }
    }
    #[cfg(test)]
    pub(super) fn first_frame_for_test(&self) -> KResult<u64> { self.zspages.iter().flatten().next().and_then(|page| page.frames.first()).copied().ok_or(BlockError::Eio) }
    #[cfg(test)]
    pub(super) fn allocate_destination_for_test(&self) -> KResult<u64> { let provider = self.provider.ok_or(BlockError::Enomem)?; let pa = if provider.legacy_test_pages { (provider.alloc_object_page)() } else { (provider.alloc_movable_page)(self.owner.ok_or(BlockError::Enomem)?) }; pa.ok_or(BlockError::Enomem) }
    #[cfg(test)]
    pub(super) fn release_detached_for_test(&self, pa: u64) -> KResult<()> { let provider = self.provider.ok_or(BlockError::Enomem)?; if provider.legacy_test_pages { (provider.release_object_page)(pa); Ok(()) } else { ((provider.release_movable_page)(self.owner.ok_or(BlockError::Enomem)?, pa)).then_some(()).ok_or(BlockError::Eio) } }
}
