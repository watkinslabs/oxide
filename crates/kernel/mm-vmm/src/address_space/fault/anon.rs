use alloc::sync::Arc;

use hal::UserVirtAddr;

use crate::{AnonVma, Error, KResult};

use super::super::AddressSpace;

impl AddressSpace {
    /// Return the VMA's anonymous-page owner, creating its canonical rmap
    /// edge at the first anonymous page install.
    /// # C: O(log N)
    pub(super) fn prepare_anon_vma(&self, va: UserVirtAddr) -> KResult<Arc<AnonVma>> {
        let mut tree = self.vmas.write();
        let vma = tree.find_containing_mut(va).ok_or(Error::Inval)?;
        if let Some(anon) = vma.anon_vma.as_ref() { return Ok(Arc::clone(anon)); }
        let anon = AnonVma::new();
        anon.attach(self.self_weak.clone(), vma.start.as_u64(), vma.end.as_u64());
        vma.anon_vma = Some(Arc::clone(&anon));
        Ok(anon)
    }
}

impl AddressSpace {
    /// Record that the mapping has acquired private anonymous data.
    /// # C: O(log N)
    pub(super) fn mark_anon_page(&self, va: UserVirtAddr) -> KResult<()> {
        let mut tree = self.vmas.write();
        let vma = tree.find_containing_mut(va).ok_or(Error::Inval)?;
        vma.anon_pages.store(true, core::sync::atomic::Ordering::Release);
        Ok(())
    }
}
