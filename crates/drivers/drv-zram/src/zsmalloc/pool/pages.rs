use alloc::vec::Vec;

use block::{BlockError, KResult};
use movable::OwnerId;

use super::super::class::{Fullness, SizeClass};
use super::super::handle::Handle;
use super::super::platform::PageProvider;

pub(in crate::zsmalloc) struct ZsPage {
    pub(in crate::zsmalloc) class: SizeClass,
    pub(in crate::zsmalloc) handles: Vec<Option<Handle>>,
    pub(in crate::zsmalloc) frames: Vec<u64>,
    pub(in crate::zsmalloc) isolated: Vec<bool>,
}

impl ZsPage {
    pub(in crate::zsmalloc) fn new(class: SizeClass, provider: PageProvider, owner: OwnerId) -> KResult<Self> {
        let mut handles = Vec::new();
        let mut frames = Vec::new();
        handles.try_reserve_exact(class.objects_per_zspage).map_err(|_| BlockError::Enomem)?;
        frames.try_reserve_exact(class.pages_per_zspage).map_err(|_| BlockError::Enomem)?;
        handles.resize(class.objects_per_zspage, None);
        for _ in 0..class.pages_per_zspage {
            let allocated = if provider.legacy_test_pages { (provider.alloc_object_page)() } else { (provider.alloc_movable_page)(owner) };
            let Some(pa) = allocated else {
                for pa in frames {
                    if provider.legacy_test_pages { (provider.release_object_page)(pa); }
                    else { let _ = (provider.release_movable_page)(owner, pa); }
                }
                return Err(BlockError::Enomem);
            };
            frames.push(pa);
        }
        let mut isolated = Vec::new();
        isolated.try_reserve_exact(class.pages_per_zspage).map_err(|_| BlockError::Enomem)?;
        isolated.resize(class.pages_per_zspage, false);
        Ok(Self { class, handles, frames, isolated })
    }

    pub(in crate::zsmalloc) fn free_slot(&self) -> Option<usize> { self.handles.iter().position(Option::is_none) }

    pub(in crate::zsmalloc) fn has_live_objects(&self) -> bool { self.handles.iter().any(Option::is_some) }

    pub(in crate::zsmalloc) fn live_objects(&self) -> usize { self.handles.iter().filter(|handle| handle.is_some()).count() }

    pub(in crate::zsmalloc) fn fullness(&self) -> Fullness { Fullness::from_live(self.live_objects(), self.class.objects_per_zspage) }

    pub(in crate::zsmalloc) fn copy_in(&mut self, provider: PageProvider, offset: usize, bytes: &[u8]) -> KResult<()> { self.copy_from(provider, offset, bytes) }
    pub(in crate::zsmalloc) fn copy_out(&self, provider: PageProvider, offset: usize, bytes: &mut [u8]) -> KResult<()> { self.copy_to(provider, offset, bytes) }
    fn copy_from(&self, provider: PageProvider, mut offset: usize, mut bytes: &[u8]) -> KResult<()> {
        let page = hal::PAGE_SIZE_BYTES as usize;
        while !bytes.is_empty() {
            let index = offset / page;
            let in_page = offset % page;
            let count = core::cmp::min(page - in_page, bytes.len());
            let pa = *self.frames.get(index).ok_or(BlockError::Eio)?;
            if !(provider.try_lock_page)(pa) { return Err(BlockError::Ebusy); }
            let result = (|| {
                let ptr = (provider.page_ptr)(pa).ok_or(BlockError::Eio)?;
                // SAFETY: zram owns this zspage and the provider lock excludes
                // PMM migration/I/O while this bounded page fragment is copied.
                let page_bytes = unsafe { core::slice::from_raw_parts_mut(ptr, page) };
                page_bytes[in_page..in_page + count].copy_from_slice(&bytes[..count]);
                Ok(())
            })();
            if !(provider.unlock_page)(pa) { return Err(BlockError::Eio); }
            result?;
            offset += count;
            bytes = &bytes[count..];
        }
        Ok(())
    }
    fn copy_to(&self, provider: PageProvider, mut offset: usize, mut bytes: &mut [u8]) -> KResult<()> {
        let page = hal::PAGE_SIZE_BYTES as usize;
        while !bytes.is_empty() {
            let index = offset / page;
            let in_page = offset % page;
            let count = core::cmp::min(page - in_page, bytes.len());
            let pa = *self.frames.get(index).ok_or(BlockError::Eio)?;
            if !(provider.try_lock_page)(pa) { return Err(BlockError::Ebusy); }
            let result = (|| {
                let ptr = (provider.page_ptr)(pa).ok_or(BlockError::Eio)?;
                // SAFETY: provider lock pins this owned physical page during copy.
                let page_bytes = unsafe { core::slice::from_raw_parts(ptr, page) };
                bytes[..count].copy_from_slice(&page_bytes[in_page..in_page + count]);
                Ok(())
            })();
            if !(provider.unlock_page)(pa) { return Err(BlockError::Eio); }
            result?;
            offset += count;
            bytes = &mut bytes[count..];
        }
        Ok(())
    }

    fn release(self, provider: PageProvider, owner: OwnerId) {
        for pa in self.frames {
            if provider.legacy_test_pages { (provider.release_object_page)(pa); }
            else { let _ = (provider.release_movable_page)(owner, pa); }
        }
    }
}

pub(crate) struct RetiredPages { pub(super) provider: Option<PageProvider>, pub(super) owner: Option<OwnerId>, pub(super) pages: Vec<ZsPage> }
impl RetiredPages {
    /// Release detached PMM object pages after zram serialization is dropped. # C: O(pages)
    pub(crate) fn release(self) -> KResult<()> {
        let provider = self.provider.ok_or(BlockError::Enomem)?;
        let owner = self.owner.ok_or(BlockError::Enomem)?;
        for page in self.pages { page.release(provider, owner); }
        Ok(())
    }
}

/// A physical zspage prepared without the zram State lock.  It is either
/// attached by the matching slot-generation commit or explicitly rescinded.
/// Dropping this value never releases PMM frames implicitly: callers must use
/// [`Self::rescind`] after dropping the State lock.
pub(crate) struct AllocationReservation {
    pub(super) class: SizeClass,
    pub(super) page: Option<ZsPage>,
    pub(super) provider: PageProvider,
    pub(super) owner: OwnerId,
}

/// Immutable State-lock snapshot used to reserve PMM capacity after dropping
/// zram serialization. It carries no allocated frame.
pub(crate) struct AllocationPlan { pub(super) class: SizeClass, pub(super) provider: PageProvider, pub(super) owner: OwnerId, pub(super) need_page: bool }

impl AllocationPlan {
    /// Obtain PMM frames outside the State lock. # C: O(zspage pages)
    pub(crate) fn reserve(self) -> KResult<AllocationReservation> {
        AllocationReservation::prepare(self.class, self.provider, self.owner, self.need_page)
    }
}

impl AllocationReservation {
    /// Reserve only the PMM frames a commit may need. # C: O(zspage pages)
    fn prepare(class: SizeClass, provider: PageProvider, owner: OwnerId, need_page: bool) -> KResult<Self> {
        let page = if need_page { Some(ZsPage::new(class, provider, owner)?) } else { None };
        Ok(Self { class, page, provider, owner })
    }

    /// Return unattached PMM frames after the State lock has been dropped.
    /// # C: O(zspage pages)
    pub(crate) fn rescind(mut self) {
        if let Some(page) = self.page.take() { page.release(self.provider, self.owner); }
    }
}
