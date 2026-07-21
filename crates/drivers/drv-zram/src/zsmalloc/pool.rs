//! Stable-handle, multi-page zspage allocation and object I/O.

use alloc::vec::Vec;

use block::{BlockError, KResult};
use movable::OwnerId;

use super::class::{Fullness, SizeClass};
use super::handle::{Handle, ObjectHeader, ObjectLocation, RegistryEntry};
use super::limits::ZS_FULLNESS_GROUP_COUNT;
use super::platform::{page_provider, PageProvider};
use super::migration::ZsPoolStats;

pub(super) struct ZsPage {
    pub(super) class: SizeClass,
    pub(super) handles: Vec<Option<Handle>>,
    pub(super) frames: Vec<u64>,
    pub(super) isolated: Vec<bool>,
}

impl ZsPage {
    fn new(class: SizeClass, provider: PageProvider, owner: OwnerId) -> KResult<Self> {
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

    fn free_slot(&self) -> Option<usize> { self.handles.iter().position(Option::is_none) }

    fn has_live_objects(&self) -> bool { self.handles.iter().any(Option::is_some) }

    fn live_objects(&self) -> usize { self.handles.iter().filter(|handle| handle.is_some()).count() }

    fn fullness(&self) -> Fullness { Fullness::from_live(self.live_objects(), self.class.objects_per_zspage) }

    fn copy_in(&mut self, provider: PageProvider, offset: usize, bytes: &[u8]) -> KResult<()> { self.copy_from(provider, offset, bytes) }
    fn copy_out(&self, provider: PageProvider, offset: usize, bytes: &mut [u8]) -> KResult<()> { self.copy_to(provider, offset, bytes) }
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

pub(crate) struct RetiredPages { provider: Option<PageProvider>, owner: Option<OwnerId>, pages: Vec<ZsPage> }
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
    class: SizeClass,
    page: Option<ZsPage>,
    provider: PageProvider,
    owner: OwnerId,
}

/// Immutable State-lock snapshot used to reserve PMM capacity after dropping
/// zram serialization. It carries no allocated frame.
pub(crate) struct AllocationPlan { class: SizeClass, provider: PageProvider, owner: OwnerId, need_page: bool }

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

/// Stable-handle zsmalloc pool. The registry is object identity; zspages own storage only.
pub(crate) struct ZsPool {
    pub(super) provider: Option<PageProvider>,
    pub(super) owner: Option<OwnerId>,
    pub(super) zspages: Vec<Option<ZsPage>>,
    registry: Vec<RegistryEntry>,
    recycled_indices: Vec<usize>,
    retired: Vec<ZsPage>,
}

impl ZsPool {
    /// # C: O(1)
    pub(crate) fn new() -> Self {
        #[cfg(test)]
        super::install_hosted_test_provider();
        Self {
            provider: page_provider(),
            #[cfg(not(target_os = "oxide-kernel"))]
            owner: Some(OwnerId { slot: 0, generation: 0 }),
            #[cfg(target_os = "oxide-kernel")]
            owner: None,
            zspages: Vec::new(), registry: Vec::new(), recycled_indices: Vec::new(), retired: Vec::new(),
        }
    }


    /// Snapshot a physical allocation plan while the State lock serializes
    /// zspage membership. No PMM allocation happens here. # C: O(zspages)
    pub(crate) fn allocation_plan(&self, bytes: usize) -> KResult<AllocationPlan> {
        let class = SizeClass::for_request(bytes)?;
        let provider = self.provider.ok_or(BlockError::Enomem)?;
        let need_page = !self.zspages.iter().flatten().any(|page| page.class == class && page.free_slot().is_some());
        Ok(AllocationPlan { class, provider, owner: self.owner.ok_or(BlockError::Enomem)?, need_page })
    }

    /// Attach a previously prepared reservation. This never allocates or
    /// releases PMM frames under the zram State lock. If another commit made
    /// existing class storage available, the unused reservation is returned
    /// for post-lock rescind. # C: O(zspages)
    pub(crate) fn commit_reserved(&mut self, mut reservation: AllocationReservation, bytes: &[u8]) -> KResult<(Handle, Option<AllocationReservation>)> {
        if reservation.class != SizeClass::for_request(bytes.len())? { return Err(BlockError::Eio); }
        let class = reservation.class;
        self.reserve_handle_slot()?;
        let existing = self.zspages.iter().position(|page| page.as_ref().is_some_and(|page| page.class == class && page.free_slot().is_some()));
        if existing.is_none() && self.zspages.iter().all(Option::is_some) {
            self.zspages.try_reserve(1).map_err(|_| BlockError::Enomem)?;
        }
        let zspage = if let Some(index) = existing {
            index
        } else {
            let page = reservation.page.take().ok_or(BlockError::Eio)?;
            if let Some(index) = self.zspages.iter().position(Option::is_none) {
                self.zspages[index] = Some(page);
                index
            } else {
                self.zspages.push(Some(page));
                self.zspages.len() - 1
            }
        };
        let slot = self.zspages[zspage].as_ref().and_then(ZsPage::free_slot).ok_or(BlockError::Eio)?;
        let handle = self.allocate_handle(ObjectHeader { location: ObjectLocation { zspage, slot }, length: bytes.len(), class_bytes: class.object_bytes })?;
        let page = self.zspages[zspage].as_mut().ok_or(BlockError::Eio)?;
        let start = slot.checked_mul(class.object_bytes).ok_or(BlockError::Eio)?;
        page.copy_in(self.provider.ok_or(BlockError::Enomem)?, start, bytes)?;
        page.handles[slot] = Some(handle);
        Ok((handle, reservation.page.take().map(|page| AllocationReservation { class, page: Some(page), provider: reservation.provider, owner: reservation.owner })))
    }

    /// Allocates and copies one object into its Linux-shaped zsmalloc class.
    /// # C: O(number of zspages in the selected class)
    pub(crate) fn alloc(&mut self, bytes: &[u8]) -> KResult<Handle> {
        let class = SizeClass::for_request(bytes.len())?;
        self.reserve_handle_slot()?;
        let zspage = self.find_or_create_zspage(class)?;
        let slot = self.zspages[zspage].as_ref().and_then(ZsPage::free_slot).ok_or(BlockError::Enomem)?;
        let handle = self.allocate_handle(ObjectHeader { location: ObjectLocation { zspage, slot }, length: bytes.len(), class_bytes: class.object_bytes })?;
        let page = self.zspages[zspage].as_mut().ok_or(BlockError::Eio)?;
        let start = slot.checked_mul(class.object_bytes).ok_or(BlockError::Eio)?;
        let end = start.checked_add(bytes.len()).ok_or(BlockError::Eio)?;
        page.copy_in(self.provider.ok_or(BlockError::Enomem)?, start, bytes)?;
        page.handles[slot] = Some(handle);
        Ok(handle)
    }

    /// Reads an object without exposing a physical zspage location.
    /// # C: O(object length)
    pub(crate) fn read_into(&self, handle: Handle, out: &mut [u8]) -> KResult<()> {
        let header = self.header(handle)?;
        if out.len() != header.length { return Err(BlockError::Einval); }
        let page = self.zspages.get(header.location.zspage).and_then(Option::as_ref).ok_or(BlockError::Eio)?;
        self.validate_location(page, handle, header)?;
        let start = header.location.slot.checked_mul(header.class_bytes).ok_or(BlockError::Eio)?;
        let end = start.checked_add(header.length).ok_or(BlockError::Eio)?;
        page.copy_out(self.provider.ok_or(BlockError::Enomem)?, start, out)?;
        Ok(())
    }

    /// Replaces an object payload without changing its stable handle or class.
    /// # C: O(object length)
    pub(crate) fn write_from(&mut self, handle: Handle, bytes: &[u8]) -> KResult<()> {
        let header = self.header(handle)?;
        if bytes.len() != header.length { return Err(BlockError::Einval); }
        let page = self.zspages.get_mut(header.location.zspage).and_then(Option::as_mut).ok_or(BlockError::Eio)?;
        Self::validate_location_static(page, handle, header)?;
        let start = header.location.slot.checked_mul(header.class_bytes).ok_or(BlockError::Eio)?;
        let end = start.checked_add(header.length).ok_or(BlockError::Eio)?;
        page.copy_in(self.provider.ok_or(BlockError::Enomem)?, start, bytes)?;
        Ok(())
    }

    /// Frees an object and returns an empty multi-page zspage to the allocator.
    /// # C: O(objects in one zspage)
    pub(crate) fn free(&mut self, handle: Handle) -> KResult<()> {
        let header = self.header(handle)?;
        let page = self.zspages.get(header.location.zspage).and_then(Option::as_ref).ok_or(BlockError::Eio)?;
        Self::validate_location_static(page, handle, header)?;
        let release = page.live_objects() == 1;
        let generation = self.registry.get(handle.index).ok_or(BlockError::Eio)?
            .generation.checked_add(1).ok_or(BlockError::Eio)?;
        // Every allocation that follows the logical free is reserved before
        // invalidating the handle or detaching its zspage. A failed reserve
        // therefore leaves the exact object and all allocator indexes live.
        self.recycled_indices.try_reserve(1).map_err(|_| BlockError::Enomem)?;
        if release { self.retired.try_reserve(1).map_err(|_| BlockError::Enomem)?; }
        let page = self.zspages.get_mut(header.location.zspage).and_then(Option::as_mut).ok_or(BlockError::Eio)?;
        Self::validate_location_static(page, handle, header)?;
        page.handles[header.location.slot] = None;
        let entry = self.registry.get_mut(handle.index).ok_or(BlockError::Eio)?;
        if !entry.matches(handle) { return Err(BlockError::Eio); }
        entry.header = None;
        entry.generation = generation;
        self.recycled_indices.push(handle.index);
        if release { self.retired.push(self.zspages[header.location.zspage].take().ok_or(BlockError::Eio)?); }
        Ok(())
    }

    /// Allocator pages retained across all live zspages.
    /// # C: O(number of zspages)
    pub(crate) fn page_count(&self) -> usize { self.zspages.iter().flatten().map(|page| page.class.pages_per_zspage).sum() }

    /// Physical bytes retained by live zspages, the single zram mem_used source.
    /// # C: O(number of zspages)
    pub(crate) fn allocated_bytes(&self) -> KResult<u64> {
        u64::try_from(self.page_count()).ok().and_then(|pages| pages.checked_mul(hal::PAGE_SIZE_BYTES)).ok_or(BlockError::Enomem)
    }

    /// Returns canonical backend occupancy and compaction eligibility.
    /// # C: O(number of zspages squared in the worst fragmented class)
    pub(super) fn stats(&self) -> ZsPoolStats {
        let zspages = self.zspages.iter().flatten().count();
        let pages = self.page_count();
        let objects = self.zspages.iter().flatten().map(ZsPage::live_objects).sum();
        ZsPoolStats { pages, zspages, objects, can_compact: self.can_compact() }
    }

    /// True when a partially used zspage can be emptied into existing same-class storage.
    /// # C: O(number of zspages squared in the worst fragmented class)
    pub(super) fn can_compact(&self) -> bool {
        self.zspages.iter().enumerate().any(|(source, page)| {
            page.as_ref().is_some_and(|page| page.fullness() == Fullness::AlmostEmpty && self.can_empty_source(source))
        })
    }

    /// Exact PMM pages that class-local compaction can currently detach.
    /// # C: O(number of zspages squared)
    pub(crate) fn reclaimable_pages(&self) -> usize {
        self.zspages.iter().enumerate().filter_map(|(source, page)| {
            page.as_ref().filter(|page| page.fullness() == Fullness::AlmostEmpty && self.can_empty_source(source))
                .map(|page| page.class.pages_per_zspage)
        }).sum()
    }

    /// Compacts only candidates that can be emptied into already allocated same-class zspages.
    /// Returns the exact number of physical pages released, without changing opaque handles.
    /// # C: O(number of zspages cubed in the worst fragmented class)
    pub(crate) fn compact(&mut self) -> KResult<usize> {
        self.compact_budget(usize::MAX)
    }

    /// Compact no more than the caller's PMM reclaim budget. Stable handles
    /// still keep object identity independent of zspage relocation.
    /// # C: O(zspages cubed in the worst fragmented class)
    pub(crate) fn compact_budget(&mut self, target: usize) -> KResult<usize> {
        let mut released = 0usize;
        let mut source = 0usize;
        while source < self.zspages.len() {
            if released >= target { break; }
            let compactable = self.zspages.get(source).and_then(Option::as_ref).is_some_and(|page| page.fullness() == Fullness::AlmostEmpty && self.can_empty_source(source));
            if compactable {
                let source_pages = self.zspages.get(source).and_then(Option::as_ref).map(|page| page.class.pages_per_zspage).ok_or(BlockError::Eio)?;
                if source_pages > target.saturating_sub(released) { source += 1; continue; }
                released = released.checked_add(self.compact_source(source)?).ok_or(BlockError::Enomem)?;
            }
            source += 1;
        }
        Ok(released)
    }

    fn find_or_create_zspage(&mut self, class: SizeClass) -> KResult<usize> {
        if let Some(index) = self.zspages.iter().position(|page| page.as_ref().is_some_and(|page| page.class == class && page.free_slot().is_some())) { return Ok(index); }
        if let Some(index) = self.zspages.iter().position(Option::is_none) {
            let page = ZsPage::new(class, self.provider.ok_or(BlockError::Enomem)?, self.owner.ok_or(BlockError::Enomem)?)?;
            self.zspages[index] = Some(page);
            return Ok(index);
        }
        self.zspages.try_reserve(1).map_err(|_| BlockError::Enomem)?;
        let page = ZsPage::new(class, self.provider.ok_or(BlockError::Enomem)?, self.owner.ok_or(BlockError::Enomem)?)?;
        self.zspages.push(Some(page));
        Ok(self.zspages.len() - 1)
    }

    /// Reserve a registry entry before any zspage becomes reachable. # C: O(1)
    fn reserve_handle_slot(&mut self) -> KResult<()> {
        if let Some(index) = self.recycled_indices.last().copied() {
            let entry = self.registry.get(index).ok_or(BlockError::Eio)?;
            if entry.header.is_some() { return Err(BlockError::Eio); }
            return Ok(());
        }
        self.registry.try_reserve(1).map_err(|_| BlockError::Enomem)
    }

    fn allocate_handle(&mut self, header: ObjectHeader) -> KResult<Handle> {
        if let Some(index) = self.recycled_indices.pop() {
            let entry = self.registry.get_mut(index).ok_or(BlockError::Eio)?;
            if entry.header.is_some() { return Err(BlockError::Eio); }
            entry.header = Some(header);
            return Ok(entry.handle(index, header.length));
        }
        let index = self.registry.len();
        let mut entry = RegistryEntry::vacant();
        entry.header = Some(header);
        self.registry.push(entry);
        Ok(self.registry[index].handle(index, header.length))
    }

    fn header(&self, handle: Handle) -> KResult<ObjectHeader> {
        let entry = self.registry.get(handle.index).ok_or(BlockError::Eio)?;
        if !entry.matches(handle) { return Err(BlockError::Eio); }
        entry.header.ok_or(BlockError::Eio)
    }

    fn validate_location(&self, page: &ZsPage, handle: Handle, header: ObjectHeader) -> KResult<()> { Self::validate_location_static(page, handle, header) }

    fn validate_location_static(page: &ZsPage, handle: Handle, header: ObjectHeader) -> KResult<()> {
        if page.class.object_bytes != header.class_bytes || page.handles.get(header.location.slot) != Some(&Some(handle)) { return Err(BlockError::Eio); }
        Ok(())
    }

    fn can_empty_source(&self, source: usize) -> bool {
        let Some(source_page) = self.zspages.get(source).and_then(Option::as_ref) else { return false; };
        let free_slots = self.zspages.iter().enumerate().filter_map(|(index, page)| {
            (index != source).then_some(page.as_ref()).flatten().filter(|page| page.class == source_page.class).map(|page| page.class.objects_per_zspage - page.live_objects())
        }).sum::<usize>();
        free_slots >= source_page.live_objects()
    }

    fn compact_source(&mut self, source: usize) -> KResult<usize> {
        let (class, live) = {
            let source_page = self.zspages.get(source).and_then(Option::as_ref).ok_or(BlockError::Eio)?;
            (source_page.class, source_page.live_objects())
        };
        if live == 0 || !self.can_empty_source(source) { return Ok(0); }
        let mut source_slots = Vec::new();
        source_slots.try_reserve_exact(live).map_err(|_| BlockError::Enomem)?;
        let source_page = self.zspages.get(source).and_then(Option::as_ref).ok_or(BlockError::Eio)?;
        for (slot, handle) in source_page.handles.iter().enumerate() {
            if let Some(handle) = handle { source_slots.push((slot, *handle)); }
        }
        let mut scratch = Vec::new();
        scratch.try_reserve_exact(class.object_bytes).map_err(|_| BlockError::Enomem)?;
        scratch.resize(class.object_bytes, 0);
        // Compaction changes object locations before detaching its source.
        // Reserve retirement ownership first so an allocation failure cannot
        // strand moved handles in a zspage no longer reachable from the pool.
        self.retired.try_reserve(1).map_err(|_| BlockError::Enomem)?;
        for (source_slot, handle) in source_slots {
            let (destination_page, destination_slot) = self.compact_destination(source, class).ok_or(BlockError::Eio)?;
            let source_start = source_slot.checked_mul(class.object_bytes).ok_or(BlockError::Eio)?;
            let source_end = source_start.checked_add(class.object_bytes).ok_or(BlockError::Eio)?;
            let page = self.zspages.get(source).and_then(Option::as_ref).ok_or(BlockError::Eio)?;
            page.copy_out(self.provider.ok_or(BlockError::Enomem)?, source_start, &mut scratch)?;
            let destination_start = destination_slot.checked_mul(class.object_bytes).ok_or(BlockError::Eio)?;
            let destination_end = destination_start.checked_add(class.object_bytes).ok_or(BlockError::Eio)?;
            let destination = self.zspages.get_mut(destination_page).and_then(Option::as_mut).ok_or(BlockError::Eio)?;
            if destination.class != class || destination.handles.get(destination_slot) != Some(&None) { return Err(BlockError::Eio); }
            let _ = destination_end;
            destination.copy_in(self.provider.ok_or(BlockError::Enomem)?, destination_start, &scratch)?;
            destination.handles[destination_slot] = Some(handle);
            let page = self.zspages.get_mut(source).and_then(Option::as_mut).ok_or(BlockError::Eio)?;
            if page.handles.get(source_slot) != Some(&Some(handle)) { return Err(BlockError::Eio); }
            page.handles[source_slot] = None;
            let entry = self.registry.get_mut(handle.index).ok_or(BlockError::Eio)?;
            if !entry.matches(handle) { return Err(BlockError::Eio); }
            let header = entry.header.as_mut().ok_or(BlockError::Eio)?;
            header.location = ObjectLocation { zspage: destination_page, slot: destination_slot };
        }
        let released = self.zspages.get(source).and_then(Option::as_ref).filter(|page| !page.has_live_objects()).map(|page| page.class.pages_per_zspage).ok_or(BlockError::Eio)?;
        let page = self.zspages[source].take().ok_or(BlockError::Eio)?;
        self.retired.push(page);
        Ok(released)
    }

    /// Return physical pages detached while zram state was locked. The caller
    /// must invoke this only after dropping the zram table lock. # C: O(pages)
    pub(crate) fn take_retired(&mut self) -> RetiredPages {
        RetiredPages { provider: self.provider, owner: self.owner, pages: core::mem::take(&mut self.retired) }
    }

    /// Detach all live zspages during device reset; caller releases token after
    /// dropping the zram state lock. # C: O(number of zspages)
    pub(crate) fn retire_all(&mut self) -> KResult<RetiredPages> {
        if self.zspages.iter().flatten().any(|page| page.isolated.iter().any(|isolated| *isolated)) { return Err(BlockError::Ebusy); }
        let live = self.zspages.iter().flatten().count();
        self.retired.try_reserve_exact(live).map_err(|_| BlockError::Enomem)?;
        for page in &mut self.zspages {
            if let Some(page) = page.take() { self.retired.push(page); }
        }
        Ok(self.take_retired())
    }

    fn compact_destination(&self, source: usize, class: SizeClass) -> Option<(usize, usize)> {
        self.zspages.iter().enumerate().filter_map(|(index, page)| {
            (index != source).then_some(page.as_ref()).flatten().filter(|page| page.class == class && page.free_slot().is_some()).map(|page| (index, page.live_objects(), page.free_slot().unwrap_or(0)))
        }).max_by_key(|(_, live, _)| *live).map(|(index, _, slot)| (index, slot))
    }

    #[cfg(test)]
    pub(super) fn class_for_test(request_bytes: usize) -> KResult<SizeClass> { SizeClass::for_request(request_bytes) }

    #[cfg(test)]
    pub(super) fn spans_page_boundary(&self, handle: Handle) -> KResult<bool> {
        let header = self.header(handle)?;
        let page_bytes = hal::PAGE_SIZE_BYTES as usize;
        let offset = header.location.slot.checked_mul(header.class_bytes).ok_or(BlockError::Eio)?;
        Ok(offset / page_bytes != (offset + header.length - 1) / page_bytes)
    }


    #[cfg(test)]
    pub(super) fn fullness_counts_for_test(&self, class: SizeClass) -> [usize; ZS_FULLNESS_GROUP_COUNT] {
        let mut counts = [0; ZS_FULLNESS_GROUP_COUNT];
        for page in self.zspages.iter().flatten().filter(|page| page.class == class) {
            counts[page.fullness().index()] += 1;
        }
        counts
    }
}
