// PMM-backed physical snapshot adapter per `32b§6`.

use alloc::vec::Vec;

use power::hibernate::snapshot::{Memory, MemoryKind, Region};
use power::hibernate::image::{self, PageSource};
use power::hibernate::{format, stream};
use power::hibernate::restore;
use power::{Error, KResult};

/// Frozen PMM view used while building one physical image.
pub struct SnapshotMemory {
    free: pmm::FreePfnSnapshot,
    topology: Vec<Region>,
    copy_frames: Vec<pmm::setup::KernelHibernateFrame>,
}

/// Early allocation owner consumed only at the quiesced ArchSnapshot point.
pub struct PreparedSnapshotMemory {
    pmm: &'static pmm::setup::KernelPmm,
    free: pmm::FreePfnWorkspace,
    topology: Vec<Region>,
    image_capacity_pages: u64,
    max_payload_pages: usize,
    free_floor_pages: u64,
    max_image_pages: u64,
    copy_frames: Vec<pmm::setup::KernelHibernateFrame>,
}

/// Streaming view borrowing the sole physical snapshot owner.
pub struct SnapshotStream<'a> {
    snapshot: &'a power::hibernate::snapshot::Snapshot<pmm::setup::KernelHibernateFrame>,
    info: stream::ImageInfo,
}

/// PMM exact-claim and safe-frame owner used by the cold restore kernel.
pub struct RestoreMemory {
    pmm: &'static pmm::setup::KernelPmm,
    topology: Vec<Region>,
}

impl<'a> SnapshotStream<'a> {
    /// Borrow one snapshot without copying its PFN or page lists. # C: O(1)
    pub fn new(snapshot: &'a power::hibernate::snapshot::Snapshot<pmm::setup::KernelHibernateFrame>)
        -> Result<Self, image::Error>
    {
        let info = stream::layout(snapshot.copied().len() as u64, snapshot.zero_pfns().len() as u64)
            .map_err(|_| image::Error::Format)?;
        Ok(Self { snapshot, info })
    }

    /// Counts persisted in the image header. # C: O(1)
    pub const fn info(&self) -> stream::ImageInfo { self.info }
}

impl PageSource for SnapshotStream<'_> {
    fn len(&self) -> usize { self.info.stream_pages as usize }

    fn read_page(&self, index: usize, out: &mut format::Page) -> Result<(), image::Error> {
        if index == 0 {
            stream::encode_info_into(self.info, out).map_err(|_| image::Error::Format)?;
            return Ok(());
        }
        let pfn_pages = self.info.pfn_pages as usize;
        if index <= pfn_pages {
            let copied = self.snapshot.copied();
            let zero = self.snapshot.zero_pfns();
            let mut writer = stream::PfnPageWriter::new(self.info, index - 1, out)
                .map_err(|_| image::Error::Format)?;
            for slot in 0..writer.count() {
                let source = writer.start() + slot;
                let pfn = if source < copied.len() { copied[source].original_pfn }
                    else { *zero.get(source - copied.len()).ok_or(image::Error::Bounds)? };
                writer.put(slot, pfn).map_err(|_| image::Error::Format)?;
            }
            return Ok(());
        }
        let copied = self.snapshot.copied().get(index - 1 - pfn_pages).ok_or(image::Error::Bounds)?;
        // SAFETY: the snapshot owns this immutable copy frame for the complete
        // stream lifetime; `out` is distinct caller-owned page storage.
        unsafe {
            core::ptr::copy_nonoverlapping(copied.copy.as_ptr(), out.as_mut_ptr(), format::PAGE_SIZE);
        }
        Ok(())
    }
}

impl SnapshotMemory {
    /// Capture canonical topology and buddy/PCP free truth once. # C: O(PFNs)
    pub fn capture() -> KResult<Self> {
        let pmm = pmm::setup::pmm_static().ok_or(Error::Nodata)?;
        let topology = topology()?;
        let free = pmm.hibernate_free_snapshot();
        Ok(Self { free, topology, copy_frames: Vec::new() })
    }

    /// Reclaim toward the preferred image size, then capture the final buddy
    /// truth and install the mandatory post-copy free-page floor. # C: O(PFNs + reclaim)
    pub fn preallocate(image_bytes: u64, reserved_bytes: u64,
        compression: image::Compression) -> KResult<(PreparedSnapshotMemory,
            power::hibernate::snapshot::Snapshot<pmm::setup::KernelHibernateFrame>)>
    {
        let initial = Self::capture()?;
        let saveable = power::hibernate::snapshot::count_saveable(&initial)?;
        let reclaimable = pmm::hibernate_reclaimable_pages() as u64;
        let metadata = bitmap_metadata_pages(initial.free.pfn_max());
        let largest = power::hibernate::snapshot::calculate_budget(saveable,
            initial.free.free_pages(), metadata, reclaimable, image_bytes,
            reserved_bytes, hal::PAGE_SIZE_BYTES);
        let metadata = transaction_metadata_pages(initial.free.pfn_max(),
            initial.topology.len(), largest.max_image_pages, compression)?;
        let budget = power::hibernate::snapshot::calculate_budget(saveable,
            initial.free.free_pages(), metadata, reclaimable, image_bytes,
            reserved_bytes, hal::PAGE_SIZE_BYTES);
        let metadata_at_ceiling = transaction_metadata_pages(initial.free.pfn_max(),
            initial.topology.len(), budget.max_image_pages, compression)?;
        drop(initial);
        let reclaim_pages = budget.reclaim_pages.checked_add(metadata_at_ceiling)
            .and_then(|pages| usize::try_from(pages).ok()).ok_or(Error::Nomem)?;
        let _ = pmm::reclaim_for_hibernate(reclaim_pages);
        let pmm = pmm::setup::pmm_static().ok_or(Error::Nodata)?;
        let topology = topology()?;
        let free = pmm.hibernate_free_workspace();
        let capacity = usize::try_from(budget.max_image_pages).map_err(|_| Error::Nomem)?;
        let pfn_limit = topology.last().map(|region| region.end_pfn).ok_or(Error::Nodata)?;
        let snapshot = power::hibernate::snapshot::Snapshot::preallocate(capacity, pfn_limit)?;
        let max_payload_pages = payload_capacity(capacity, compression)?;
        let mut copy_frames = Vec::new();
        copy_frames.try_reserve_exact(capacity).map_err(|_| Error::Nomem)?;
        Ok((PreparedSnapshotMemory { pmm, free, topology,
            image_capacity_pages: 0, max_payload_pages,
            free_floor_pages: budget.free_floor_pages,
            max_image_pages: budget.max_image_pages, copy_frames }, snapshot))
    }
}

impl PreparedSnapshotMemory {
    /// Worst-case encoded payload capacity whose locator buffers are allocated early. # C: O(1)
    pub const fn max_payload_pages(&self) -> usize { self.max_payload_pages }

    /// Close copy ownership against allocator truth after all metadata exists. # C: O(PFNs + pages)
    pub fn seal(&mut self) -> KResult<()> {
        loop {
            let measured = SnapshotMemory::capture()?;
            let saveable = power::hibernate::snapshot::count_saveable(&measured)?;
            let capacity = power::hibernate::snapshot::retained_capacity(saveable, 0,
                self.free_floor_pages, self.max_image_pages).ok_or(Error::Nomem)?;
            let capacity = usize::try_from(capacity).map_err(|_| Error::Nomem)?;
            if self.copy_frames.len() >= capacity {
                self.image_capacity_pages = self.copy_frames.len() as u64;
                return Ok(());
            }
            while self.copy_frames.len() < capacity {
                if self.pmm.free_pages() <= self.free_floor_pages { return Err(Error::Nomem); }
                self.copy_frames.push(self.pmm.alloc_hibernate_frame().map_err(|_| Error::Nomem)?);
            }
        }
    }

    /// Release at most `count` retained copy-frame owners. # C: O(count)
    pub fn release_copies(&mut self, count: usize) -> usize {
        let old = self.copy_frames.len();
        self.copy_frames.truncate(old.saturating_sub(count));
        old - self.copy_frames.len()
    }

    /// Capture final free/forbidden truth after device/CPU quiesce, retaining
    /// the early copy pool without allocation. # C: O(PFNs)
    pub fn finalize(self) -> (SnapshotMemory, KResult<()>) {
        let free = self.pmm.hibernate_free_snapshot_into(self.free);
        let view = SnapshotMemory { free, topology: self.topology,
            copy_frames: self.copy_frames };
        let admission = power::hibernate::snapshot::count_saveable(&view).and_then(|saveable| {
            power::hibernate::log::snapshot_admission(saveable, self.image_capacity_pages,
                view.copy_frames.len() as u64);
            if saveable > self.image_capacity_pages { Err(Error::Nomem) } else { Ok(()) }
        });
        (view, admission)
    }
}

impl RestoreMemory {
    /// Capture the same canonical topology used by image compatibility. # C: O(regions)
    pub fn capture() -> KResult<Self> {
        let pmm = pmm::setup::pmm_static().ok_or(Error::Nodata)?;
        Ok(Self { pmm, topology: topology()? })
    }

    /// Canonical managed physical interval containing every restore allocation. # C: O(regions)
    pub fn physical_span(&self) -> KResult<(u64, u64)> {
        let managed = self.topology.iter().filter(|region| matches!(region.kind,
            MemoryKind::Usable | MemoryKind::KernelImage | MemoryKind::Initramfs));
        let start = managed.clone().map(|region| region.start_pfn).min().ok_or(Error::Nodata)?;
        let end = managed.map(|region| region.end_pfn).max().ok_or(Error::Nodata)?;
        Ok((start.checked_mul(hal::PAGE_SIZE_BYTES).ok_or(Error::Inval)?,
            end.checked_mul(hal::PAGE_SIZE_BYTES).ok_or(Error::Inval)?))
    }

    /// Live canonical direct-map offset used to populate safe tables. # C: O(1)
    pub fn direct_map_base(&self) -> KResult<u64> {
        let base = pmm::setup::direct_map_base();
        if base == 0 { Err(Error::Nodata) } else { Ok(base) }
    }
}

impl restore::Memory for RestoreMemory {
    type Frame = pmm::setup::KernelHibernateFrame;

    fn topology(&self) -> &[Region] { &self.topology }

    fn claim_exact(&mut self, pfn: u64) -> Option<Self::Frame> {
        self.pmm.claim_hibernate_pfn(hal::Pfn(pfn))
    }

    fn alloc_safe(&mut self) -> KResult<Self::Frame> {
        self.pmm.alloc_hibernate_frame().map_err(|_| Error::Nomem)
    }

    fn frame_pfn(&self, frame: &Self::Frame) -> u64 { frame.pfn().0 }

    fn write(&self, frame: &mut Self::Frame, page: &format::Page) {
        // SAFETY: restore owns `frame` exclusively and page is one complete
        // immutable image buffer of the same fixed size.
        unsafe { core::ptr::copy_nonoverlapping(page.as_ptr(), frame.as_mut_ptr(), format::PAGE_SIZE); }
    }

    fn zero(&self, frame: &mut Self::Frame) {
        // SAFETY: restore owns `frame` exclusively for a complete base page.
        unsafe { core::ptr::write_bytes(frame.as_mut_ptr(), 0, format::PAGE_SIZE); }
    }
}

impl Memory for SnapshotMemory {
    type Frame = pmm::setup::KernelHibernateFrame;

    fn topology(&self) -> &[Region] { &self.topology }
    fn was_free(&self, pfn: u64) -> bool { self.free.contains(hal::Pfn(pfn)) }
    fn is_forbidden(&self, pfn: u64) -> bool {
        self.free.forbidden(hal::Pfn(pfn))
    }

    fn take_copy(&mut self) -> KResult<Self::Frame> { self.copy_frames.pop().ok_or(Error::Nomem) }

    fn copy_into(&self, pfn: u64, frame: &mut Self::Frame) -> KResult<()> {
        let source = page_ptr(pfn)?;
        // SAFETY: source is one admitted page; frame is exclusively owned by
        // this snapshot and provides a disjoint PAGE_SIZE destination.
        unsafe {
            core::ptr::copy_nonoverlapping(source, frame.as_mut_ptr(), hal::PAGE_SIZE_BYTES as usize);
        }
        Ok(())
    }
}

impl SnapshotMemory {
    /// Release at most `count` retained copy-frame owners. # C: O(count)
    pub fn release_copies(&mut self, count: usize) -> usize {
        let old = self.copy_frames.len();
        self.copy_frames.truncate(old.saturating_sub(count));
        old - self.copy_frames.len()
    }
}

fn bitmap_metadata_pages(pfn_max: u64) -> u64 {
    bitmap_metadata_pages_for(pfn_max, 2)
}

fn bitmap_metadata_pages_for(pfn_max: u64, maps: u64) -> u64 {
    const BITS_PER_BYTE: u64 = 8;
    let bytes = pfn_max.saturating_add(BITS_PER_BYTE - 1) / BITS_PER_BYTE;
    let total = bytes.saturating_mul(maps);
    total / hal::PAGE_SIZE_BYTES + ((total % hal::PAGE_SIZE_BYTES != 0) as u64)
}

fn payload_capacity(image_pages: usize, compression: image::Compression) -> KResult<usize> {
    let info = stream::layout(image_pages as u64, 0).map_err(|_| Error::Nomem)?;
    image::max_stored_pages(info.stream_pages as usize, compression).map_err(|_| Error::Nomem)
}

fn transaction_metadata_pages(pfn_max: u64, topology_len: usize, image_pages: u64,
    compression: image::Compression) -> KResult<u64>
{
    let image_pages = usize::try_from(image_pages).map_err(|_| Error::Nomem)?;
    let payload = payload_capacity(image_pages, compression)?;
    let maps = payload.div_ceil(format::MAP_ENTRIES);
    let locators = payload.checked_add(maps).ok_or(Error::Nomem)?;
    let copied = allocation_backing_pages(image_pages.checked_mul(core::mem::size_of::<
        power::hibernate::snapshot::CopiedPage<pmm::setup::KernelHibernateFrame>>())
        .ok_or(Error::Nomem)?, core::mem::align_of::<
        power::hibernate::snapshot::CopiedPage<pmm::setup::KernelHibernateFrame>>())?;
    let frames = allocation_backing_pages(image_pages.checked_mul(core::mem::size_of::<
        pmm::setup::KernelHibernateFrame>()).ok_or(Error::Nomem)?,
        core::mem::align_of::<pmm::setup::KernelHibernateFrame>())?;
    let locator_bytes = locators.checked_mul(core::mem::size_of::<u64>()).ok_or(Error::Nomem)?;
    let locator = allocation_backing_pages(locator_bytes, core::mem::align_of::<u64>())?;
    let topology = allocation_backing_pages(topology_len.checked_mul(core::mem::size_of::<Region>())
        .ok_or(Error::Nomem)?, core::mem::align_of::<Region>())?;
    let bitmap_bytes = usize::try_from(pfn_max.div_ceil(8)).map_err(|_| Error::Nomem)?;
    let bitmap = allocation_backing_pages(bitmap_bytes, core::mem::align_of::<u64>())?;
    copied.checked_add(frames).and_then(|pages| pages.checked_add(locator.checked_mul(2)?))
        .and_then(|pages| pages.checked_add(topology))
        .and_then(|pages| pages.checked_add(bitmap.checked_mul(3)?)).ok_or(Error::Nomem)
}

fn allocation_backing_pages(bytes: usize, align: usize) -> KResult<u64> {
    const KALLOC_GROW_MIN_BYTES: usize = 1024 * 1024;
    let need = bytes.checked_add(align).ok_or(Error::Nomem)?.max(KALLOC_GROW_MIN_BYTES);
    let pages = need.div_ceil(hal::PAGE_SIZE_BYTES as usize).checked_next_power_of_two()
        .ok_or(Error::Nomem)?;
    u64::try_from(pages).map_err(|_| Error::Nomem)
}

fn page_ptr(pfn: u64) -> KResult<*const u8> {
    let pa = pfn.checked_mul(hal::PAGE_SIZE_BYTES).ok_or(Error::Inval)?;
    let va = pmm::setup::direct_map_base().checked_add(pa).ok_or(Error::Inval)?;
    if va == 0 { return Err(Error::Nodata); }
    Ok(va as *const u8)
}

fn topology() -> KResult<Vec<Region>> {
    let mut topology = Vec::new();
    topology.try_reserve_exact(pmm::setup::memory_topology().len()).map_err(|_| Error::Nomem)?;
    for region in pmm::setup::memory_topology() {
        topology.push(Region { start_pfn: region.start.0, end_pfn: region.end.0,
            kind: kind(region.kind) });
    }
    Ok(topology)
}

fn kind(kind: boot_info::BootMemKind) -> MemoryKind {
    use boot_info::BootMemKind;
    match kind {
        BootMemKind::Usable => MemoryKind::Usable,
        BootMemKind::KernelImage => MemoryKind::KernelImage,
        BootMemKind::Initramfs => MemoryKind::Initramfs,
        BootMemKind::AcpiNvs => MemoryKind::AcpiNvs,
        BootMemKind::AcpiReclaim => MemoryKind::AcpiReclaim,
        BootMemKind::BadMem => MemoryKind::Bad,
        BootMemKind::Reserved | BootMemKind::BootloaderUsed => MemoryKind::Reserved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_metadata_counts_allocator_arena_geometry_not_logical_bytes() {
        assert_eq!(allocation_backing_pages(1, 1), Ok(256));
        assert_eq!(allocation_backing_pages(4 * 1024 * 1024, 8), Ok(2048),
            "size plus alignment crossing a power of two needs the complete grow arena");
        assert!(allocation_backing_pages(usize::MAX, 8).is_err());
    }
}
