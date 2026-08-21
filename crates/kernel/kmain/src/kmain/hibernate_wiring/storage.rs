// Swap-area-backed image persistence adapter per `32b§5`.

use power::hibernate::format::Page;
use power::hibernate::image::Storage;

/// Storage view whose lifetime is exactly the canonical swap-area lease.
pub struct ImageStorage { lease: pmm::swap::hibernate::HibernationLease }

/// Cold-boot storage view retaining the canonical raw block target claim.
pub struct ResumeStorage {
    _claim: block::registry::DeviceClaim,
    io: block::pageio::PageIo,
}

impl ImageStorage {
    /// Pin the active area whose persistent target matches cold-boot settings.
    /// # C: O(number of swap areas)
    pub fn begin_target(resume: &str, offset: u64) -> Result<Self, pmm::swap::SwapError> {
        let claim = block::registry::claim_target_spec(resume.as_bytes())
            .ok_or(pmm::swap::SwapError::NoSuchArea)?;
        let device = claim.device();
        let lease = pmm::swap::hibernate::begin_target_device(&device, offset)?;
        Ok(Self { lease })
    }

    fn payload_slots(payload_pages: usize) -> Result<usize, pmm::swap::SwapError> {
        if payload_pages == 0 { return Err(pmm::swap::SwapError::Inval); }
        let maps = payload_pages.div_ceil(power::hibernate::format::MAP_ENTRIES);
        maps.checked_add(payload_pages).ok_or(pmm::swap::SwapError::NoSpace)
    }

    /// Allocate worst-case locator backing before final image selection. # C: O(payload pages)
    pub fn preallocate_payload_pages(&mut self, payload_pages: usize) -> Result<(), pmm::swap::SwapError> {
        self.lease.preallocate(Self::payload_slots(payload_pages)?)
    }

    /// Reserve exact map and payload slots after image selection. # C: O(area pages)
    pub fn reserve_payload_pages(&mut self, payload_pages: usize) -> Result<(), pmm::swap::SwapError> {
        drv_virtio_blk::modern::arm_hibernate_sync_trace();
        power::hibernate::log::serialize_phase(power::hibernate::log::SerializePhase::Reserve,
            power::hibernate::log::SerializeBoundary::Begin);
        let result = self.lease.reserve(Self::payload_slots(payload_pages)?);
        power::hibernate::log::serialize_phase(power::hibernate::log::SerializePhase::Reserve,
            power::hibernate::log::SerializeBoundary::End);
        result
    }

    /// Reserved persistent page locators. # C: O(1)
    pub fn pages(&self) -> &[u64] { self.lease.pages() }

    /// Header locator in the same canonical backing. # C: O(1)
    pub fn header_page(&self) -> u64 { self.lease.header_page() }

    /// Split one reservation into map slots and encoded payload slots.
    /// # C: O(1)
    pub fn plan_payload(&self, payload_pages: usize) -> Result<power::hibernate::image::Plan<'_>, pmm::swap::SwapError> {
        let map_pages = payload_pages.div_ceil(power::hibernate::format::MAP_ENTRIES);
        let needed = map_pages.checked_add(payload_pages).ok_or(pmm::swap::SwapError::NoSpace)?;
        if payload_pages == 0 || needed > self.pages().len() {
            return Err(pmm::swap::SwapError::Inval);
        }
        Ok(power::hibernate::image::Plan { header_page: self.header_page(),
            map_pages: &self.pages()[..map_pages],
            data_pages: &self.pages()[map_pages..needed] })
    }
}

impl Storage for ImageStorage {
    type Error = pmm::swap::SwapError;

    fn page_count(&self) -> u64 { self.lease.page_count() }
    fn read_page(&mut self, page: u64, out: &mut Page) -> Result<(), Self::Error> {
        self.lease.read_page(page, out)
    }
    fn write_page(&mut self, page: u64, data: &Page) -> Result<(), Self::Error> {
        self.lease.write_page(page, data)
    }
    fn flush(&mut self) -> Result<(), Self::Error> { self.lease.flush() }
    fn commit_page(&mut self, page: u64, data: &Page) -> Result<(), Self::Error> {
        self.lease.commit_page(page, data)
    }
}

impl ResumeStorage {
    /// Claim a raw target whose persisted locators use device-absolute pages.
    /// # C: O(disks + partitions)
    pub fn claim(name: &str) -> Result<Self, block::BlockError> {
        let claim = block::registry::claim_target_spec(name.as_bytes()).ok_or(block::BlockError::Ebusy)?;
        let io = block::pageio::PageIo::new(
            claim.device(), 0, power::hibernate::format::PAGE_SIZE,
        )?;
        Ok(Self { _claim: claim, io })
    }
}

impl Storage for ResumeStorage {
    type Error = block::BlockError;

    fn page_count(&self) -> u64 { self.io.page_count() }
    fn read_page(&mut self, page: u64, out: &mut Page) -> Result<(), Self::Error> {
        self.io.read_page(page, out)
    }
    fn write_page(&mut self, page: u64, data: &Page) -> Result<(), Self::Error> {
        self.io.write_page(page, data)
    }
    fn flush(&mut self) -> Result<(), Self::Error> { self.io.flush() }
    fn commit_page(&mut self, page: u64, data: &Page) -> Result<(), Self::Error> {
        self.io.commit_page(page, data)
    }
}
