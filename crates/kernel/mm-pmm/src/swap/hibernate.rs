// Canonical swap-area hibernation slot lease per `32b§5`.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, pageio::PageIo};

use super::{AREAS, FIRST_DATA_PAGE, Result, Slot, SwapError, SWAP_HEADER_PAGE};

/// Exclusive image-slot ownership borrowed from one active swap area.
pub struct HibernationLease {
    kind: u8,
    io: PageIo,
    pages: Vec<u64>,
    logical_pages: Vec<u64>,
    header_page: u64,
}

impl HibernationLease {
    /// Allocate locator metadata before final free-page truth. # C: O(count)
    pub fn preallocate(&mut self, count: usize) -> Result<()> {
        if count == 0 || !self.pages.is_empty() { return Err(SwapError::Inval); }
        self.pages.try_reserve_exact(count).map_err(|_| SwapError::NoMem)?;
        self.logical_pages.try_reserve_exact(count).map_err(|_| SwapError::NoMem)
    }
    /// Reserve the image pages once its immutable stream size is known.
    /// # C: O(area pages)
    pub fn reserve(&mut self, count: usize) -> Result<()> {
        if count == 0 || !self.pages.is_empty() { return Err(SwapError::Inval); }
        let mut areas = AREAS.lock();
        let area = areas.areas.get_mut(self.kind as usize).and_then(Option::as_mut)
            .ok_or(SwapError::NoSuchArea)?;
        if !area.hibernating || area.draining { return Err(SwapError::Busy); }
        if self.pages.capacity() < count || self.logical_pages.capacity() < count {
            self.preallocate(count)?;
        }
        for page in FIRST_DATA_PAGE as usize..area.slot_count {
            if area.slot(page) != Some(Slot::Free) { continue; }
            area.set_slot(page, Slot::Hibernate)?;
            self.logical_pages.push(page as u64);
            self.pages.push(match area.file_geometry.as_ref() {
                Some(geometry) => *geometry.pages.get(page).ok_or(SwapError::Inval)?,
                None => page as u64,
            });
            if self.pages.len() == count { break; }
        }
        if self.pages.len() == count { return Ok(()); }
        self.pages.clear();
        for page in self.logical_pages.drain(..) {
            area.set_slot(page as usize, Slot::Free)?;
            area.next_free = area.next_free.min(page as usize);
        }
        Err(SwapError::NoSpace)
    }

    /// Reserved persistent page locators, excluding the header. # C: O(1)
    pub fn pages(&self) -> &[u64] { &self.pages }

    /// Swap-header page locator. # C: O(1)
    pub const fn header_page(&self) -> u64 { self.header_page }

    /// Addressable pages in the selected canonical area. # C: O(1)
    pub const fn page_count(&self) -> u64 { self.io.page_count() }

    fn admitted(&self, page: u64) -> bool {
        page == self.header_page || self.pages.contains(&page)
    }

    /// Read the header or one page owned by this lease. # C: one device read
    pub fn read_page(&self, page: u64, out: &mut [u8]) -> Result<()> {
        if !self.admitted(page) || out.len() != hal::PAGE_SIZE_BYTES as usize { return Err(SwapError::Inval); }
        self.io.read_page(page, out).map_err(SwapError::from)
    }

    /// Write the header or one page owned by this lease. # C: one device write
    pub fn write_page(&self, page: u64, data: &[u8]) -> Result<()> {
        if !self.admitted(page) || data.len() != hal::PAGE_SIZE_BYTES as usize { return Err(SwapError::Inval); }
        self.io.write_page(page, data).map_err(SwapError::from)
    }

    /// Make every preceding image write durable. # C: one device flush
    pub fn flush(&self) -> Result<()> {
        self.io.flush().map_err(SwapError::from)
    }

    /// Durably publish or consume the header after a preflush. # C: one durable write
    pub fn commit_page(&self, page: u64, data: &[u8]) -> Result<()> {
        if !self.admitted(page) || data.len() != hal::PAGE_SIZE_BYTES as usize { return Err(SwapError::Inval); }
        self.io.commit_page(page, data).map_err(SwapError::from)
    }
}

impl Drop for HibernationLease {
    fn drop(&mut self) {
        let mut areas = AREAS.lock();
        let Some(area) = areas.areas.get_mut(self.kind as usize).and_then(Option::as_mut) else { return; };
        for page in &self.logical_pages {
            if area.slot(*page as usize) == Some(Slot::Hibernate) {
                let _ = area.set_slot(*page as usize, Slot::Free);
                area.next_free = area.next_free.min(*page as usize);
            }
        }
        area.hibernating = false;
    }
}

/// Reserve exactly `count` image pages from one active canonical area.
/// # C: O(area pages)
pub fn begin(kind: u8) -> Result<HibernationLease> {
    let mut areas = AREAS.lock();
    let area = areas.areas.get_mut(kind as usize).and_then(Option::as_mut).ok_or(SwapError::NoSuchArea)?;
    if area.draining || area.hibernating { return Err(SwapError::Busy); }
    area.hibernating = true;
    let (device, bound, header_page) = match area.file_geometry.as_ref() {
        Some(geometry) => (geometry.device.clone(), None,
            geometry.pages[SWAP_HEADER_PAGE as usize]),
        None => (area.device.clone(), Some(area.slot_count as u64), SWAP_HEADER_PAGE),
    };
    let io = match PageIo::new_bounded(device, 0, hal::PAGE_SIZE_BYTES as usize, bound) {
        Ok(io) => io,
        Err(error) => {
            area.hibernating = false;
            return Err(error.into());
        }
    };
    Ok(HibernationLease { kind, io, pages: Vec::new(), logical_pages: Vec::new(), header_page })
}

/// Begin a session on the one canonical active area named by `resume`.
/// # C: O(number of swap areas)
pub fn begin_named(resume: &str) -> Result<HibernationLease> {
    let block_name = resume.strip_prefix("/dev/").filter(|name| !name.contains('/'));
    let kind = {
        let areas = AREAS.lock();
        areas.areas.iter().enumerate().find_map(|(kind, area)| {
            area.as_ref().filter(|area| area.name == resume || area.display_name == resume
                || block_name.is_some_and(|name| area.backing == super::SwapBacking::BlockDevice
                    && area.name == name)).map(|_| kind as u8)
        }).ok_or(SwapError::NoSuchArea)?
    };
    begin(kind)
}

/// Begin the unique area whose persistent raw target and header page match the
/// cold-boot locator. # C: O(number of swap areas)
pub fn begin_target(resume: &str, offset: u64) -> Result<HibernationLease> {
    let name = resume.strip_prefix("/dev/").unwrap_or(resume);
    let kind = {
        let areas = AREAS.lock();
        let mut found = None;
        for (kind, area) in areas.areas.iter().enumerate() {
            let Some(area) = area.as_ref() else { continue; };
            let matches = match area.file_geometry.as_ref() {
                Some(geometry) => geometry.device_name == name
                    && geometry.pages.first() == Some(&offset),
                None => area.name == name && offset == SWAP_HEADER_PAGE,
            };
            if !matches { continue; }
            if found.is_some() { return Err(SwapError::Busy); }
            found = Some(kind as u8);
        }
        found.ok_or(SwapError::NoSuchArea)?
    };
    begin(kind)
}

/// Begin the unique area backed by the resolved canonical block target and
/// header locator. # C: O(number of swap areas)
pub fn begin_target_device(device: &Arc<dyn BlockDevice>, offset: u64) -> Result<HibernationLease> {
    let kind = {
        let areas = AREAS.lock();
        let mut found = None;
        for (kind, area) in areas.areas.iter().enumerate() {
            let Some(area) = area.as_ref() else { continue; };
            let matches = match area.file_geometry.as_ref() {
                Some(geometry) => Arc::ptr_eq(&geometry.device, device)
                    && geometry.pages.first() == Some(&offset),
                None => Arc::ptr_eq(&area.device, device) && offset == SWAP_HEADER_PAGE,
            };
            if !matches { continue; }
            if found.is_some() { return Err(SwapError::Busy); }
            found = Some(kind as u8);
        }
        found.ok_or(SwapError::NoSuchArea)?
    };
    begin(kind)
}

/// Begin one area session and reserve its exact image footprint.
/// # C: O(area pages)
pub fn reserve(kind: u8, count: usize) -> Result<HibernationLease> {
    let mut lease = begin(kind)?;
    lease.reserve(count)?;
    Ok(lease)
}
