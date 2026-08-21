//! Cold-image admission, exact destination claims, and collision ownership.

extern crate alloc;
use alloc::vec::Vec;

use crate::decide::{Error, KResult};
use super::format::Page;
use super::image::{ImageReader, Storage};
use super::stream;
use super::bitmap::Bitmap;

mod chain;

/// PMM boundary used only after marker consumption and checksum admission.
pub trait Memory {
    type Frame;
    /// Canonical retained topology used to derive PFN admission metadata. # C: O(1)
    fn topology(&self) -> &[super::snapshot::Region];
    /// Claim exactly one currently free destination PFN. # C: O(log free blocks)
    fn claim_exact(&mut self, pfn: u64) -> Option<Self::Frame>;
    /// Allocate one image-excluded collision frame. # C: O(log free blocks)
    fn alloc_safe(&mut self) -> KResult<Self::Frame>;
    /// Return the physical frame number owned by `frame`. # C: O(1)
    fn frame_pfn(&self, frame: &Self::Frame) -> u64;
    /// Replace the complete exclusively owned frame contents. # C: O(PAGE_SIZE)
    fn write(&self, frame: &mut Self::Frame, page: &Page);
    /// Zero the complete exclusively owned frame. # C: O(PAGE_SIZE)
    fn zero(&self, frame: &mut Self::Frame);
}

/// Fresh-kernel identity required before any destination is claimed.
pub struct Compatibility {
    pub arch: u32,
    pub cpu_count: u32,
    pub hardware_sig: u32,
    pub build_id: [u8; 32],
    pub topology_id: [u8; 32],
    pub cpu_id: [u8; 32],
}

/// Validate every generic compatibility field before destination ownership.
/// # C: O(1)
pub fn validate_compatibility(h: &super::format::Header, expected: &Compatibility) -> KResult<()> {
    if h.arch != expected.arch || h.cpu_count != expected.cpu_count
        || h.hardware_sig != expected.hardware_sig || h.build_id != expected.build_id
        || h.topology_id != expected.topology_id || h.cpu_id != expected.cpu_id
    {
        return Err(Error::Inval);
    }
    Ok(())
}

/// One loaded page retained until the terminal architecture transfer.
pub struct Target<F> {
    pub original_pfn: u64,
    pub source_pfn: u64,
    pub frame: F,
}

/// Sole restore owner: direct destinations and safe collision sources.
pub struct RestoreImage<F> {
    copied: Vec<Target<F>>,
    zero: Vec<Target<F>>,
    occupied: Bitmap,
    collisions: Vec<Collision>,
}

/// Reader token proving generic and architecture identity admission completed.
pub struct Admission<'a> { reader: &'a ImageReader }

/// One collision expressed in the generic image owner's PFN unit.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Collision { pub source_pfn: u64, pub destination_pfn: u64 }

/// Architecture-facing byte addresses derived from one owned collision.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PhysicalCollision { pub source_pa: u64, pub destination_pa: u64 }

/// Half-open PFN span every architecture temporary map must cover.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PfnRange { pub start: u64, pub end: u64 }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PhysicalRange { pub start: u64, pub end: u64 }

/// Terminal restore owner: loaded image plus every additional safe page.
///
/// Construction consumes [`RestoreImage`], so there is never a loaded-image
/// owner beside a terminal-plan owner. Collision sources remain the frames in
/// `image`; control/table/list pages remain in `control`; neither can be
/// released while an architecture borrows this plan.
pub struct SafeRestore<F> {
    image: RestoreImage<F>,
    control: Vec<Pinned<F>>,
    collision_nodes: Vec<usize>,
    collision_head_pa: u64,
    collision_prepared: bool,
}

struct Pinned<F> { pfn: u64, frame: F }

impl<F> RestoreImage<F> {
    /// Loaded nonzero targets in persistent stream order. # C: O(1)
    pub fn copied(&self) -> &[Target<F>] { &self.copied }
    /// Loaded zero-fill targets in persistent metadata order. # C: O(1)
    pub fn zero(&self) -> &[Target<F>] { &self.zero }
    /// Number of targets staged outside their original PFN. # C: O(image pages)
    pub fn collision_count(&self) -> usize { self.collisions.len() }
}

impl<F> SafeRestore<F> {
    /// Loaded nonzero targets retained by the terminal owner. # C: O(1)
    pub fn copied(&self) -> &[Target<F>] { self.image.copied() }
    /// Loaded zero-fill targets retained by the terminal owner. # C: O(1)
    pub fn zero(&self) -> &[Target<F>] { self.image.zero() }
    /// Number of staged source-to-destination copies. # C: O(image pages)
    pub fn collision_count(&self) -> usize { self.image.collision_count() }
    /// Number of architecture control/table/list frames. # C: O(1)
    pub fn control_count(&self) -> usize { self.control.len() }
    /// Borrow one architecture-owned control frame by role index. # C: O(1)
    pub fn control(&self, index: usize) -> Option<&F> { self.control.get(index).map(|p| &p.frame) }
    /// Mutably borrow one architecture-owned control frame by role index. # C: O(1)
    pub fn control_mut(&mut self, index: usize) -> Option<&mut F> {
        self.control.get_mut(index).map(|p| &mut p.frame)
    }
    /// Physical frame number for one architecture control role. # C: O(1)
    pub fn control_pfn(&self, index: usize) -> Option<u64> { self.control.get(index).map(|p| p.pfn) }

    /// Allocate and retain one more architecture control/table page.
    /// The PFN is admitted against every destination, staging source, and
    /// earlier control before it becomes visible. # C: O(image + control pages)
    pub fn allocate_control<M: Memory<Frame = F>>(&mut self, memory: &mut M) -> KResult<usize> {
        self.control.try_reserve(1).map_err(|_| Error::Nomem)?;
        let mut frame = memory.alloc_safe()?;
        let pfn = memory.frame_pfn(&frame);
        if !self.image.occupied.claim(pfn).map_err(|_| Error::Inval)? {
            return Err(Error::Inval);
        }
        memory.zero(&mut frame);
        let index = self.control.len();
        self.control.push(Pinned { pfn, frame });
        Ok(index)
    }

    /// Collision at `index`, in persistent target order. # C: O(image pages)
    pub fn collision(&self, index: usize) -> Option<Collision> {
        self.image.collisions.get(index).copied()
    }

    /// Destination-safe PFNs: collision staging first, then control pages.
    /// # C: O(image pages)
    pub fn safe_pfn(&self, index: usize) -> Option<u64> {
        let collisions = self.collision_count();
        if index < collisions { return self.collision(index).map(|c| c.source_pfn); }
        self.control_pfn(index - collisions)
    }

    /// Architecture collision addresses, checked before multiplication. # C: O(image pages)
    pub fn physical_collision(&self, index: usize) -> KResult<PhysicalCollision> {
        let c = self.collision(index).ok_or(Error::Inval)?;
        Ok(PhysicalCollision {
            source_pa: c.source_pfn.checked_mul(super::format::PAGE_SIZE as u64).ok_or(Error::Inval)?,
            destination_pa: c.destination_pfn.checked_mul(super::format::PAGE_SIZE as u64)
                .ok_or(Error::Inval)?,
        })
    }

    /// Borrowed-owner conversion into the x86 terminal ABI. # C: O(image pages)
    #[cfg(any(target_arch = "x86_64", not(target_os = "oxide-kernel")))]
    pub fn x86_collision(&self, index: usize) -> KResult<hal_x86_64::hibernate::Collision> {
        let c = self.physical_collision(index)?;
        Ok(hal_x86_64::hibernate::Collision {
            source_pa: c.source_pa, destination_pa: c.destination_pa })
    }

    /// Borrowed-owner conversion into the aarch64 terminal ABI. # C: O(image pages)
    #[cfg(any(target_arch = "aarch64", not(target_os = "oxide-kernel")))]
    pub fn arm_collision(&self, index: usize) -> KResult<hal_aarch64::hibernate::Collision> {
        let c = self.physical_collision(index)?;
        Ok(hal_aarch64::hibernate::Collision {
            source_pa: c.source_pa, destination_pa: c.destination_pa })
    }

    /// Architecture address of one destination-safe page. # C: O(image pages)
    pub fn safe_pa(&self, index: usize) -> KResult<u64> {
        self.safe_pfn(index).ok_or(Error::Inval)?
            .checked_mul(super::format::PAGE_SIZE as u64).ok_or(Error::Inval)
    }

    /// Number of PFNs architectures must exclude from every destination. # C: O(image pages)
    pub fn safe_page_count(&self) -> usize { self.collision_count() + self.control.len() }

    /// Smallest half-open span covering sources, destinations and controls.
    /// # C: O(image pages + control pages)
    pub fn physical_span(&self) -> Option<PfnRange> {
        let mut start = u64::MAX;
        let mut end = 0u64;
        for target in self.image.copied.iter().chain(&self.image.zero) {
            start = start.min(target.original_pfn).min(target.source_pfn);
            end = end.max(target.original_pfn).max(target.source_pfn);
        }
        for page in &self.control { start = start.min(page.pfn); end = end.max(page.pfn); }
        if start == u64::MAX { None } else { end.checked_add(1).map(|end| PfnRange { start, end }) }
    }

    /// Byte span used by architecture temporary-map planning. # C: O(image pages + control pages)
    pub fn physical_span_bytes(&self) -> KResult<PhysicalRange> {
        let span = self.physical_span().ok_or(Error::Inval)?;
        Ok(PhysicalRange {
            start: span.start.checked_mul(super::format::PAGE_SIZE as u64).ok_or(Error::Inval)?,
            end: span.end.checked_mul(super::format::PAGE_SIZE as u64).ok_or(Error::Inval)?,
        })
    }

    /// Derived x86 direct-map interval; no second range owner. # C: O(image pages + control pages)
    #[cfg(any(target_arch = "x86_64", not(target_os = "oxide-kernel")))]
    pub fn x86_direct_map(&self) -> KResult<hal_x86_64::hibernate::PhysRange> {
        let r = self.physical_span_bytes()?;
        Ok(hal_x86_64::hibernate::PhysRange { start: r.start, end: r.end })
    }

    /// Derived aarch64 physical interval; no second range owner. # C: O(image pages + control pages)
    #[cfg(any(target_arch = "aarch64", not(target_os = "oxide-kernel")))]
    pub fn arm_physical_map(&self) -> KResult<hal_aarch64::hibernate::PhysRange> {
        let r = self.physical_span_bytes()?;
        Ok(hal_aarch64::hibernate::PhysRange { start: r.start, end: r.end })
    }
}

/// Consume one admitted image and pin `control_pages` additional safe frames.
///
/// Architecture code assigns roles within `control` but cannot allocate a
/// second pool. Every PFN is checked against both restored destinations and
/// already-pinned sources/controls before the plan becomes observable.
/// # C: O(control pages)
pub fn prepare_safe<M: Memory>(image: RestoreImage<M::Frame>, memory: &mut M,
                               control_pages: usize) -> KResult<SafeRestore<M::Frame>> {
    let mut control = Vec::new();
    control.try_reserve_exact(control_pages).map_err(|_| Error::Nomem)?;
    let mut safe = SafeRestore { image, control, collision_nodes: Vec::new(), collision_head_pa: 0,
        collision_prepared: false };
    for _ in 0..control_pages {
        safe.allocate_control(memory)?;
    }
    Ok(safe)
}

struct Pending<F> { original_pfn: u64, frame: Option<F> }

/// Admit every persistent identity field before destination ownership.
/// # C: O(1) plus architecture validation
pub fn admit<'a, F>(reader: &'a ImageReader, expected: &Compatibility,
                    validate_arch: F) -> KResult<Admission<'a>>
where F: FnOnce(&[u8; 128]) -> KResult<()>
{
    validate_compatibility(&reader.header, expected)?;
    validate_arch(&reader.header.arch_data)?;
    Ok(Admission { reader })
}

/// Load a fully checksummed stream into exact or safe PMM-owned frames.
/// # C: O(image pages + populated PFNs)
pub fn load<S: Storage, M: Memory>(admission: Admission<'_>, store: &mut S,
                                   memory: &mut M) -> KResult<RestoreImage<M::Frame>> {
    let reader = admission.reader;
    reader.verify_checksum(store).map_err(map_image_error)?;
    let mut page = super::scratch::zeroed::<u8, { super::format::PAGE_SIZE }>()
        .ok_or(Error::Nomem)?;
    reader.read_page(store, 0, &mut page).map_err(map_image_error)?;
    let info = stream::decode_info(&page).map_err(|_| Error::Inval)?;
    if info.stream_pages as usize != reader.len()
        || info.copied_pages.checked_add(info.zero_pages) != Some(reader.header.image_pages)
        || info.zero_pages != reader.header.zero_pages
    {
        return Err(Error::Inval);
    }
    let total = usize::try_from(info.copied_pages.checked_add(info.zero_pages).ok_or(Error::Inval)?)
        .map_err(|_| Error::Nomem)?;
    let pfn_limit = super::snapshot::topology_pfn_limit(memory.topology())?;
    let mut valid = Bitmap::new(pfn_limit).map_err(|_| Error::Nomem)?;
    for region in memory.topology() {
        if !super::snapshot::saveable(region.kind) { continue; }
        for pfn in region.start_pfn..region.end_pfn {
            valid.claim(pfn).map_err(|_| Error::Inval)?;
        }
    }
    let mut occupied = Bitmap::new(pfn_limit).map_err(|_| Error::Nomem)?;
    let mut pfns = Vec::new();
    pfns.try_reserve_exact(total).map_err(|_| Error::Nomem)?;
    for index in 0..info.pfn_pages as usize {
        reader.read_page(store, 1 + index, &mut page).map_err(map_image_error)?;
        let mut decoded = super::scratch::zeroed::<u64,
            { super::format::PAGE_SIZE / core::mem::size_of::<u64>() }>().ok_or(Error::Nomem)?;
        let count = stream::decode_pfns(&page, info, index, &mut *decoded).map_err(|_| Error::Inval)?;
        for pfn in &decoded[..count] {
            if !valid.contains(*pfn)
                || !occupied.claim(*pfn).map_err(|_| Error::Inval)? {
                return Err(Error::Inval);
            }
            pfns.push(*pfn);
        }
    }
    if pfns.len() != total { return Err(Error::Inval); }

    let mut pending = Vec::new();
    pending.try_reserve_exact(total).map_err(|_| Error::Nomem)?;
    for pfn in pfns { pending.push(Pending { original_pfn: pfn, frame: memory.claim_exact(pfn) }); }
    for target in &mut pending {
        if target.frame.is_none() {
            let safe = memory.alloc_safe()?;
            if !occupied.claim(memory.frame_pfn(&safe)).map_err(|_| Error::Inval)? {
                return Err(Error::Inval);
            }
            target.frame = Some(safe);
        }
    }

    let copied_count = info.copied_pages as usize;
    let mut copied = Vec::new();
    let mut zero = Vec::new();
    let mut collisions = Vec::new();
    copied.try_reserve_exact(copied_count).map_err(|_| Error::Nomem)?;
    zero.try_reserve_exact(info.zero_pages as usize).map_err(|_| Error::Nomem)?;
    collisions.try_reserve_exact(total).map_err(|_| Error::Nomem)?;
    let payload_start = 1 + info.pfn_pages as usize;
    for (index, mut target) in pending.into_iter().enumerate() {
        let mut frame = target.frame.take().ok_or(Error::Nodata)?;
        let source_pfn = memory.frame_pfn(&frame);
        if source_pfn != target.original_pfn {
            collisions.push(Collision { source_pfn, destination_pfn: target.original_pfn });
        }
        if index < copied_count {
            reader.read_page(store, payload_start + index, &mut page).map_err(map_image_error)?;
            memory.write(&mut frame, &page);
            copied.push(Target { original_pfn: target.original_pfn,
                source_pfn, frame });
        } else {
            memory.zero(&mut frame);
            zero.push(Target { original_pfn: target.original_pfn,
                source_pfn, frame });
        }
    }
    Ok(RestoreImage { copied, zero, occupied, collisions })
}

fn map_image_error(error: super::image::Error) -> Error {
    match error {
        super::image::Error::Io => Error::Io,
        super::image::Error::NoImage => Error::Nodata,
        super::image::Error::Unsupported => Error::Opnotsupp,
        super::image::Error::SwapSignature | super::image::Error::Format |
        super::image::Error::Bounds | super::image::Error::Cycle |
        super::image::Error::Duplicate | super::image::Error::PrematureEnd |
        super::image::Error::TrailingEntry | super::image::Error::Checksum => Error::Inval,
    }
}

#[cfg(test)]
#[path = "restore/tests.rs"]
mod tests;
