//! `striped`: round-robin chunks across several devices.
//!
//! The mapping is two divisions, and getting either backwards sends a chunk to
//! the wrong member — a corruption with no error path, which is why the
//! arithmetic is a separate function with its own tests.

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::QueueLimits;
use core::sync::atomic::{AtomicU32, Ordering};
use syscall::errno::Errno;

use crate::args::{parse_u32, parse_u64};
use crate::target::{Ctr, DevMode, DmDev, DmIo, DmResult, DmTarget, MapResult, StatusType,
                    TargetFeatures, TargetType};
use crate::uapi::SECTOR_SHIFT;

/// The registered `striped` mapping type.
pub const TYPE: TargetType = TargetType {
    name: "striped",
    version: [1, 7, 0],
    features: TargetFeatures { singleton: false, always_writeable: false, immutable: false, wildcard: false, nowait: true },
    ctr,
};

/// One member of a stripe set.
pub struct Stripe {
    /// The member device.
    pub dev: DmDev,
    /// First sector of the member the stripe set starts at.
    pub physical_start: u64,
    /// Errors seen on this member, which the status report renders as `D`.
    pub error_count: AtomicU32,
}

/// A stripe set.
pub struct Striped {
    /// First sector of the mapped device this target covers.
    pub begin: u64,
    /// Sectors in one chunk.
    pub chunk_size: u64,
    /// Sectors of the mapped device each member contributes.
    pub stripe_width: u64,
    /// The members, in table order — the order IS the stripe numbering.
    pub stripes: Vec<Stripe>,
}

impl Striped {
    /// Which member, and which sector of it, a mapped-device sector lands on.
    ///
    /// The chunk number is split twice: the low part selects the member, the
    /// high part is the chunk's index within that member. Doing it the other
    /// way round — member from the high part — produces a mapping that is
    /// self-consistent and completely wrong against every other stripe
    /// implementation. # C: O(1)
    pub fn map_sector(&self, sector: u64) -> (usize, u64) {
        let mut chunk = sector - self.begin;
        let chunk_offset = chunk % self.chunk_size;
        chunk /= self.chunk_size;
        let stripe = (chunk % self.stripes.len() as u64) as usize;
        chunk /= self.stripes.len() as u64;
        (stripe, chunk * self.chunk_size + chunk_offset)
    }
}

fn ctr(c: &mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>> {
    if c.argv.len() < 2 { return Err(c.fail("Not enough arguments", Errno::Einval)); }
    let stripes = match parse_u32(c.argv[0]) { Some(n) if n != 0 => n as u64,
        _ => return Err(c.fail("Invalid stripe count", Errno::Einval)) };
    let chunk_size = match parse_u32(c.argv[1]) { Some(n) if n != 0 => n as u64,
        _ => return Err(c.fail("Invalid chunk_size", Errno::Einval)) };

    // The set must divide evenly twice: once so every member carries the same
    // number of sectors, and once so a member's share is a whole number of
    // chunks. Either remainder would leave a tail of the device that the
    // round-robin cannot address.
    if c.len % stripes != 0 {
        return Err(c.fail("Target length not divisible by number of stripes", Errno::Einval));
    }
    let width = c.len / stripes;
    if width % chunk_size != 0 {
        return Err(c.fail("Target length not divisible by chunk size", Errno::Einval));
    }
    if c.argv.len() as u64 != 2 + 2 * stripes {
        return Err(c.fail("Not enough destinations specified", Errno::Einval));
    }

    let mut members = Vec::new();
    for i in 0..stripes as usize {
        let name = c.argv[2 + i * 2];
        let start = parse_u64(c.argv[3 + i * 2])
            .ok_or_else(|| c.fail("Couldn't parse stripe destination", Errno::Einval))?;
        let dev = c.resolver.get_device(name, DevMode::RW)
            .map_err(|e| { c.error = Some("Couldn't parse stripe destination"); e })?;
        members.push(Stripe { dev, physical_start: start, error_count: AtomicU32::new(0) });
    }

    Ok(Arc::new(Striped { begin: c.begin, chunk_size, stripe_width: width, stripes: members }))
}

impl DmTarget for Striped {
    fn map(&self, io: &mut DmIo<'_>) -> DmResult<MapResult> {
        let (idx, sector) = self.map_sector(io.sector);
        let s = &self.stripes[idx];
        Ok(MapResult::Remapped { dev: s.dev.bdev.clone(), sector: s.physical_start + sector })
    }

    /// A chunk is the largest piece that stays on one member, so the core
    /// splits at every chunk boundary before calling `map`. Without this a
    /// transfer spanning two chunks would be placed entirely on the member the
    /// first sector selected.
    fn max_io_len(&self) -> u64 { self.chunk_size }

    fn status(&self, kind: StatusType) -> String {
        let mut s = String::new();
        match kind {
            StatusType::Info => {
                s.push_str(&format!("{} ", self.stripes.len()));
                for st in &self.stripes { s.push_str(&format!("{} ", st.dev.name)); }
                s.push_str("1 ");
                for st in &self.stripes {
                    s.push(if st.error_count.load(Ordering::Relaxed) != 0 { 'D' } else { 'A' });
                }
            }
            StatusType::Table => {
                s.push_str(&format!("{} {}", self.stripes.len(), self.chunk_size));
                for st in &self.stripes {
                    s.push_str(&format!(" {} {}", st.dev.name, st.physical_start));
                }
            }
        }
        s
    }

    fn iterate_devices(&self) -> Vec<DmDev> { self.stripes.iter().map(|s| s.dev.clone()).collect() }

    fn io_hints(&self, limits: &mut QueueLimits) {
        let io_min = (self.chunk_size << SECTOR_SHIFT) as u32;
        let io_opt = io_min.saturating_mul(self.stripes.len() as u32);
        let lbs = limits.logical_block_size();
        if let Ok(next) = QueueLimits::new(lbs, limits.physical_block_size(), io_min, io_opt) {
            *limits = next;
        }
    }
}
