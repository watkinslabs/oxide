//! `linear`: an extent of another device, at an offset.
//!
//! Every logical volume is built out of these, so it is the target that has to
//! be exactly right. Its whole behaviour is one addition, and the addition is
//! relative to the target's own start, not the device's.

extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::args::parse_u64;
use crate::target::{Ctr, DevMode, DmDev, DmIo, DmResult, DmTarget, MapResult, StatusType,
                    TargetFeatures, TargetType};

/// The registered `linear` mapping type.
pub const TYPE: TargetType = TargetType {
    name: "linear",
    version: [1, 4, 0],
    features: TargetFeatures { singleton: false, always_writeable: false, immutable: false, wildcard: false, nowait: true },
    ctr,
};

/// One linear extent.
pub struct Linear {
    /// First sector of the mapped device this target covers.
    pub begin: u64,
    /// First sector on the backing device the extent starts at.
    pub start: u64,
    /// The backing device.
    pub dev: DmDev,
}

impl Linear {
    /// Sector on the backing device that `sector` of the mapped device lands
    /// on. The subtraction is what makes the second and later targets of a
    /// table address their own device from its own offset rather than from the
    /// mapped device's. # C: O(1)
    pub fn map_sector(&self, sector: u64) -> u64 { self.start + (sector - self.begin) }
}

fn ctr(c: &mut Ctr<'_>) -> DmResult<Arc<dyn DmTarget>> {
    if c.argv.len() != 2 { return Err(c.fail("Invalid argument count", Errno::Einval)); }
    let start = parse_u64(c.argv[1]).ok_or_else(|| c.fail("Invalid device sector", Errno::Einval))?;
    let dev = c.resolver.get_device(c.argv[0], DevMode::RW)
        .map_err(|e| { c.error = Some("Device lookup failed"); e })?;
    Ok(Arc::new(Linear { begin: c.begin, start, dev }))
}

impl DmTarget for Linear {
    fn map(&self, io: &mut DmIo<'_>) -> DmResult<MapResult> {
        Ok(MapResult::Remapped { dev: self.dev.bdev.clone(), sector: self.map_sector(io.sector) })
    }

    fn status(&self, kind: StatusType) -> String {
        match kind {
            StatusType::Info => String::new(),
            StatusType::Table => format!("{} {}", self.dev.name, self.start),
        }
    }

    fn iterate_devices(&self) -> Vec<DmDev> { alloc::vec![self.dev.clone()] }
}
