//! The per-volume figures the member reports settle.
//!
//! One number carries almost all of the weight: the blocks per section that
//! cannot be written. It is read off the sequential zones' short capacity, and
//! every zoned member's sequential zones must agree on it — a volume whose
//! zones have different capacities has no single answer, and a filesystem that
//! averaged them would place blocks past the capacity of the smaller ones.

use alloc::vec::Vec;

use super::report::DevZones;

/// Why a volume's zone reports cannot be used.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ZoneError {
    /// Two members state different zone sizes.
    MixedZoneSize,
    /// Two sequential zones have different capacities.
    MixedCapacity,
    /// The drives will not keep as many zones open as the mount has logs.
    TooFewOpenZones,
    /// A member reports zones on a volume not formatted for them.
    FeatureOff,
    /// The volume is formatted for zones, names no member paths, and the
    /// device it was mounted from reports none — so nothing says where the
    /// zones are.
    PathMissing,
}

/// Whether a volume formatted for zones says enough to find them.
///
/// A volume that names its members says where every zone is. One that names
/// none is relying on the device it was mounted from BEING the zoned drive,
/// so a device that reports no zones leaves the layout unexplained — and a
/// volume laid out for zones read as though it had none places blocks the
/// drive will refuse.
/// # C: O(1)
pub fn paths_ok(feature: u32, names_devices: bool, mounted_zoned: bool) -> Result<(), ZoneError> {
    if !crate::features::has_blkzoned(feature) { return Ok(()); }
    if names_devices || mounted_zoned { return Ok(()); }
    Err(ZoneError::PathMissing)
}

/// No stated limit on open zones.
pub const OPEN_ZONES_UNBOUNDED: u32 = u32::MAX;

/// What the mount knows about its members' zones.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Geometry {
    pub blocks_per_zone: u32,
    /// Blocks per section that no write may use. Zero when every zone is
    /// conventional or reports its full length as capacity, and zero is what
    /// makes every usable-space answer below collapse to the plain one.
    pub unusable_blocks_per_sec: u32,
    pub max_open_zones: u32,
    /// Per member, one flag per zone: whether that zone is sequential.
    /// Empty for a member that reported nothing.
    seq: Vec<Vec<bool>>,
}

impl Geometry {
    /// Settle the reports into one geometry.
    ///
    /// `reports` is one entry per member, in the superblock's order, `None`
    /// for a member that is not a zoned device. A member that IS one on a
    /// volume not formatted for zones is refused: the format decides the
    /// layout, and a zoned drive holding a conventional layout would be
    /// written wherever the filesystem liked.
    /// # C: O(zones)
    pub fn build(feature: u32, reports: &[Option<DevZones>], active_logs: u32)
        -> Result<Self, ZoneError> {
        if !crate::features::has_blkzoned(feature) && reports.iter().any(Option::is_some) {
            return Err(ZoneError::FeatureOff);
        }
        let mut blocks_per_zone = 0u32;
        let mut unusable = 0u32;
        let mut max_open = OPEN_ZONES_UNBOUNDED;
        let mut seq: Vec<Vec<bool>> = Vec::with_capacity(reports.len());
        for r in reports {
            let Some(r) = r else { seq.push(Vec::new()); continue };
            if let Some(m) = r.max_open_zones {
                if m != 0 && m < max_open { max_open = m; }
            }
            if max_open < active_logs { return Err(ZoneError::TooFewOpenZones); }
            if blocks_per_zone != 0 && blocks_per_zone != r.blocks_per_zone {
                return Err(ZoneError::MixedZoneSize);
            }
            blocks_per_zone = r.blocks_per_zone;
            let mut bits = alloc::vec![false; r.zones.len()];
            for (idx, z) in r.zones.iter().enumerate() {
                if !z.kind.sequential() { continue; }
                bits[idx] = true;
                let u = z.unusable_blks();
                // The FIRST sequential zone fixes the figure; a zone that
                // disagrees is refused rather than averaged, and a first zone
                // with none makes every later short zone a disagreement.
                if unusable == 0 { unusable = u; continue; }
                if unusable != u { return Err(ZoneError::MixedCapacity); }
            }
            seq.push(bits);
        }
        Ok(Self {
            blocks_per_zone,
            unusable_blocks_per_sec: unusable,
            max_open_zones: max_open,
            seq,
        })
    }

    /// Whether zone `zoneno` of member `dev` must be written sequentially.
    /// A member that reported nothing has no sequential zones.
    /// # C: O(1)
    pub fn is_seq(&self, dev: usize, zoneno: usize) -> bool {
        self.seq.get(dev).and_then(|b| b.get(zoneno)).copied().unwrap_or(false)
    }

    /// Zones member `dev` reported. # C: O(1)
    pub fn zone_count(&self, dev: usize) -> usize {
        self.seq.get(dev).map_or(0, |b| b.len())
    }

    /// Whether member `dev` is a zoned drive — that is, reported at least one
    /// sequential zone. A member that reported nothing, or reported only
    /// conventional zones, behaves exactly like an ordinary drive.
    /// # C: O(zones)
    pub fn dev_is_zoned(&self, dev: usize) -> bool {
        self.seq.get(dev).is_some_and(|b| b.iter().any(|&s| s))
    }

    /// Whether any member reported a sequential zone. # C: O(zones)
    pub fn any_sequential(&self) -> bool {
        (0..self.seq.len()).any(|d| self.dev_is_zoned(d))
    }
}
