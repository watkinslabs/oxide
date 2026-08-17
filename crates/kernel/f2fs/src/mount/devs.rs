//! Finding a volume's member devices, and asking each what its zones are.
//!
//! The only place in this filesystem that turns a path on the medium into a
//! block device. Everything above it addresses members by index.
//!
//! Two conversions live here because they are both block-layer facing. The
//! zone report arrives in the DEVICE's block unit, which need not be the
//! volume's, and a report used in the wrong unit puts every zone boundary in
//! the wrong place — which is the one mistake in this area that corrupts a
//! real drive rather than merely failing.

use alloc::sync::Arc;
use alloc::vec::Vec;

use sectors::BlockSource;

use vfs::{KResult, VfsError};

use crate::devices::{DeviceSet, DevTable};
use crate::sb::SuperBlock;
use crate::uapi::BLKSIZE;
use crate::zoned::{DevZones, Zone, ZoneCond, ZoneType};

/// The medium a mounted volume reads through: its members, behind the map
/// that says which of them holds a given block.
pub type Medium = DeviceSet<BlockSource>;

/// The prefix a superblock's device paths carry.
const DEV_PREFIX: &str = "/dev/";

/// Every member device, in the superblock's order.
///
/// Member zero is the device the mount was given rather than the one its
/// recorded path names: the mount already has it open, and a path that has
/// since been renamed must not stop a volume mounting from the device in
/// hand.
/// # C: O(devices)
#[inline(never)]
pub fn open_members(dev: Arc<dyn block::BlockDevice>, sb: &SuperBlock)
    -> KResult<Vec<Arc<dyn block::BlockDevice>>> {
    let mut out = Vec::with_capacity(sb.devices.len().max(1));
    out.push(dev);
    for spec in sb.devices.iter().skip(1) {
        out.push(by_path(&spec.path).ok_or(VfsError::Enoent)?);
    }
    Ok(out)
}

/// One member, by the path the superblock recorded. # C: O(disks)
fn by_path(path: &str) -> Option<Arc<dyn block::BlockDevice>> {
    let name = path.strip_prefix(DEV_PREFIX).unwrap_or(path);
    if name.is_empty() || name.contains('/') { return None; }
    block::by_name(name).map(|d| Arc::clone(&d.dev))
}

/// What each member says about its zones, in the volume's block unit.
/// # C: O(zones)
#[inline(never)]
pub fn zone_reports(members: &[Arc<dyn block::BlockDevice>]) -> Vec<Option<DevZones>> {
    members.iter().map(|d| convert(d.zone_report()?, d.block_size())).collect()
}

/// A device's report in the volume's unit, or `None` when the two units make
/// the report unusable.
///
/// A drive whose blocks are LARGER than the volume's is fine — the boundaries
/// still fall on volume blocks. One whose zones do not land on a whole number
/// of volume blocks is refused rather than rounded: a rounded boundary is a
/// zone map that disagrees with the drive.
/// # C: O(zones)
pub(crate) fn convert(r: block::ZoneReport, dev_block: u32) -> Option<DevZones> {
    let bs = u64::from(dev_block.max(1));
    let per = BLKSIZE as u64;
    let to_blks = |n: u64| -> Option<u32> {
        let bytes = n.checked_mul(bs)?;
        if bytes % per != 0 { return None; }
        u32::try_from(bytes / per).ok()
    };
    let mut zones = Vec::with_capacity(r.zones.len());
    for z in &r.zones {
        let start_bytes = z.start_block.checked_mul(bs)?;
        if start_bytes % per != 0 { return None; }
        // The write pointer is the one figure that need NOT land on a volume
        // block: the drive moves it by its own block, so a drive with the
        // smaller block can park it inside one of ours. Rounding it down and
        // saying so is the only honest answer — rounding up would place it
        // past bytes the drive has already taken, and rounding silently would
        // make a log that is half a block behind the drive look aligned.
        let (wp_blk, wp_partial) = match z.wp_block {
            Some(wp) => {
                let bytes = wp.checked_mul(bs)?;
                (Some(bytes / per), bytes % per != 0)
            }
            None => (None, false),
        };
        zones.push(Zone {
            start_blk: start_bytes / per,
            len_blks: to_blks(z.len_blocks)?,
            cap_blks: to_blks(z.capacity_blocks)?,
            kind: match z.kind {
                block::ZoneType::Conventional => ZoneType::Conventional,
                block::ZoneType::SeqWriteRequired => ZoneType::SeqWriteRequired,
                block::ZoneType::SeqWritePreferred => ZoneType::SeqWritePreferred,
            },
            wp_blk,
            wp_partial,
            cond: match z.cond {
                block::ZoneCond::NotWp => ZoneCond::NotWp,
                block::ZoneCond::Empty => ZoneCond::Empty,
                block::ZoneCond::ImplicitOpen => ZoneCond::ImplicitOpen,
                block::ZoneCond::ExplicitOpen => ZoneCond::ExplicitOpen,
                block::ZoneCond::Closed => ZoneCond::Closed,
                block::ZoneCond::Full => ZoneCond::Full,
                block::ZoneCond::ReadOnly => ZoneCond::ReadOnly,
                block::ZoneCond::Offline => ZoneCond::Offline,
            },
        });
    }
    Some(DevZones {
        blocks_per_zone: to_blks(r.zone_blocks)?,
        max_open_zones: r.max_open_zones,
        zones,
    })
}

/// The medium a volume reads through, built from members already open.
/// # C: O(devices)
#[inline(never)]
pub fn medium(members: &[Arc<dyn block::BlockDevice>], table: DevTable, write: bool)
    -> KResult<Medium> {
    let sources: Vec<BlockSource> = members
        .iter()
        .map(|d| {
            BlockSource::new(Arc::clone(d)).with_sector_size(BLKSIZE as u32).writable(write)
        })
        .collect();
    DeviceSet::new(sources, table).map_err(crate::mount::errno_to_vfs)
}
