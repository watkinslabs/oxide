//! The same image, split across several member media.
//!
//! The split is the point of the fixture. One flat image and the same bytes
//! cut at the member boundaries must mount to the same volume and read the
//! same files; anything the address map gets wrong shows up as a difference
//! between the two, with no assertion about the map itself required.

use alloc::string::String;
use alloc::vec::Vec;

use sectors::MemImage;
use syscall::errno::Errno;

use crate::devices::{DeviceSet, DevTable};
use crate::opts::Options;
use crate::uapi::{BLKSIZE, SUPER_OFFSET, SUPER_SIZE};
use crate::volume::Volume;
use crate::zoned::{DevZones, Zone, ZoneType};

use super::Builder;

/// The medium a spread fixture mounts through.
pub type Spread = DeviceSet<MemImage>;

impl Builder {
    /// Name the member devices this volume is spread over.
    ///
    /// The segment counts must sum to the volume's total, which is what the
    /// superblock check demands; a fixture that does not is rejected at
    /// mount and would test the check rather than the map.
    /// # C: O(devices)
    pub fn devices(mut self, devs: &[(&str, u32)]) -> Self {
        self.devices = devs.iter().map(|(p, s)| (String::from(*p), *s)).collect();
        self
    }
}

/// The finished image cut into one medium per member. # C: O(image bytes)
pub fn members(b: Builder) -> (Vec<MemImage>, DevTable) {
    let bytes = b.finish();
    let raw = &bytes[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE];
    let sb = crate::sb::parse(raw).expect("fixture superblock parses");
    let table = DevTable::scan(&sb);
    let mut out = Vec::with_capacity(table.len());
    for d in table.devs() {
        let from = d.start_blk as usize * BLKSIZE;
        let to = ((d.end_blk as usize) + 1) * BLKSIZE;
        let piece = bytes.get(from..to.min(bytes.len())).unwrap_or(&[]).to_vec();
        out.push(MemImage::from_bytes(BLKSIZE as u32, piece));
    }
    (out, table)
}

/// The finished image, spread over its members and mounted read-write.
/// # C: O(image bytes)
pub fn mount(b: Builder) -> Result<Volume<Spread>, Errno> {
    mount_zoned(b, &[])
}

/// The same, with what each member says about its zones. # C: O(image bytes)
pub fn mount_zoned(b: Builder, reports: &[Option<DevZones>]) -> Result<Volume<Spread>, Errno> {
    let (media, table) = members(b);
    let set = DeviceSet::new(media, table)?;
    Volume::mount_devices(set, Options::defaults(), true, reports)
}

/// A report of `count` zones of `len` blocks each, the first `conv` of them
/// conventional and the rest sequential with `cap` usable blocks.
/// # C: O(count)
pub fn report(count: usize, len: u32, cap: u32, conv: usize) -> DevZones {
    let zones = (0..count)
        .map(|i| Zone::fresh(
            (i as u64) * u64::from(len),
            len,
            if i < conv { len } else { cap },
            if i < conv { ZoneType::Conventional } else { ZoneType::SeqWriteRequired }))
        .collect();
    DevZones { blocks_per_zone: len, max_open_zones: None, zones }
}
