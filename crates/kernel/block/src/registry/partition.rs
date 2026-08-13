//! Disk-owned partition scanning and publication.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::partitions::{self, PartitionDevice};
use crate::BlockDevice;

use super::{DevNum, Disk, PARTITION_MINOR_COUNT};
#[cfg(test)] use super::by_name;

/// One published partition, owned by its parent whole-disk object.
pub struct Partition {
    pub name: String,
    pub number_dev: DevNum,
    pub number: u32,
    pub start_lba: u64,
    pub sectors: u64,
    pub uuid: Option<String>,
    pub label: Option<String>,
    pub dev: Arc<dyn BlockDevice>,
}

/// Scan a whole disk then replace its complete, disk-owned partition set.
/// A malformed table and a valid unpartitioned disk both publish an empty set.
/// # C: O(partition table)
pub fn rescan_partitions(name: &str) -> Option<Vec<Arc<Partition>>> {
    let rescan = super::try_partition_rescan(name)?;
    let disk = Arc::clone(rescan.disk());
    unpublish_partitions(&disk);
    let capacity = disk.dev.capacity_blocks();
    let parts = partitions::read(disk.dev.as_ref()).into_iter().filter_map(|info| {
        if info.number >= PARTITION_MINOR_COUNT { return None; }
        let name = partitions::node_name(&disk.name, info.number)?;
        let sectors = match info.start_lba.checked_add(info.sectors) {
            Some(end) if end <= capacity => info.sectors,
            _ => capacity.checked_sub(info.start_lba)?,
        };
        let dev = PartitionDevice::new(Arc::clone(&disk.dev), info.start_lba, sectors)?;
        Some(Arc::new(Partition {
            name, number_dev: DevNum { major: disk.number.major, minor: disk.number.minor.checked_add(info.number)? },
            number: info.number, start_lba: info.start_lba, sectors,
            uuid: info.uuid, label: info.label, dev,
        }))
    }).collect();
    disk.publish_partitions(parts);
    let parts = disk.partitions();
    let parent = drv::devices().into_iter().find(|device| device.bus == "block" && device.addr == disk.name);
    for part in &parts {
        crate::devbridge::publish_partition(Arc::clone(part));
        let node = Arc::new(drv::Device::new("block", part.name.clone(), 0, 0, 0)
            .with_devnode("block", part.name.clone(), Some((part.number_dev.major, part.number_dev.minor))));
        if let Some(parent) = &parent { let _ = drv::try_device_add_with_parent(node, parent); }
        else { let _ = drv::try_device_add(node); }
    }
    Some(parts)
}

/// Remove all published child partitions of a disk before its parent is
/// removed or its partition table is replaced. # C: O(partitions + devices)
pub(crate) fn unpublish_partitions(disk: &Disk) {
    let parts = disk.partitions();
    disk.publish_partitions(Vec::new());
    for part in parts {
        crate::devbridge::unpublish_partition(&part);
        if let Some(node) = drv::devices().into_iter().find(|device| device.bus == "block" && device.addr == part.name) { drv::device_del(&node); }
    }
}

/// Find a partition by its conventional block-node name. # C: O(disks + partitions)
pub fn partition_by_name(name: &str) -> Option<Arc<Partition>> {
    super::snapshot().into_iter().flat_map(|disk| disk.partitions()).find(|part| part.name == name)
}

/// Resolve a packed device number to its disk-owned partition. # C: O(disks + partitions)
pub fn partition_by_dev(dev_t: u32) -> Option<Arc<Partition>> {
    let (major, minor) = super::decode_dev(dev_t);
    super::snapshot().into_iter().flat_map(|disk| disk.partitions())
        .find(|part| part.number_dev == DevNum { major, minor })
}

/// Find a partition by its on-media UUID. # C: O(disks + partitions)
pub fn partition_by_uuid(uuid: &str) -> Option<Arc<Partition>> {
    super::snapshot().into_iter().flat_map(|disk| disk.partitions())
        .find(|part| part.uuid.as_deref().is_some_and(|id| id.eq_ignore_ascii_case(uuid)))
}

/// Find the partition at a signed number offset from a partition UUID.
/// # C: O(disks + partitions)
pub fn partition_by_uuid_offset(uuid: &str, offset: i32) -> Option<Arc<Partition>> {
    let (disk, base) = super::snapshot().into_iter().find_map(|disk| {
        disk.partitions().into_iter().find(|part| part.uuid.as_deref().is_some_and(|id| id.eq_ignore_ascii_case(uuid)))
            .map(|part| (disk, part))
    })?;
    let number = i64::from(base.number).checked_add(i64::from(offset))?;
    let number = u32::try_from(number).ok().filter(|number| *number != 0)?;
    disk.partitions().into_iter().find(|part| part.number == number)
}

/// Find a partition by its on-media label. # C: O(disks + partitions)
pub fn partition_by_label(label: &str) -> Option<Arc<Partition>> {
    super::snapshot().into_iter().flat_map(|disk| disk.partitions())
        .find(|part| part.label.as_deref() == Some(label))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockRequest, MemDisk, register, unregister};
    use alloc::vec;
    use sync::TaskList;

    const PUBLISH_NAME: &str = "partition-scan-publish-fixture";
    const REPLACE_NAME: &str = "partition-scan-replace-fixture";
    const CLIP_NAME: &str = "partition-scan-clip-fixture";
    const REMOVE_NAME: &str = "partition-scan-remove-fixture";
    const BLOCK_BYTES: u32 = 512;

    #[test]
    fn rescan_publishes_bounded_disk_owned_children() {
        let dev = MemDisk::<TaskList>::new(BLOCK_BYTES, 32);
        let mut mbr = vec![0; BLOCK_BYTES as usize];
        mbr[440..444].copy_from_slice(&0x1234_abcd_u32.to_le_bytes());
        mbr[446 + 4] = 0x83;
        mbr[446 + 8..446 + 12].copy_from_slice(&4u32.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&8u32.to_le_bytes());
        mbr[510..512].copy_from_slice(&[0x55, 0xaa]);
        let mut write = BlockRequest::new_write(0, 1, mbr);
        dev.submit_sync(&mut write).expect("fixture table write");
        assert_ne!(register(PUBLISH_NAME, dev), 0);

        let parts = by_name(PUBLISH_NAME).expect("registered disk").partitions();
        assert_eq!(parts.len(), 1);
        let part = &parts[0];
        assert_eq!(part.name, "partition-scan-publish-fixture1");
        assert_eq!(part.start_lba, 4);
        assert_eq!(part.sectors, 8);
        assert_eq!(part.uuid.as_deref(), Some("1234abcd-01"));
        assert_eq!(part.dev.capacity_blocks(), 8);
        assert!(partition_by_name(&part.name).is_some());
        assert!(partition_by_uuid("1234abcd-01").is_some());
        assert!(partition_by_label("root").is_none());
        assert!(unregister(PUBLISH_NAME));
    }

    #[test]
    fn rescan_replaces_stale_children_after_table_change() {
        let dev = MemDisk::<TaskList>::new(BLOCK_BYTES, 32);
        assert_ne!(register(REPLACE_NAME, dev), 0);
        assert!(rescan_partitions(REPLACE_NAME).expect("registered disk").is_empty());
        assert!(by_name(REPLACE_NAME).expect("registered disk").partitions().is_empty());
        assert!(unregister(REPLACE_NAME));
    }

    #[test]
    fn rescan_clips_a_partition_that_runs_past_the_end_of_disk() {
        let dev = MemDisk::<TaskList>::new(BLOCK_BYTES, 32);
        let mut mbr = vec![0; BLOCK_BYTES as usize];
        mbr[446 + 4] = 0x83;
        mbr[446 + 8..446 + 12].copy_from_slice(&28u32.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&8u32.to_le_bytes());
        mbr[510..512].copy_from_slice(&[0x55, 0xaa]);
        let mut write = BlockRequest::new_write(0, 1, mbr);
        dev.submit_sync(&mut write).expect("fixture table write");
        assert_ne!(register(CLIP_NAME, dev), 0);

        let parts = rescan_partitions(CLIP_NAME).expect("registered disk");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].start_lba, 28);
        assert_eq!(parts[0].sectors, 4);
        assert!(unregister(CLIP_NAME));
    }

    #[test]
    fn unregister_removes_all_partition_publication() {
        let dev = MemDisk::<TaskList>::new(BLOCK_BYTES, 32);
        let mut mbr = vec![0; BLOCK_BYTES as usize];
        mbr[446 + 4] = 0x83;
        mbr[446 + 8..446 + 12].copy_from_slice(&4u32.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&8u32.to_le_bytes());
        mbr[510..512].copy_from_slice(&[0x55, 0xaa]);
        let mut write = BlockRequest::new_write(0, 1, mbr);
        dev.submit_sync(&mut write).expect("fixture table write");
        assert_ne!(register(REMOVE_NAME, dev), 0);

        let part = by_name(REMOVE_NAME).expect("registered disk").partitions().pop().expect("published partition");
        let devt = vfs::Devt(super::super::encode_dev(part.number_dev.major, part.number_dev.minor));
        assert!(vfs::lookup_blkdev(devt).is_some(), "partition VFS region is live");

        assert!(unregister(REMOVE_NAME));
        assert!(vfs::lookup_blkdev(devt).is_none(), "partition VFS region is removed with disk");
    }
}
