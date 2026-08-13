//! Disk-owned partition scanning and publication.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::partitions::{self, PartitionDevice};
use crate::BlockDevice;

use super::by_name;

/// One published partition, owned by its parent whole-disk object.
pub struct Partition {
    pub name: String,
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
    let disk = by_name(name)?;
    let capacity = disk.dev.capacity_blocks();
    let parts = partitions::read(disk.dev.as_ref()).into_iter().filter_map(|info| {
        let name = partitions::node_name(&disk.name, info.number)?;
        let sectors = match info.start_lba.checked_add(info.sectors) {
            Some(end) if end <= capacity => info.sectors,
            _ => capacity.checked_sub(info.start_lba)?,
        };
        let dev = PartitionDevice::new(Arc::clone(&disk.dev), info.start_lba, sectors)?;
        Some(Arc::new(Partition {
            name, number: info.number, start_lba: info.start_lba, sectors,
            uuid: info.uuid, label: info.label, dev,
        }))
    }).collect();
    disk.publish_partitions(parts);
    Some(disk.partitions())
}

/// Find a partition by its conventional block-node name. # C: O(disks + partitions)
pub fn partition_by_name(name: &str) -> Option<Arc<Partition>> {
    super::snapshot().into_iter().flat_map(|disk| disk.partitions()).find(|part| part.name == name)
}

/// Find a partition by its on-media UUID. # C: O(disks + partitions)
pub fn partition_by_uuid(uuid: &str) -> Option<Arc<Partition>> {
    super::snapshot().into_iter().flat_map(|disk| disk.partitions())
        .find(|part| part.uuid.as_deref() == Some(uuid))
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

        let parts = rescan_partitions(PUBLISH_NAME).expect("registered disk");
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
}
