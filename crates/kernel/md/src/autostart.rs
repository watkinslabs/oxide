//! Boot-time assembly of RAID-marked partition members.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use block::BlockDevice;

use crate::{MetadataVersion, Superblock, publish, read_superblock};
use crate::assembly::assemble_registered;

struct Candidate {
    parent: String,
    member: Arc<dyn BlockDevice>,
    version: MetadataVersion,
    superblock: Superblock,
}

/// Inspect every RAID-marked partition published by the block layer, collect
/// complete current arrays, and publish each successfully assembled array.
/// # C: O(raid members × 4 KiB)
pub(crate) fn init() { let _ = autostart(); }

fn autostart() -> usize {
    let mut groups: Vec<Vec<Candidate>> = Vec::new();
    for disk in block::registry::snapshot() {
        for part in disk.partitions().into_iter().filter(|part| part.is_raid) {
            let Some((version, superblock)) = read_member(part.dev.as_ref()) else { continue; };
            let candidate = Candidate { parent: disk.name.clone(), member: part.dev.clone(), version, superblock };
            if let Some(group) = groups.iter_mut().find(|group| group[0].version == candidate.version
                && group[0].superblock.same_array(&candidate.superblock)) {
                group.push(candidate);
            } else {
                groups.push(Vec::from([candidate]));
            }
        }
    }
    let mut started = 0;
    for group in groups {
        let Some(reference) = group.iter().max_by_key(|candidate| candidate.superblock.events())
            .map(|candidate| (candidate.version, candidate.superblock.clone())) else { continue; };
        let members = group.into_iter().filter(|candidate| reference.1.roles()
            .get(candidate.superblock.dev_number() as usize).is_some_and(|role| usize::from(*role) < reference.1.raid_disks() as usize))
            .map(|candidate| (candidate.parent, candidate.member)).collect();
        let Ok(array) = assemble_registered(members, reference.0) else { continue; };
        let Some(name) = next_name() else { continue; };
        if publish(&name, array) != 0 { started += 1; }
    }
    started
}

fn read_member(member: &dyn BlockDevice) -> Option<(MetadataVersion, Superblock)> {
    [MetadataVersion::V1_0, MetadataVersion::V1_1, MetadataVersion::V1_2].into_iter()
        .find_map(|version| read_superblock(member, version).ok().map(|superblock| (version, superblock)))
}

fn next_name() -> Option<String> {
    const MAX_MD_MINORS: u32 = 1 << 20;
    (0..MAX_MD_MINORS).map(|minor| alloc::format!("md{minor}")).find(|name| block::registry::by_name(name).is_none())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::sync::Arc;
    use alloc::vec;
    use block::{BlockDevice, BlockRequest, MemDisk};
    use sync::TaskList;

    use super::*;

    const LEFT: &str = "md-autostart-left";
    const RIGHT: &str = "md-autostart-right";

    fn put32(bytes: &mut [u8], offset: usize, value: u32) { bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) { bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }

    fn metadata(number: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 4096];
        put32(&mut bytes, 0, 0xa92b_4efc); put32(&mut bytes, 4, 1);
        bytes[16..32].copy_from_slice(b"md-autostart-001"); put32(&mut bytes, 72, (-1i32) as u32);
        put64(&mut bytes, 80, 128); put32(&mut bytes, 92, 2); put64(&mut bytes, 128, 16); put64(&mut bytes, 136, 128);
        put64(&mut bytes, 144, 8); put32(&mut bytes, 160, number); put64(&mut bytes, 200, 3); put32(&mut bytes, 220, 2);
        bytes[256..258].copy_from_slice(&0u16.to_le_bytes()); bytes[258..260].copy_from_slice(&1u16.to_le_bytes());
        let checksum = crate::superblock::checksum(&bytes, 260).expect("checksum"); put32(&mut bytes, 216, checksum);
        bytes
    }

    fn member(number: u32) -> Arc<dyn BlockDevice> {
        let member: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(512, 512);
        let mut mbr = vec![0u8; 512];
        mbr[446 + 4] = 0xfd; mbr[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&256u32.to_le_bytes()); mbr[510..].copy_from_slice(&[0x55, 0xaa]);
        member.submit_sync(&mut BlockRequest::new_write(0, 1, mbr)).expect("write MBR");
        member.submit_sync(&mut BlockRequest::new_write(9, 8, metadata(number))).expect("write metadata");
        member
    }

    #[test]
    fn boot_hook_assembles_raid_marked_partitions_and_holds_parents() {
        let left = member(0); let right = member(1);
        assert_ne!(block::registry::register(LEFT, Arc::clone(&left)), 0);
        assert_ne!(block::registry::register(RIGHT, Arc::clone(&right)), 0);
        let before: Vec<u32> = block::registry::snapshot().into_iter().filter(|disk| disk.driver.name == "md").map(|disk| disk.index).collect();
        crate::init();
        let array = block::registry::snapshot().into_iter().find(|disk| disk.driver.name == "md" && !before.contains(&disk.index)).expect("published MD array");
        assert_eq!(block::registry::holder_count(LEFT), Some(1)); assert_eq!(block::registry::holder_count(RIGHT), Some(1));
        let mut write = BlockRequest::new_write(128, 1, vec![0x5a; 512]); array.dev.submit_sync(&mut write).expect("array write");
        let mut read = BlockRequest::new_read(17, 1, 512); right.submit_sync(&mut read).expect("member read");
        assert_eq!(read.buffer, vec![0x5a; 512]);
        let name = array.name.clone(); drop(array);
        assert!(block::registry::unregister(&name));
        assert_eq!(block::registry::holder_count(LEFT), Some(0)); assert_eq!(block::registry::holder_count(RIGHT), Some(0));
        assert!(block::registry::unregister(LEFT)); assert!(block::registry::unregister(RIGHT));
    }
}
