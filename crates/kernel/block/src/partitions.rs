//! On-media GPT and DOS partition-table decoding.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::{BlockDevice, BlockRequest};

mod device;
pub use device::PartitionDevice;

const SECTOR_BYTES: usize = 512;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";
const GPT_HEADER_MIN_BYTES: usize = 92;
const GPT_ENTRY_MIN_BYTES: usize = 128;
const GPT_ENTRY_MAX_BYTES: usize = 4096;
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_PARTITION_OFFSET: usize = 446;
const MBR_PARTITION_BYTES: usize = 16;
const MBR_PARTITION_COUNT: usize = 4;
const GPT_PROTECTIVE_TYPE: u8 = 0xee;
const LINUX_RAID_MBR_TYPE: u8 = 0xfd;
const LINUX_RAID_GPT_TYPE: [u8; 16] = [0x0f, 0x88, 0x9d, 0xa1, 0xfc, 0x05, 0x3b, 0x4d,
    0xa0, 0x06, 0x74, 0x3f, 0x0f, 0x84, 0x91, 0x1e];

/// One partition discovered from a validated on-media table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartitionInfo {
    pub number: u32,
    pub start_lba: u64,
    pub sectors: u64,
    pub is_raid: bool,
    pub uuid: Option<String>,
    pub label: Option<String>,
}

/// Derive the conventional partition node name from a whole-disk node name.
/// Disk names ending in an ASCII digit use the required `p` separator.
/// # C: O(name length)
pub fn node_name(disk: &str, number: u32) -> Option<String> {
    if disk.is_empty() || number == 0 { return None; }
    let separator = disk.as_bytes().last().is_some_and(u8::is_ascii_digit).then_some("p").unwrap_or("");
    Some(alloc::format!("{disk}{separator}{number}"))
}

/// Parse the partition table at the start of a 512-byte-sector disk image.
/// A protective DOS record selects GPT; otherwise primary DOS entries are
/// returned. Corrupt GPT metadata yields no partitions rather than mounting a
/// range whose identity was not authenticated. # C: O(entries)
pub fn parse(bytes: &[u8]) -> Vec<PartitionInfo> {
    let Some(mbr) = bytes.get(..SECTOR_BYTES) else { return Vec::new(); };
    if mbr.get(MBR_SIGNATURE_OFFSET..) != Some(&[0x55, 0xaa]) { return Vec::new(); }
    if mbr_entries(mbr).any(|(_, kind, _, _)| kind == GPT_PROTECTIVE_TYPE) {
        return parse_gpt(bytes);
    }
    parse_mbr(mbr)
}

/// Read and decode a whole-disk partition table through the canonical block
/// backend. GPT is read through the end of its declared entry array; a table
/// outside the medium or with invalid metadata yields no entries. # C: O(table)
pub fn read(device: &dyn BlockDevice) -> Vec<PartitionInfo> {
    let block_bytes = match usize::try_from(device.block_size()) { Ok(bytes) => bytes, Err(_) => return Vec::new() };
    if block_bytes < SECTOR_BYTES || block_bytes % SECTOR_BYTES != 0 || device.capacity_blocks() < 2 { return Vec::new(); }
    let mut head = BlockRequest::new_read(0, 2, device.block_size());
    if device.submit_sync(&mut head).is_err() { return Vec::new(); }
    if !is_protective_mbr(&head.buffer) { return parse_mbr(&head.buffer[..SECTOR_BYTES]).into_iter().filter_map(|part| scale_mbr(part, block_bytes)).collect(); }
    let header = match head.buffer.get(block_bytes..block_bytes * 2) { Some(v) => v, None => return Vec::new() };
    let count = le32(&header[80..84]) as usize;
    let entry_bytes = le32(&header[84..88]) as usize;
    let entries_lba = le64(&header[72..80]);
    if count == 0 || !(GPT_ENTRY_MIN_BYTES..=GPT_ENTRY_MAX_BYTES).contains(&entry_bytes) { return Vec::new(); }
    let bytes = match count.checked_mul(entry_bytes) { Some(v) => v, None => return Vec::new() };
    let sectors = match bytes.checked_add(block_bytes - 1).map(|v| v / block_bytes) { Some(v) => v, None => return Vec::new() };
    let blocks = match usize::try_from(entries_lba).ok().and_then(|v| v.checked_add(sectors)) { Some(v) => v, None => return Vec::new() };
    if blocks > device.capacity_blocks() as usize || blocks > u32::MAX as usize { return Vec::new(); }
    let mut table = BlockRequest::new_read(0, blocks as u32, device.block_size());
    if device.submit_sync(&mut table).is_err() { return Vec::new(); }
    parse_gpt_at(&table.buffer, block_bytes)
}

fn scale_mbr(mut part: PartitionInfo, block_bytes: usize) -> Option<PartitionInfo> {
    let scale = u64::try_from(block_bytes / SECTOR_BYTES).ok()?;
    if part.start_lba % scale != 0 || part.sectors % scale != 0 { return None; }
    part.start_lba /= scale;
    part.sectors /= scale;
    Some(part)
}

fn is_protective_mbr(bytes: &[u8]) -> bool {
    bytes.get(..SECTOR_BYTES).is_some_and(|mbr| mbr.get(MBR_SIGNATURE_OFFSET..) == Some(&[0x55, 0xaa])
        && mbr_entries(mbr).any(|(_, kind, _, _)| kind == GPT_PROTECTIVE_TYPE))
}

fn mbr_entries(mbr: &[u8]) -> impl Iterator<Item = (u32, u8, u32, u32)> + '_ {
    (0..MBR_PARTITION_COUNT).filter_map(move |slot| {
        let off = MBR_PARTITION_OFFSET + slot * MBR_PARTITION_BYTES;
        let entry = mbr.get(off..off + MBR_PARTITION_BYTES)?;
        let kind = entry[4];
        let start = le32(&entry[8..12]);
        let sectors = le32(&entry[12..16]);
        Some((slot as u32 + 1, kind, start, sectors))
    })
}

fn parse_mbr(mbr: &[u8]) -> Vec<PartitionInfo> {
    let signature = le32(&mbr[440..444]);
    mbr_entries(mbr).filter_map(|(number, kind, start, sectors)| {
        if kind == 0 || sectors == 0 { return None; }
        Some(PartitionInfo {
            number, start_lba: u64::from(start), sectors: u64::from(sectors), is_raid: kind == LINUX_RAID_MBR_TYPE,
            uuid: Some(alloc::format!("{signature:08x}-{number:02x}")), label: None,
        })
    }).collect()
}

fn parse_gpt(bytes: &[u8]) -> Vec<PartitionInfo> { parse_gpt_at(bytes, SECTOR_BYTES) }

fn parse_gpt_at(bytes: &[u8], block_bytes: usize) -> Vec<PartitionInfo> {
    let header = match bytes.get(block_bytes..block_bytes * 2) { Some(header) => header, None => return Vec::new() };
    if header.get(..8) != Some(GPT_SIGNATURE) { return Vec::new(); }
    let header_bytes = le32(&header[12..16]) as usize;
    if !(GPT_HEADER_MIN_BYTES..=block_bytes).contains(&header_bytes) { return Vec::new(); }
    let header_crc = le32(&header[16..20]);
    let mut checked = header[..header_bytes].to_vec();
    checked[16..20].fill(0);
    if crc::crc32(&checked) != header_crc { return Vec::new(); }
    let entries_lba = le64(&header[72..80]);
    let count = le32(&header[80..84]) as usize;
    let entry_bytes = le32(&header[84..88]) as usize;
    let entries_crc = le32(&header[88..92]);
    if count == 0 || entry_bytes < GPT_ENTRY_MIN_BYTES || entry_bytes > GPT_ENTRY_MAX_BYTES { return Vec::new(); }
    let total = match count.checked_mul(entry_bytes) { Some(total) => total, None => return Vec::new() };
    let offset = match usize::try_from(entries_lba).ok().and_then(|lba| lba.checked_mul(block_bytes)) { Some(offset) => offset, None => return Vec::new() };
    let entries = match bytes.get(offset..offset.saturating_add(total)) { Some(entries) => entries, None => return Vec::new() };
    if crc::crc32(entries) != entries_crc { return Vec::new(); }
    entries.chunks_exact(entry_bytes).enumerate().filter_map(|(index, entry)| {
        if entry[..16].iter().all(|byte| *byte == 0) { return None; }
        let start_lba = le64(&entry[32..40]);
        let end_lba = le64(&entry[40..48]);
        if end_lba < start_lba { return None; }
        let sectors = end_lba.checked_sub(start_lba)?.checked_add(1)?;
        let number = u32::try_from(index + 1).ok()?;
        Some(PartitionInfo {
            number, start_lba, sectors, is_raid: entry[..16] == LINUX_RAID_GPT_TYPE,
            uuid: Some(guid(&entry[16..32])), label: utf16_label(&entry[56..]),
        })
    }).collect()
}

fn le32(bytes: &[u8]) -> u32 { u32::from_le_bytes(bytes.try_into().expect("partition field width")) }
fn le64(bytes: &[u8]) -> u64 { u64::from_le_bytes(bytes.try_into().expect("partition field width")) }

fn guid(bytes: &[u8]) -> String {
    alloc::format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[3], bytes[2], bytes[1], bytes[0], bytes[5], bytes[4], bytes[7], bytes[6],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15])
}

fn utf16_label(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    for pair in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 { break; }
        units.push(unit);
    }
    let label = String::from_utf16(&units).ok()?;
    (!label.is_empty()).then_some(label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlockDevice, BlockRequest, MemDisk};
    use sync::TaskList;
    use alloc::vec;

    fn mbr() -> Vec<u8> { let mut disk = vec![0; SECTOR_BYTES]; disk[MBR_SIGNATURE_OFFSET..].copy_from_slice(&[0x55, 0xaa]); disk }

    #[test]
    fn dos_primary_partition_has_the_standard_disk_signature_identity() {
        let mut disk = mbr();
        disk[440..444].copy_from_slice(&0x1234_abcd_u32.to_le_bytes());
        let e = &mut disk[MBR_PARTITION_OFFSET..MBR_PARTITION_OFFSET + MBR_PARTITION_BYTES];
        e[4] = 0x83; e[8..12].copy_from_slice(&2048u32.to_le_bytes()); e[12..16].copy_from_slice(&4096u32.to_le_bytes());
        assert_eq!(parse(&disk), vec![PartitionInfo { number: 1, start_lba: 2048, sectors: 4096, is_raid: false, uuid: Some("1234abcd-01".into()), label: None }]);
    }

    #[test]
    fn corrupt_or_incomplete_tables_publish_nothing() {
        assert!(parse(&[]).is_empty());
        let mut disk = mbr();
        disk[MBR_PARTITION_OFFSET + 4] = GPT_PROTECTIVE_TYPE;
        assert!(parse(&disk).is_empty());
    }

    #[test]
    fn gpt_guid_uses_the_canonical_mixed_endian_text_form() {
        assert_eq!(guid(&[0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                   "00112233-4455-6677-8899-aabbccddeeff");
    }

    #[test]
    fn partition_node_separator_follows_the_disk_name_grammar() {
        assert_eq!(node_name("sda", 1).as_deref(), Some("sda1"));
        assert_eq!(node_name("vda", 15).as_deref(), Some("vda15"));
        assert_eq!(node_name("nvme0n1", 2).as_deref(), Some("nvme0n1p2"));
        assert_eq!(node_name("mmcblk0", 3).as_deref(), Some("mmcblk0p3"));
        assert_eq!(node_name("", 1), None);
        assert_eq!(node_name("sda", 0), None);
    }

    #[test]
    fn linux_raid_partition_types_survive_mbr_and_gpt_parsing() {
        let mut mbr = mbr();
        let entry = &mut mbr[MBR_PARTITION_OFFSET..MBR_PARTITION_OFFSET + MBR_PARTITION_BYTES];
        entry[4] = LINUX_RAID_MBR_TYPE; entry[8..12].copy_from_slice(&1u32.to_le_bytes()); entry[12..16].copy_from_slice(&8u32.to_le_bytes());
        assert!(parse(&mbr)[0].is_raid);

        let mut disk = vec![0; SECTOR_BYTES * 34];
        disk[MBR_SIGNATURE_OFFSET..SECTOR_BYTES].copy_from_slice(&[0x55, 0xaa]); disk[MBR_PARTITION_OFFSET + 4] = GPT_PROTECTIVE_TYPE;
        let entry = &mut disk[SECTOR_BYTES * 2..SECTOR_BYTES * 2 + GPT_ENTRY_MIN_BYTES];
        entry[..16].copy_from_slice(&LINUX_RAID_GPT_TYPE); entry[32..40].copy_from_slice(&2u64.to_le_bytes()); entry[40..48].copy_from_slice(&9u64.to_le_bytes());
        let entries_crc = crc::crc32(&disk[SECTOR_BYTES * 2..SECTOR_BYTES * 2 + GPT_ENTRY_MIN_BYTES]);
        let header = &mut disk[SECTOR_BYTES..SECTOR_BYTES * 2];
        header[..8].copy_from_slice(GPT_SIGNATURE); header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); header[12..16].copy_from_slice(&(GPT_HEADER_MIN_BYTES as u32).to_le_bytes());
        header[24..32].copy_from_slice(&1u64.to_le_bytes()); header[32..40].copy_from_slice(&33u64.to_le_bytes()); header[40..48].copy_from_slice(&34u64.to_le_bytes()); header[48..56].copy_from_slice(&32u64.to_le_bytes());
        header[72..80].copy_from_slice(&2u64.to_le_bytes()); header[80..84].copy_from_slice(&1u32.to_le_bytes()); header[84..88].copy_from_slice(&(GPT_ENTRY_MIN_BYTES as u32).to_le_bytes()); header[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let header_crc = crc::crc32(&header[..GPT_HEADER_MIN_BYTES]); header[16..20].copy_from_slice(&header_crc.to_le_bytes());
        assert!(parse(&disk)[0].is_raid);
    }

    #[test]
    fn gpt_requires_both_checksums_and_retains_guid_and_label() {
        let mut disk = vec![0; SECTOR_BYTES * 34];
        disk[MBR_SIGNATURE_OFFSET..SECTOR_BYTES].copy_from_slice(&[0x55, 0xaa]);
        disk[MBR_PARTITION_OFFSET + 4] = GPT_PROTECTIVE_TYPE;
        let entry = &mut disk[SECTOR_BYTES * 2..SECTOR_BYTES * 2 + GPT_ENTRY_MIN_BYTES];
        entry[0] = 1;
        entry[16..32].copy_from_slice(&[0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        entry[32..40].copy_from_slice(&2048u64.to_le_bytes());
        entry[40..48].copy_from_slice(&4095u64.to_le_bytes());
        for (slot, unit) in "root".encode_utf16().enumerate() {
            let off = 56 + slot * 2;
            entry[off..off + 2].copy_from_slice(&unit.to_le_bytes());
        }
        let entries_crc = crc::crc32(&disk[SECTOR_BYTES * 2..SECTOR_BYTES * 2 + GPT_ENTRY_MIN_BYTES]);
        let header = &mut disk[SECTOR_BYTES..SECTOR_BYTES * 2];
        header[..8].copy_from_slice(GPT_SIGNATURE);
        header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        header[12..16].copy_from_slice(&(GPT_HEADER_MIN_BYTES as u32).to_le_bytes());
        header[24..32].copy_from_slice(&1u64.to_le_bytes());
        header[32..40].copy_from_slice(&33u64.to_le_bytes());
        header[40..48].copy_from_slice(&34u64.to_le_bytes());
        header[48..56].copy_from_slice(&32u64.to_le_bytes());
        header[72..80].copy_from_slice(&2u64.to_le_bytes());
        header[80..84].copy_from_slice(&1u32.to_le_bytes());
        header[84..88].copy_from_slice(&(GPT_ENTRY_MIN_BYTES as u32).to_le_bytes());
        header[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let header_crc = crc::crc32(&header[..GPT_HEADER_MIN_BYTES]);
        header[16..20].copy_from_slice(&header_crc.to_le_bytes());
        assert_eq!(parse(&disk), vec![PartitionInfo {
            number: 1, start_lba: 2048, sectors: 2048, is_raid: false,
            uuid: Some("00112233-4455-6677-8899-aabbccddeeff".into()), label: Some("root".into()),
        }]);
        disk[SECTOR_BYTES * 2 + 32] ^= 1;
        assert!(parse(&disk).is_empty());
    }

    #[test]
    fn read_uses_the_devices_logical_block_size_for_gpt() {
        const BLOCK_BYTES: usize = 4096;
        let dev = MemDisk::<TaskList>::new(BLOCK_BYTES as u32, 8);
        let mut disk = vec![0; BLOCK_BYTES * 3];
        disk[MBR_SIGNATURE_OFFSET..SECTOR_BYTES].copy_from_slice(&[0x55, 0xaa]);
        disk[MBR_PARTITION_OFFSET + 4] = GPT_PROTECTIVE_TYPE;
        let entry = &mut disk[BLOCK_BYTES * 2..BLOCK_BYTES * 2 + GPT_ENTRY_MIN_BYTES];
        entry[0] = 1;
        entry[16..32].copy_from_slice(&[0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        entry[32..40].copy_from_slice(&3u64.to_le_bytes());
        entry[40..48].copy_from_slice(&6u64.to_le_bytes());
        let entries_crc = crc::crc32(&disk[BLOCK_BYTES * 2..BLOCK_BYTES * 2 + GPT_ENTRY_MIN_BYTES]);
        let header = &mut disk[BLOCK_BYTES..BLOCK_BYTES * 2];
        header[..8].copy_from_slice(GPT_SIGNATURE);
        header[12..16].copy_from_slice(&(GPT_HEADER_MIN_BYTES as u32).to_le_bytes());
        header[72..80].copy_from_slice(&2u64.to_le_bytes());
        header[80..84].copy_from_slice(&1u32.to_le_bytes());
        header[84..88].copy_from_slice(&(GPT_ENTRY_MIN_BYTES as u32).to_le_bytes());
        header[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let header_crc = crc::crc32(&header[..GPT_HEADER_MIN_BYTES]);
        header[16..20].copy_from_slice(&header_crc.to_le_bytes());
        let mut write = BlockRequest::new_write(0, 3, disk);
        dev.submit_sync(&mut write).expect("4Kn fixture write");
        assert_eq!(read(dev.as_ref()), vec![PartitionInfo {
            number: 1, start_lba: 3, sectors: 4, is_raid: false,
            uuid: Some("00112233-4455-6677-8899-aabbccddeeff".into()), label: None,
        }]);
    }
}
