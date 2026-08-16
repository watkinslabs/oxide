use super::*;
use crate::uapi::{DENTRY_BYTES, FILE_OFF_CHECKSUM, TYPE_FILE};

#[test]
fn the_sixteen_bit_sum_rotates_right_before_adding() {
    // One byte from a zero seed is that byte: nothing has been rotated in yet.
    assert_eq!(sum16(&[0x01], 0), 1);
    // A second byte rotates the first into the top bit, then adds.
    assert_eq!(sum16(&[0x01, 0x00], 0), 0x8000);
}

#[test]
fn the_thirty_two_bit_sum_rotates_the_same_way() {
    assert_eq!(sum32(&[0x01], 0), 1);
    assert_eq!(sum32(&[0x01, 0x00], 0), 0x8000_0000);
}

#[test]
fn a_seed_continues_a_previous_run() {
    let whole = sum16(&[1, 2, 3, 4], 0);
    let split = sum16(&[3, 4], sum16(&[1, 2], 0));
    assert_eq!(whole, split);
}

#[test]
fn the_skipped_bytes_do_not_contribute() {
    let with = sum16_skipping(&[1, 2, 3, 4], 0, &[]);
    let without = sum16_skipping(&[1, 2, 0xFF, 4], 0, &[2]);
    assert_eq!(with, sum16(&[1, 2, 3, 4], 0));
    assert_eq!(without, sum16_skipping(&[1, 2, 3, 4], 0, &[2]));
}

/// Two entries whose second differs only at the offsets the FIRST entry skips.
fn two_entries() -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec![0u8; DENTRY_BYTES * 2];
    bytes[0] = TYPE_FILE;
    bytes[DENTRY_BYTES] = 0xC0;
    bytes
}

#[test]
fn the_set_checksum_skips_its_own_field_in_the_first_entry_only() {
    let base = two_entries();
    let mut stamped = base.clone();
    // Writing into the checksum field of the FILE entry changes nothing.
    stamped[FILE_OFF_CHECKSUM] = 0xAB;
    stamped[FILE_OFF_CHECKSUM + 1] = 0xCD;
    assert_eq!(entry_set(&base), entry_set(&stamped));

    // The same offsets in the SECOND entry are ordinary bytes and do count.
    let mut later = base.clone();
    later[DENTRY_BYTES + FILE_OFF_CHECKSUM] = 0xAB;
    assert_ne!(entry_set(&base), entry_set(&later));
}

#[test]
fn a_name_hash_depends_on_order() {
    assert_ne!(name_hash(&[0x0041, 0x0042]), name_hash(&[0x0042, 0x0041]));
}

#[test]
fn a_name_hash_reads_units_little_endian() {
    // Two bytes per unit, low byte first: the hash of one unit equals the sum
    // over the two bytes it becomes.
    assert_eq!(name_hash(&[0x1234]), sum16(&[0x34, 0x12], 0));
}

#[test]
fn the_boot_region_skips_the_three_bytes_a_mount_changes() {
    let mut sector = alloc::vec![0u8; 512];
    let base = boot_region(&sector, 0, true);
    for skip in crate::uapi::BOOT_CHECKSUM_SKIP {
        let mut changed = sector.clone();
        changed[skip] = 0xFF;
        assert_eq!(boot_region(&changed, 0, true), base, "byte {skip} must not contribute");
    }
    // Any other byte does.
    sector[105] = 0xFF;
    assert_ne!(boot_region(&sector, 0, true), base);
}

#[test]
fn only_the_first_sector_of_the_region_skips_anything() {
    let mut sector = alloc::vec![0u8; 512];
    let base = boot_region(&sector, 0, false);
    sector[crate::uapi::BOOT_CHECKSUM_SKIP[0]] = 0xFF;
    assert_ne!(boot_region(&sector, 0, false), base);
}
