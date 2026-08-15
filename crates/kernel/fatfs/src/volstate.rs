//! The two things a writable volume owes every other system that reads it:
//! a dirty flag, and every copy of the table kept identical.
//!
//! Neither matters while a volume is only read. Both matter the moment it is
//! written, and both are invisible until the medium is carried somewhere else
//! — which is exactly what removable media is for.

use crate::geometry::{FatWidth, Geometry};

/// Bit meaning "this volume was mounted and not cleanly unmounted".
///
/// Set while a volume is writable and cleared on unmount. Another system
/// seeing it set knows the volume may be inconsistent and runs a check; a
/// writer that never sets it hands over a possibly-broken volume that looks
/// clean, which is worse than one that admits it.
pub const FAT_STATE_DIRTY: u8 = 0x01;

/// Byte offset of the state flag in the boot sector.
///
/// It sits at a different place per width because the two layouts overlay the
/// same region: FAT32 puts a further eighteen bytes of geometry where FAT16
/// keeps its drive number. Writing the FAT16 offset on a FAT32 volume lands in
/// the middle of the root-cluster and info-sector fields — corrupting the
/// volume in the act of marking it dirty.
/// # C: O(1)
pub fn state_offset(width: FatWidth) -> usize {
    match width { FatWidth::Fat32 => 0x41, _ => 0x25 }
}

/// Is this volume marked as not cleanly unmounted? # C: O(1)
pub fn is_dirty(boot: &[u8], width: FatWidth) -> Option<bool> {
    boot.get(state_offset(width)).map(|b| b & FAT_STATE_DIRTY != 0)
}

/// Set or clear the flag in a boot sector image. Only that bit moves: the rest
/// of the byte is undocumented and belongs to whoever wrote it.
/// # C: O(1)
pub fn set_dirty(boot: &mut [u8], width: FatWidth, dirty: bool) -> Option<()> {
    let at = state_offset(width);
    let byte = boot.get_mut(at)?;
    if dirty { *byte |= FAT_STATE_DIRTY; } else { *byte &= !FAT_STATE_DIRTY; }
    Some(())
}

/// First sector of each copy of the allocation table.
///
/// A volume almost always carries two. A writer that updates only the first
/// leaves the second stale, and every checker on every other system reports
/// the mismatch — correctly, because the volume now has two different answers
/// about which clusters are free.
/// # C: O(copies)
pub fn fat_copy_starts(geo: &Geometry, copies: u32) -> alloc::vec::Vec<u32> {
    (0..copies).map(|i| geo.fat_start + i * geo.fat_length).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bpb::Bpb;
    use crate::geometry::resolve;
    use alloc::vec;

    fn geo(width: FatWidth) -> Geometry {
        let b = match width {
            FatWidth::Fat32 => Bpb { sector_size: 512, sec_per_clus: 1, reserved: 32, fats: 2,
                dir_entries: 0, media: 0xf8, fat_length16: 0, fat_length32: 256,
                total_sect16: 0, total_sect32: 20_000, root_cluster: 2, fsinfo_sector: 1 },
            _ => Bpb { sector_size: 512, sec_per_clus: 1, reserved: 1, fats: 2,
                dir_entries: 16, media: 0xf8, fat_length16: 64, fat_length32: 0,
                total_sect16: 0, total_sect32: 20_000, root_cluster: 0, fsinfo_sector: 0 },
        };
        resolve(&b).expect("valid")
    }

    /// The flag lives at a different offset per width because the two layouts
    /// overlay the same region. Writing the FAT16 offset on a FAT32 volume
    /// lands inside its root-cluster and info-sector fields — corrupting the
    /// volume in the act of marking it dirty.
    #[test]
    fn the_flag_sits_where_each_layout_keeps_it() {
        assert_eq!(state_offset(FatWidth::Fat12), 0x25);
        assert_eq!(state_offset(FatWidth::Fat16), 0x25);
        assert_eq!(state_offset(FatWidth::Fat32), 0x41);
        // A FAT32 volume's root cluster is at 0x2c and its info sector at
        // 0x30, both inside the range the FAT16 offset would disturb.
        assert!(state_offset(FatWidth::Fat16) < 0x2c);
        assert!(state_offset(FatWidth::Fat32) > 0x30);
    }

    /// Setting the flag on a FAT32 volume must not touch its geometry.
    #[test]
    fn marking_a_fat32_volume_dirty_leaves_its_geometry_alone() {
        let mut boot = vec![0u8; 512];
        boot[0x2c..0x30].copy_from_slice(&2u32.to_le_bytes());
        boot[0x30..0x32].copy_from_slice(&1u16.to_le_bytes());
        set_dirty(&mut boot, FatWidth::Fat32, true).expect("in range");
        assert_eq!(&boot[0x2c..0x30], &2u32.to_le_bytes(), "root cluster untouched");
        assert_eq!(&boot[0x30..0x32], &1u16.to_le_bytes(), "info sector untouched");
        assert_eq!(is_dirty(&boot, FatWidth::Fat32), Some(true));
    }

    /// Only the one bit moves. The rest of the byte is undocumented and
    /// belongs to whoever wrote it.
    #[test]
    fn only_the_dirty_bit_moves() {
        let mut boot = vec![0u8; 512];
        boot[state_offset(FatWidth::Fat16)] = 0xF0;
        set_dirty(&mut boot, FatWidth::Fat16, true).expect("in range");
        assert_eq!(boot[state_offset(FatWidth::Fat16)], 0xF1);
        set_dirty(&mut boot, FatWidth::Fat16, false).expect("in range");
        assert_eq!(boot[state_offset(FatWidth::Fat16)], 0xF0, "the other bits survived");
    }

    #[test]
    fn the_flag_round_trips() {
        for width in [FatWidth::Fat12, FatWidth::Fat16, FatWidth::Fat32] {
            let mut boot = vec![0u8; 512];
            assert_eq!(is_dirty(&boot, width), Some(false));
            set_dirty(&mut boot, width, true).expect("in range");
            assert_eq!(is_dirty(&boot, width), Some(true), "{width:?}");
            set_dirty(&mut boot, width, false).expect("in range");
            assert_eq!(is_dirty(&boot, width), Some(false), "{width:?}");
        }
    }

    /// A boot sector too short to hold the flag is refused rather than
    /// silently reporting clean.
    #[test]
    fn a_short_boot_sector_reports_nothing_rather_than_clean() {
        let short = vec![0u8; 0x30];
        assert_eq!(is_dirty(&short, FatWidth::Fat32), None);
        assert_eq!(set_dirty(&mut vec![0u8; 0x30], FatWidth::Fat32, true), None);
        assert_eq!(is_dirty(&short, FatWidth::Fat16), Some(false), "this one does fit");
    }

    /// Every copy of the table gets its own start sector. Updating only the
    /// first leaves the volume with two different answers about which
    /// clusters are free, and every checker elsewhere reports it.
    #[test]
    fn each_table_copy_has_its_own_start() {
        let g = geo(FatWidth::Fat16);
        let starts = fat_copy_starts(&g, 2);
        assert_eq!(starts, vec![g.fat_start, g.fat_start + g.fat_length]);
        assert_ne!(starts[0], starts[1], "the copies are distinct regions");
        // The second copy ends exactly where the root directory begins.
        assert_eq!(starts[1] + g.fat_length, g.dir_start);
    }

    /// A volume with one table has one copy, and one with three has three —
    /// the count comes from the volume, not from an assumption.
    #[test]
    fn the_copy_count_comes_from_the_volume() {
        let g = geo(FatWidth::Fat32);
        assert_eq!(fat_copy_starts(&g, 1), vec![g.fat_start]);
        assert_eq!(fat_copy_starts(&g, 3).len(), 3);
        assert_eq!(fat_copy_starts(&g, 0), vec![], "a volume declaring none has none");
    }
}
