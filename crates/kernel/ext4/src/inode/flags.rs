// On-disk `ext4_inode.i_flags` bits — the `chattr` flag word.
//
// ONE owner. These were declared independently in four modules (the project-id
// helper, the quota-file cleanup, the inode metadata path and the attribute
// report), which is exactly the shape that lets two of them disagree about a
// bit position and nothing notice.

/// `EXT4_SECRM_FL` — secure deletion.
pub const EXT4_SECRM_FL:     u32 = 0x0000_0001;
/// `EXT4_UNRM_FL` — undelete.
pub const EXT4_UNRM_FL:      u32 = 0x0000_0002;
/// `EXT4_COMPR_FL` — file is compressed.
pub const EXT4_COMPR_FL:     u32 = 0x0000_0004;
/// `EXT4_SYNC_FL` — synchronous updates.
pub const EXT4_SYNC_FL:      u32 = 0x0000_0008;
/// `EXT4_IMMUTABLE_FL` — immutable file.
pub const EXT4_IMMUTABLE_FL: u32 = 0x0000_0010;
/// `EXT4_APPEND_FL` — append-only.
pub const EXT4_APPEND_FL:    u32 = 0x0000_0020;
/// `EXT4_NODUMP_FL` — do not dump.
pub const EXT4_NODUMP_FL:    u32 = 0x0000_0040;
/// `EXT4_NOATIME_FL` — do not update atime.
pub const EXT4_NOATIME_FL:   u32 = 0x0000_0080;
/// `EXT4_DIRSYNC_FL` — synchronous directory modifications.
pub const EXT4_DIRSYNC_FL:   u32 = 0x0001_0000;
/// `EXT4_TOPDIR_FL` — top of directory hierarchy.
pub const EXT4_TOPDIR_FL:    u32 = 0x0002_0000;
/// `EXT4_PROJINHERIT_FL` — children inherit the project id.
pub const EXT4_PROJINHERIT_FL: u32 = 0x2000_0000;
/// `EXT4_ENCRYPT_FL` — file contents are encrypted.
pub const EXT4_ENCRYPT_FL:   u32 = 0x0000_0800;
/// `EXT4_VERITY_FL` — file has fs-verity enabled.
pub const EXT4_VERITY_FL:    u32 = 0x0010_0000;

/// `EXT4_FL_USER_VISIBLE` — the bits `lsattr` and the attribute report may see.
pub const EXT4_FL_USER_VISIBLE: u32 = EXT4_SECRM_FL | EXT4_UNRM_FL | EXT4_COMPR_FL
    | EXT4_SYNC_FL | EXT4_IMMUTABLE_FL | EXT4_APPEND_FL | EXT4_NODUMP_FL | EXT4_NOATIME_FL
    | EXT4_ENCRYPT_FL | EXT4_VERITY_FL | EXT4_DIRSYNC_FL | EXT4_TOPDIR_FL
    | EXT4_PROJINHERIT_FL;

/// Translate the user-visible on-disk flag word into the statx attribute bits
/// and the mask of attributes this backend is able to report.
///
/// The mask half is not optional: an attribute bit that is clear means "not
/// set" only when the corresponding mask bit is set. Reporting attributes with
/// an empty mask — which is what happened while this translation did not exist
/// — tells the caller nothing was learned, so a reader could not distinguish
/// "not compressed" from "this filesystem has no idea". # C: O(1)
pub fn statx_attributes(i_flags: u32) -> (u64, u64) {
    use vfs::getattr::{STATX_ATTR_APPEND, STATX_ATTR_COMPRESSED, STATX_ATTR_ENCRYPTED,
                       STATX_ATTR_IMMUTABLE, STATX_ATTR_NODUMP, STATX_ATTR_VERITY};
    let f = i_flags & EXT4_FL_USER_VISIBLE;
    let mut a = 0u64;
    if f & EXT4_APPEND_FL    != 0 { a |= STATX_ATTR_APPEND; }
    if f & EXT4_COMPR_FL     != 0 { a |= STATX_ATTR_COMPRESSED; }
    if f & EXT4_ENCRYPT_FL   != 0 { a |= STATX_ATTR_ENCRYPTED; }
    if f & EXT4_IMMUTABLE_FL != 0 { a |= STATX_ATTR_IMMUTABLE; }
    if f & EXT4_NODUMP_FL    != 0 { a |= STATX_ATTR_NODUMP; }
    if f & EXT4_VERITY_FL    != 0 { a |= STATX_ATTR_VERITY; }
    let mask = STATX_ATTR_APPEND | STATX_ATTR_COMPRESSED | STATX_ATTR_ENCRYPTED
        | STATX_ATTR_IMMUTABLE | STATX_ATTR_NODUMP | STATX_ATTR_VERITY;
    (a, mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::getattr::{STATX_ATTR_APPEND, STATX_ATTR_COMPRESSED, STATX_ATTR_ENCRYPTED,
                       STATX_ATTR_IMMUTABLE, STATX_ATTR_NODUMP, STATX_ATTR_VERITY};

    /// Each on-disk bit maps to its own attribute bit, and to no other. Four of
    /// these six were previously unreachable: only the two the generic VFS
    /// flag word happens to mirror were ever reported. # C: O(1)
    #[test]
    fn each_visible_flag_maps_to_its_own_attribute() {
        let cases: [(u32, u64); 6] = [
            (EXT4_APPEND_FL,    STATX_ATTR_APPEND),
            (EXT4_COMPR_FL,     STATX_ATTR_COMPRESSED),
            (EXT4_ENCRYPT_FL,   STATX_ATTR_ENCRYPTED),
            (EXT4_IMMUTABLE_FL, STATX_ATTR_IMMUTABLE),
            (EXT4_NODUMP_FL,    STATX_ATTR_NODUMP),
            (EXT4_VERITY_FL,    STATX_ATTR_VERITY),
        ];
        for (fl, attr) in cases {
            let (a, mask) = statx_attributes(fl);
            assert_eq!(a, attr, "flag {fl:#x}");
            assert_ne!(mask & attr, 0, "flag {fl:#x} must be inside the reported mask");
        }
        // All six together, and nothing outside the six.
        let all = cases.iter().fold(0u32, |acc, (f, _)| acc | f);
        let (a, mask) = statx_attributes(all);
        assert_eq!(a, cases.iter().fold(0u64, |acc, (_, at)| acc | at));
        assert_eq!(a & !mask, 0, "no attribute may be reported outside the mask");
    }

    /// A bit outside `EXT4_FL_USER_VISIBLE` reports nothing, and the MASK is
    /// still reported — "no attributes set" and "cannot tell" are different
    /// answers and the mask is what separates them. # C: O(1)
    #[test]
    fn invisible_flags_report_nothing_but_the_mask_stands() {
        let (a, mask) = statx_attributes(0);
        assert_eq!(a, 0);
        assert_ne!(mask, 0, "the mask must be reported even when no bit is set");
        // A bit this filesystem does not expose to lsattr is filtered out.
        let hidden = !EXT4_FL_USER_VISIBLE;
        assert_eq!(statx_attributes(hidden).0, 0);
    }

    /// The bit positions are the on-disk ABI, not ours to choose; a slip here
    /// silently reports a different attribute than the file carries. # C: O(1)
    #[test]
    fn flag_bit_positions_are_the_on_disk_abi() {
        assert_eq!(EXT4_SECRM_FL, 0x1);
        assert_eq!(EXT4_COMPR_FL, 0x4);
        assert_eq!(EXT4_SYNC_FL, 0x8);
        assert_eq!(EXT4_IMMUTABLE_FL, 0x10);
        assert_eq!(EXT4_APPEND_FL, 0x20);
        assert_eq!(EXT4_NODUMP_FL, 0x40);
        assert_eq!(EXT4_NOATIME_FL, 0x80);
        assert_eq!(EXT4_ENCRYPT_FL, 0x800);
        assert_eq!(EXT4_DIRSYNC_FL, 0x1_0000);
        assert_eq!(EXT4_VERITY_FL, 0x10_0000);
        assert_eq!(EXT4_PROJINHERIT_FL, 0x2000_0000);
    }
}
