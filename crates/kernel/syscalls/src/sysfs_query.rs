// sysfs(2) slot 139 — the SysV filesystem-type query, unrelated to sysfs the
// filesystem. Linux `fs/filesystems.c`:
//
//   SYSCALL_DEFINE3(sysfs, int option, unsigned long arg1, unsigned long arg2)
//     1 -> fs_index((const char __user *)arg1)          name  -> index
//     2 -> fs_name(arg1, (char __user *)arg2)           index -> name
//     3 -> fs_maxindex()                                count of registered
//     default -> -EINVAL
//
// All three walk the SAME `file_systems` list `/proc/filesystems` renders
// (`vfs::fs::registered_filesystems` here), in registration order.
//
// Not kernel-cfg'd on purpose: the slot file is `#![cfg(target_os =
// "oxide-kernel")]` and so cannot be exercised hosted, which would leave the
// index arithmetic and the EINVAL boundaries untested (CLAUDE.md phantom-test
// rule, docs/53 hollow shell).

use syscall::errno::Errno;

/// `option == 1`: translate a filesystem-type name to its index.
pub const SYSFS_GET_FS_INDEX: i32 = 1;
/// `option == 2`: translate an index to its filesystem-type name.
pub const SYSFS_GET_FS_NAME: i32 = 2;
/// `option == 3`: report the number of registered filesystem types.
pub const SYSFS_GET_FS_MAXINDEX: i32 = 3;

/// `fs_index` — position of `name` in the registration-ordered type list.
/// Linux compares with `strcmp`, so the match is EXACT: no `.subtype` stripping
/// (that is `get_fs_type`'s mount-path behaviour, not this query's) and no
/// prefix match. Absent ⇒ EINVAL.
/// # C: O(N_fs)
pub fn fs_index(names: &[&str], name: &str) -> Result<i64, Errno> {
    match names.iter().position(|n| *n == name) {
        Some(i) => Ok(i as i64),
        None    => Err(Errno::Einval),
    }
}

/// `fs_name` — the type name at `index`. Linux's `if (index--) continue;` walk
/// simply runs off the end for an out-of-range index and returns EINVAL; the
/// argument is an `unsigned int`, so a negative-looking `arg1` is a huge index,
/// not a wrap to the last entry.
/// # C: O(N_fs)
pub fn fs_name_at<'a>(names: &[&'a str], index: u32) -> Result<&'a str, Errno> {
    names.get(index as usize).copied().ok_or(Errno::Einval)
}

/// `fs_maxindex` — count of registered types. Despite the name this is the
/// COUNT, not the last valid index, so `fs_name_at(names, fs_maxindex(names))`
/// is EINVAL: a caller looping `for (i = 0; i < sysfs(3); i++)` is correct and
/// one looping `i <= sysfs(3)` gets the EINVAL Linux gives it.
/// # C: O(1)
pub fn fs_maxindex(names: &[&str]) -> i64 { names.len() as i64 }

/// Reject an unknown `option` the way Linux's `switch` default does. Kept
/// beside the three handlers so the option set has one owner.
/// # C: O(1)
pub fn option_known(option: i32) -> bool {
    matches!(option, SYSFS_GET_FS_INDEX | SYSFS_GET_FS_NAME | SYSFS_GET_FS_MAXINDEX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FSTYPES: [&str; 4] = ["tmpfs", "ramfs", "ext4", "proc"];

    /// Name → index is exact and registration-ordered. # C: O(1)
    #[test]
    fn index_is_registration_order() {
        assert_eq!(fs_index(&FSTYPES, "tmpfs"), Ok(0));
        assert_eq!(fs_index(&FSTYPES, "ext4"),  Ok(2));
        assert_eq!(fs_index(&FSTYPES, "proc"),  Ok(3));
    }

    /// An unregistered name is EINVAL — including one that merely PREFIXES a
    /// registered type or carries a `.subtype`, because Linux uses `strcmp`.
    /// A `starts_with` here would report a bogus index for `ext`. # C: O(1)
    #[test]
    fn unknown_or_partial_name_is_einval() {
        assert_eq!(fs_index(&FSTYPES, "xfs"),        Err(Errno::Einval));
        assert_eq!(fs_index(&FSTYPES, "ext"),        Err(Errno::Einval));
        assert_eq!(fs_index(&FSTYPES, "ext44"),      Err(Errno::Einval));
        assert_eq!(fs_index(&FSTYPES, "fuse.sshfs"), Err(Errno::Einval));
        assert_eq!(fs_index(&FSTYPES, ""),           Err(Errno::Einval));
    }

    /// Index → name, and one past the end is EINVAL rather than a wrap or a
    /// clamp to the last entry. # C: O(1)
    #[test]
    fn name_at_index_and_out_of_range() {
        assert_eq!(fs_name_at(&FSTYPES, 0), Ok("tmpfs"));
        assert_eq!(fs_name_at(&FSTYPES, 3), Ok("proc"));
        assert_eq!(fs_name_at(&FSTYPES, 4), Err(Errno::Einval));
        assert_eq!(fs_name_at(&FSTYPES, u32::MAX), Err(Errno::Einval));
    }

    /// `fs_maxindex` is the COUNT, so it is itself an invalid index — the
    /// off-by-one every `sysfs(2)` caller has to get right. # C: O(1)
    #[test]
    fn maxindex_is_count_not_last_index() {
        assert_eq!(fs_maxindex(&FSTYPES), 4);
        assert_eq!(fs_name_at(&FSTYPES, fs_maxindex(&FSTYPES) as u32), Err(Errno::Einval));
        assert_eq!(fs_name_at(&FSTYPES, fs_maxindex(&FSTYPES) as u32 - 1), Ok("proc"));
    }

    /// Index/name round-trip over the whole list. # C: O(N)
    #[test]
    fn index_and_name_round_trip() {
        for i in 0..FSTYPES.len() as u32 {
            let n = fs_name_at(&FSTYPES, i).expect("in range");
            assert_eq!(fs_index(&FSTYPES, n), Ok(i as i64), "round-trip {n}");
        }
    }

    /// Only 1/2/3 are options; 0 and 4 are EINVAL, and so is a negative one.
    /// # C: O(1)
    #[test]
    fn only_three_options_exist() {
        assert!(option_known(SYSFS_GET_FS_INDEX));
        assert!(option_known(SYSFS_GET_FS_NAME));
        assert!(option_known(SYSFS_GET_FS_MAXINDEX));
        for o in [i32::MIN, -1, 0, 4, 5, i32::MAX] { assert!(!option_known(o), "option {o}"); }
    }

    /// An empty registry answers 0 for the count and EINVAL for every lookup,
    /// rather than panicking on the index arithmetic. # C: O(1)
    #[test]
    fn empty_registry_is_not_a_panic() {
        let empty: [&str; 0] = [];
        assert_eq!(fs_maxindex(&empty), 0);
        assert_eq!(fs_name_at(&empty, 0), Err(Errno::Einval));
        assert_eq!(fs_index(&empty, "tmpfs"), Err(Errno::Einval));
    }
}
