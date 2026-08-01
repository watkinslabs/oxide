// The file destination's admission rules.
//
// A dump written to a filesystem lands at a path an unprivileged process chose
// the shape of, in a directory it may control, at a moment when the kernel is
// running with the dying process's credentials. Every rule here exists because
// some arrangement of those three lets a memory image be read by, or written on
// behalf of, someone who should not have it.
//
// The whole ladder is a pure function of what the freshly created target turned
// out to be, so it is decided once and tested without a filesystem.

use vfs::FileType;

/// Mode a core file is created with: readable and writable by its owner and
/// nobody else. A dump is the process's whole address space, including whatever
/// it had in memory that never reached disk.
pub const CORE_FILE_MODE: u32 = 0o600;

/// Bits that must survive creation unchanged. Owner-write is excluded because
/// the kernel is what holds the file open for writing; group and other bits are
/// not, because a filesystem that granted them (or an existing file that
/// already had them) would publish the dump.
pub const MODE_PRESERVE_MASK: u16 = 0o677;

/// What the created target turned out to be. Read back AFTER creation rather
/// than assumed from the request: the backend, not the caller, decides what it
/// made, and a filesystem that cannot represent an owner or a mode will hand
/// back something other than what was asked for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CreatedTarget {
    pub file_type: FileType,
    /// `i_nlink` — how many names reach this file.
    pub nlink: u32,
    /// Owner the backend recorded.
    pub uid: u32,
    /// Permission bits the backend recorded.
    pub perm: u16,
}

/// Why a dump is not written to the target that was created for it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileRefusal {
    /// Another name already reaches this file, so writing the dump would also
    /// write through that other name — which someone else may hold.
    MultiplyLinked,
    /// Not a regular file. A dump written into a device or a pipe goes
    /// somewhere the operator did not ask for and cannot be read back.
    NotRegular,
    /// The backend recorded a different owner than the process being dumped —
    /// the dump would end up belonging to someone who may then read it.
    OwnerChanged,
    /// The backend could not represent the requested mode, so the dump would be
    /// readable by more than its owner.
    ModeChanged,
}

/// Whether the dump may be written to the target that was just created for it.
///
/// Order is fixed: the cheapest structural facts first, then ownership, then
/// permissions. Reporting the wrong one of two simultaneous problems tells an
/// operator to fix the wrong thing.
/// # C: O(1)
pub fn admit_created(t: &CreatedTarget, fsuid: u32) -> Result<(), FileRefusal> {
    if t.nlink > 1 { return Err(FileRefusal::MultiplyLinked); }
    if t.file_type != FileType::Regular { return Err(FileRefusal::NotRegular); }
    if t.uid != fsuid { return Err(FileRefusal::OwnerChanged); }
    if t.perm & MODE_PRESERVE_MASK != CORE_FILE_MODE as u16 { return Err(FileRefusal::ModeChanged); }
    Ok(())
}

/// Whether an existing name at the dump's path may be removed to make room.
///
/// Normally yes: yesterday's dump must not block today's, and a symlink left at
/// the path must not survive to redirect the dump. But a process whose
/// dumpability was downgraded by a privilege change is dumped while the kernel
/// holds privilege the crashing process itself did not, so removing whatever
/// happens to be at the path would delete another user's file on the say-so of
/// an unprivileged caller who chose the path. Such a dump takes the path only
/// if it is free.
/// # C: O(1)
pub const fn may_unlink_existing(force_suid_safe: bool) -> bool { !force_suid_safe }

/// Split an absolute pathname into the directory to create in and the name to
/// create. `None` when the path names no final component — a path ending in a
/// separator, or the root itself, names a directory, and a dump is not a
/// directory.
/// # C: O(len)
pub fn split_parent<'a>(path: &'a str) -> Option<(&'a str, &'a str)> {
    if !path.starts_with('/') { return None; }
    let cut = path.rfind('/')?;
    let name = &path[cut + 1..];
    if name.is_empty() || name == "." || name == ".." { return None; }
    let dir = if cut == 0 { "/" } else { &path[..cut] };
    Some((dir, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: CreatedTarget = CreatedTarget {
        file_type: FileType::Regular, nlink: 1, uid: 1000, perm: 0o600,
    };

    #[test]
    fn a_freshly_created_private_regular_file_is_admitted() {
        assert_eq!(admit_created(&GOOD, 1000), Ok(()));
    }

    #[test]
    fn a_second_link_to_the_target_refuses_the_dump() {
        let t = CreatedTarget { nlink: 2, ..GOOD };
        assert_eq!(admit_created(&t, 1000), Err(FileRefusal::MultiplyLinked));
    }

    #[test]
    fn a_target_that_is_not_a_regular_file_refuses_the_dump() {
        for ft in [FileType::Directory, FileType::Fifo, FileType::Symlink, FileType::CharDev,
                   FileType::BlockDev, FileType::Socket] {
            let t = CreatedTarget { file_type: ft, ..GOOD };
            assert_eq!(admit_created(&t, 1000), Err(FileRefusal::NotRegular), "{ft:?}");
        }
    }

    #[test]
    fn a_target_the_backend_gave_to_someone_else_refuses_the_dump() {
        assert_eq!(admit_created(&GOOD, 1001), Err(FileRefusal::OwnerChanged));
        assert_eq!(admit_created(&GOOD, 0), Err(FileRefusal::OwnerChanged));
    }

    #[test]
    fn a_mode_the_backend_could_not_preserve_refuses_the_dump() {
        // A filesystem with no permission bits of its own reports everything
        // readable; that is exactly the case this rule exists for.
        for perm in [0o644u16, 0o666, 0o604, 0o640, 0o777, 0o400] {
            let t = CreatedTarget { perm, ..GOOD };
            assert_eq!(admit_created(&t, 1000), Err(FileRefusal::ModeChanged), "{perm:o}");
        }
    }

    #[test]
    fn the_owner_execute_bit_is_outside_the_preserved_set() {
        // Owner-execute is not checked, so a backend that forces it does not
        // block the dump; every bit that could publish the dump still does.
        let t = CreatedTarget { perm: 0o700, ..GOOD };
        assert_eq!(admit_created(&t, 1000), Ok(()));
    }

    #[test]
    fn the_structural_refusal_is_reported_before_the_ownership_one() {
        // A target that is wrong in every way names the structural problem.
        let t = CreatedTarget { file_type: FileType::Fifo, nlink: 3, uid: 0, perm: 0o777 };
        assert_eq!(admit_created(&t, 1000), Err(FileRefusal::MultiplyLinked));
        let t = CreatedTarget { nlink: 1, ..t };
        assert_eq!(admit_created(&t, 1000), Err(FileRefusal::NotRegular));
        let t = CreatedTarget { file_type: FileType::Regular, ..t };
        assert_eq!(admit_created(&t, 1000), Err(FileRefusal::OwnerChanged));
        let t = CreatedTarget { uid: 1000, ..t };
        assert_eq!(admit_created(&t, 1000), Err(FileRefusal::ModeChanged));
    }

    #[test]
    fn a_privilege_downgraded_dump_never_removes_what_is_already_there() {
        assert!(!may_unlink_existing(true));
        assert!(may_unlink_existing(false), "an ordinary dump replaces the previous one");
    }

    #[test]
    fn a_path_splits_into_the_directory_to_create_in_and_the_name() {
        assert_eq!(split_parent("/var/lib/systemd/coredump/core.42"),
                   Some(("/var/lib/systemd/coredump", "core.42")));
        assert_eq!(split_parent("/core.42"), Some(("/", "core.42")));
    }

    #[test]
    fn a_path_naming_no_final_component_is_not_a_dump_target() {
        assert_eq!(split_parent("/"), None);
        assert_eq!(split_parent("/var/tmp/"), None);
        assert_eq!(split_parent("/var/."), None);
        assert_eq!(split_parent("/var/.."), None);
        assert_eq!(split_parent("core.42"), None, "a relative path is never resolved here");
        assert_eq!(split_parent(""), None);
    }
}
