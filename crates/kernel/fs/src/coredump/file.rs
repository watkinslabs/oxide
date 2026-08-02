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

use vfs::{FileType, OpenFlags};

/// Mode a core file is created with: readable and writable by its owner and
/// nobody else. A dump is the process's whole address space, including whatever
/// it had in memory that never reached disk.
pub const CORE_FILE_MODE: u32 = 0o600;

/// Bits that must survive creation unchanged. Owner-write is excluded because
/// the kernel is what holds the file open for writing; group and other bits are
/// not, because a filesystem that granted them (or an existing file that
/// already had them) would publish the dump.
pub const MODE_PRESERVE_MASK: u16 = 0o677;

/// Flags a dump's own open uses.
///
/// `O_CREAT|O_RDWR` because the dump both makes the file and writes it;
/// `O_NOFOLLOW` because a symlink planted at the path must not redirect it.
/// A dump whose dumpability was downgraded by a privilege change adds
/// `O_EXCL`, which is what makes it take the path only if the path is free:
/// the kernel holds privilege the crashing process did not, so it must not
/// write through a name someone else already owns.
/// # C: O(1)
pub fn core_open_flags(force_suid_safe: bool) -> OpenFlags {
    let base = OpenFlags::O_CREAT | OpenFlags::O_RDWR | OpenFlags::O_NOFOLLOW;
    if force_suid_safe { base | OpenFlags::O_EXCL } else { base }
}

/// What the opened target turned out to be. Read back AFTER the open rather
/// than assumed from the request: the backend, not the caller, decides what it
/// made, and an existing file at the path is whatever it already was.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct OpenedTarget {
    pub file_type: FileType,
    /// `i_nlink` — how many names reach this file.
    pub nlink: u32,
    /// Owner the backend recorded.
    pub uid: u32,
    /// Permission bits the backend recorded.
    pub perm: u16,
    /// The name the dump was opened through is still hashed in the cache — it
    /// has not been unlinked or renamed out from under the open.
    pub hashed: bool,
    /// The open description can be written through.
    pub writable: bool,
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
    /// The name was unlinked or renamed between the open and the check, so the
    /// dump would be written to a file no operator can find.
    Unhashed,
    /// The open cannot be written through, so the dump would be silently empty.
    NotWritable,
}

/// Whether the dump may be written to the target that was just created for it.
///
/// Order is fixed: the cheapest structural facts first, then ownership, then
/// permissions. Reporting the wrong one of two simultaneous problems tells an
/// operator to fix the wrong thing.
/// # C: O(1)
pub fn admit_opened(t: &OpenedTarget, fsuid: u32) -> Result<(), FileRefusal> {
    if t.nlink > 1 { return Err(FileRefusal::MultiplyLinked); }
    if !t.hashed { return Err(FileRefusal::Unhashed); }
    if t.file_type != FileType::Regular { return Err(FileRefusal::NotRegular); }
    if t.uid != fsuid { return Err(FileRefusal::OwnerChanged); }
    if !t.writable { return Err(FileRefusal::NotWritable); }
    if t.perm & MODE_PRESERVE_MASK != CORE_FILE_MODE as u16 { return Err(FileRefusal::ModeChanged); }
    Ok(())
}

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

    const GOOD: OpenedTarget = OpenedTarget {
        file_type: FileType::Regular, nlink: 1, uid: 1000, perm: 0o600,
        hashed: true, writable: true,
    };

    #[test]
    fn a_freshly_created_private_regular_file_is_admitted() {
        assert_eq!(admit_opened(&GOOD, 1000), Ok(()));
    }

    #[test]
    fn a_second_link_to_the_target_refuses_the_dump() {
        let t = OpenedTarget { nlink: 2, ..GOOD };
        assert_eq!(admit_opened(&t, 1000), Err(FileRefusal::MultiplyLinked));
    }

    #[test]
    fn a_target_that_is_not_a_regular_file_refuses_the_dump() {
        for ft in [FileType::Directory, FileType::Fifo, FileType::Symlink, FileType::CharDev,
                   FileType::BlockDev, FileType::Socket] {
            let t = OpenedTarget { file_type: ft, ..GOOD };
            assert_eq!(admit_opened(&t, 1000), Err(FileRefusal::NotRegular), "{ft:?}");
        }
    }

    #[test]
    fn a_target_the_backend_gave_to_someone_else_refuses_the_dump() {
        assert_eq!(admit_opened(&GOOD, 1001), Err(FileRefusal::OwnerChanged));
        assert_eq!(admit_opened(&GOOD, 0), Err(FileRefusal::OwnerChanged));
    }

    #[test]
    fn a_mode_the_backend_could_not_preserve_refuses_the_dump() {
        // A filesystem with no permission bits of its own reports everything
        // readable; that is exactly the case this rule exists for.
        for perm in [0o644u16, 0o666, 0o604, 0o640, 0o777, 0o400] {
            let t = OpenedTarget { perm, ..GOOD };
            assert_eq!(admit_opened(&t, 1000), Err(FileRefusal::ModeChanged), "{perm:o}");
        }
    }

    #[test]
    fn the_owner_execute_bit_is_outside_the_preserved_set() {
        // Owner-execute is not checked, so a backend that forces it does not
        // block the dump; every bit that could publish the dump still does.
        let t = OpenedTarget { perm: 0o700, ..GOOD };
        assert_eq!(admit_opened(&t, 1000), Ok(()));
    }

    #[test]
    fn the_structural_refusal_is_reported_before_the_ownership_one() {
        // A target that is wrong in every way names the structural problem.
        let t = OpenedTarget { file_type: FileType::Fifo, nlink: 3, uid: 0, perm: 0o777,
            hashed: false, writable: false };
        assert_eq!(admit_opened(&t, 1000), Err(FileRefusal::MultiplyLinked));
        let t = OpenedTarget { nlink: 1, ..t };
        assert_eq!(admit_opened(&t, 1000), Err(FileRefusal::Unhashed));
        let t = OpenedTarget { hashed: true, ..t };
        assert_eq!(admit_opened(&t, 1000), Err(FileRefusal::NotRegular));
        let t = OpenedTarget { file_type: FileType::Regular, ..t };
        assert_eq!(admit_opened(&t, 1000), Err(FileRefusal::OwnerChanged));
        let t = OpenedTarget { uid: 1000, ..t };
        assert_eq!(admit_opened(&t, 1000), Err(FileRefusal::NotWritable));
        let t = OpenedTarget { writable: true, ..t };
        assert_eq!(admit_opened(&t, 1000), Err(FileRefusal::ModeChanged));
    }

    /// A name unlinked out from under the open takes the dump nowhere findable.
    #[test]
    fn a_target_whose_name_is_gone_refuses_the_dump() {
        let t = OpenedTarget { hashed: false, ..GOOD };
        assert_eq!(admit_opened(&t, 1000), Err(FileRefusal::Unhashed));
    }

    /// An open that cannot be written through would leave a zero-length file
    /// reading as a dump that was taken.
    #[test]
    fn a_target_that_cannot_be_written_refuses_the_dump() {
        let t = OpenedTarget { writable: false, ..GOOD };
        assert_eq!(admit_opened(&t, 1000), Err(FileRefusal::NotWritable));
    }

    /// A dump whose dumpability was downgraded takes the path only if it is
    /// free; an ordinary one opens whatever is there and truncates it.
    #[test]
    fn a_privilege_downgraded_dump_demands_an_unused_name() {
        assert!(core_open_flags(true).contains(OpenFlags::O_EXCL));
        assert!(!core_open_flags(false).contains(OpenFlags::O_EXCL));
        for f in [core_open_flags(true), core_open_flags(false)] {
            assert!(f.contains(OpenFlags::O_CREAT));
            assert!(f.contains(OpenFlags::O_RDWR));
            assert!(f.contains(OpenFlags::O_NOFOLLOW), "a symlink must not redirect a dump");
        }
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
