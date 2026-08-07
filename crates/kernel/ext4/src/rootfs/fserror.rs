// ext4 FILESYSTEM-ERROR reporting: the point where an error coming back from
// the on-disk layer is classified, announced to whoever is watching the
// filesystem, and turned into the errno the caller sees.
//
// Not every failure is a filesystem error. Running out of space, asking for a
// feature this build does not implement, or naming something that is not there
// are ordinary answers about a healthy filesystem. A filesystem error is the
// filesystem saying its OWN state is wrong — a malformed extent tree, a
// metadata checksum that does not verify, an inode whose extent header is not
// an extent header — or that its device would not answer at all. Those are what
// a monitoring daemon exists to hear about, and reporting the ordinary answers
// alongside them would bury the ones that matter.
//
// Deliberately free of any target gate so the classification is hosted-testable.

use crate::{InodeError, MountError};

use super::state::RootfsState;

/// Is `e` the filesystem reporting that its own state is wrong, rather than
/// answering a question about a healthy one? # C: O(1)
pub(crate) fn is_inconsistency(e: &MountError) -> bool {
    match e {
        // On-disk structure that cannot be what it claims to be.
        MountError::CorruptExtentTree | MountError::BadChecksum => true,
        MountError::Inode(InodeError::BadExtentMagic)
        | MountError::Inode(InodeError::TooManyExtents) => true,
        MountError::Superblock(_) | MountError::Gdt(_) | MountError::Dir(_) => true,
        // Freeing a block whose bit was already clear, or naming one outside
        // every group, means the allocator's on-disk view disagrees with
        // itself.
        MountError::DoubleFree | MountError::BadBlock => true,
        // The device did not answer. The structures may be perfectly fine, but
        // the filesystem is no longer able to read them, which is the other
        // half of what a watcher is listening for.
        MountError::BlockIo => true,
        _ => false,
    }
}

/// Announce a filesystem error and map it to the errno the caller sees.
///
/// One call site does both so the two can never disagree: an error cannot be
/// returned to userspace as a corruption errno while no watcher was told, and a
/// watcher cannot be told about something the caller was never refused for.
/// # C: O(1) + subscribers
pub(crate) fn report(st: &RootfsState, e: MountError) -> vfs::VfsError {
    let bad = is_inconsistency(&e);
    if bad {
        klog::write_raw(b"[EXT4-ERROR] kind=");
        klog::write_raw(error_kind(&e));
        klog::write_raw(b"\n");
    }
    let mapped = super::inode::regular::vfs_error_from_mount(e);
    if bad { vfs::fire_fs_error(watcher_fsid(st), None, mapped as i32); }
    mapped
}

/// Stable error-only diagnostic kind; no pathname or transient allocation.
/// # C: O(1)
fn error_kind(e: &MountError) -> &'static [u8] {
    match e {
        MountError::BlockIo => b"block-io",
        MountError::Superblock(_) => b"superblock",
        MountError::Gdt(_) => b"gdt",
        MountError::Inode(_) => b"inode",
        MountError::Dir(_) => b"directory",
        MountError::NotFound => b"not-found",
        MountError::NotDir => b"not-directory",
        MountError::NotExtents => b"not-extents",
        MountError::DepthUnsupported => b"extent-depth",
        MountError::NoSpace => b"no-space",
        MountError::BadBlock => b"bad-block",
        MountError::DoubleFree => b"double-free",
        MountError::ExtentTreeFull => b"extent-tree-full",
        MountError::DirFull => b"directory-full",
        MountError::CorruptExtentTree => b"corrupt-extent-tree",
        MountError::BadChecksum => b"bad-checksum",
        MountError::UnsupportedFeature => b"unsupported-feature",
        MountError::Quota(_) => b"quota",
    }
}

/// The filesystem identity a report carries: the `st_dev` every inode on this
/// mount reports. It MUST be that number and not any other per-mount identity,
/// because a watcher attaches its mark by `st_dev` — a report keyed on anything
/// else reaches nobody. `0` for a mount whose superblock is already gone, which
/// no mark can be attached to either.
/// # C: O(1)
fn watcher_fsid(st: &RootfsState) -> u64 {
    st.sb.lock().upgrade().map(|sb| sb.s_dev).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The structural failures a monitoring daemon exists to hear about.
    /// # C: O(1)
    #[test]
    fn malformed_on_disk_state_is_a_filesystem_error() {
        assert!(is_inconsistency(&MountError::CorruptExtentTree));
        assert!(is_inconsistency(&MountError::BadChecksum));
        assert!(is_inconsistency(&MountError::Inode(InodeError::BadExtentMagic)));
        assert!(is_inconsistency(&MountError::Inode(InodeError::TooManyExtents)));
        assert!(is_inconsistency(&MountError::DoubleFree));
        assert!(is_inconsistency(&MountError::BadBlock));
        assert!(is_inconsistency(&MountError::BlockIo));
        assert_eq!(error_kind(&MountError::BlockIo), b"block-io");
        assert_eq!(error_kind(&MountError::BadChecksum), b"bad-checksum");
    }

    /// Ordinary answers about a HEALTHY filesystem are not errors about the
    /// filesystem, and reporting them would bury the ones that are.
    /// # C: O(1)
    #[test]
    fn ordinary_answers_are_not_filesystem_errors() {
        assert!(!is_inconsistency(&MountError::NoSpace));
        assert!(!is_inconsistency(&MountError::DirFull));
        assert!(!is_inconsistency(&MountError::NotFound));
        assert!(!is_inconsistency(&MountError::NotDir));
        assert!(!is_inconsistency(&MountError::UnsupportedFeature));
        assert!(!is_inconsistency(&MountError::DepthUnsupported));
        assert!(!is_inconsistency(&MountError::ExtentTreeFull));
        assert!(!is_inconsistency(&MountError::NotExtents));
        assert!(!is_inconsistency(&MountError::Inode(InodeError::BadLen)));
    }

    /// A corrupt extent tree surfaces as an I/O error, which is the number the
    /// record carries. Classification and mapping are separate questions: a
    /// reported error still has to be the errno the caller was refused with.
    /// # C: O(1)
    #[test]
    fn the_reported_number_is_the_errno_the_caller_sees() {
        let mapped = super::super::inode::regular::vfs_error_from_mount(MountError::CorruptExtentTree);
        assert_eq!(mapped, vfs::VfsError::Eio);
        assert!(mapped as i32 > 0, "the record carries a POSITIVE errno");
    }
}
