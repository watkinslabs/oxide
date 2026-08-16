//! What may be done to a verity inode.
//!
//! A verity file is immutable by construction: its hashes describe exactly
//! the bytes it holds, so any change to those bytes invalidates every hash
//! above them. The refusal therefore happens at the moment a writable handle
//! is asked for, not at the write — a caller that gets a writable handle and
//! is refused later has already been told the file is writable.
//!
//! Two paths reach the same bytes without a handle and each is refused in its
//! own place: shortening the file by name, and turning verity on twice.

use syscall::errno::Errno;

use crate::flags::F2FS_VERITY_FL;

use super::VerityError;

/// Whether the stored attribute word marks this inode as verity-protected.
/// # C: O(1)
pub fn is_verity(flags: u32) -> bool { flags & F2FS_VERITY_FL != 0 }

/// Whether a handle may be opened for writing.
///
/// The refusal is a permission failure rather than a read-only-medium one:
/// the medium is writable and this file is not.
/// # C: O(1)
pub fn open_write(flags: u32) -> Result<(), VerityError> {
    if is_verity(flags) { return Err(VerityError::ReadOnlyFile); }
    Ok(())
}

/// Whether the file may be resized. # C: O(1)
pub fn truncate(flags: u32) -> Result<(), VerityError> {
    if is_verity(flags) { return Err(VerityError::ReadOnlyFile); }
    Ok(())
}

/// Whether verity may be turned on. # C: O(1)
pub fn enable(flags: u32) -> Result<(), VerityError> {
    if is_verity(flags) { return Err(VerityError::AlreadyEnabled); }
    Ok(())
}

/// What a caller reports for a refusal. # C: O(1)
pub fn errno(e: VerityError) -> Errno {
    match e {
        VerityError::ReadOnlyFile => Errno::Eperm,
        VerityError::AlreadyEnabled => Errno::Eexist,
        VerityError::DescriptorTooLarge => Errno::Emsgsize,
        VerityError::Corrupted => Errno::Euclean,
        VerityError::NoDescriptor => Errno::Enodata,
        _ => Errno::Einval,
    }
}
