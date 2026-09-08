//! Failure statuses for the NT file boundary.
//!
//! A loader walking a search path branches on the status of every candidate
//! it fails to open: a name or path that is simply absent means "keep
//! looking", and anything else means "this file exists and something is
//! wrong, stop". Collapsing the classes into one status either aborts a
//! search that should continue or continues one that should have reported.

use syscall::errno::Errno;

pub(crate) const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;
pub(crate) const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
pub(crate) const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
pub(crate) const STATUS_INVALID_DEVICE_REQUEST: u64 = 0xc000_0010;
pub(crate) const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
pub(crate) const STATUS_NO_SUCH_DEVICE: u64 = 0xc000_000e;
pub(crate) const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
pub(crate) const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
pub(crate) const STATUS_OBJECT_NAME_COLLISION: u64 = 0xc000_0035;
pub(crate) const STATUS_OBJECT_PATH_NOT_FOUND: u64 = 0xc000_003a;
pub(crate) const STATUS_SHARING_VIOLATION: u64 = 0xc000_0043;
pub(crate) const STATUS_DISK_FULL: u64 = 0xc000_007f;
pub(crate) const STATUS_DEVICE_NOT_READY: u64 = 0xc000_00a3;
pub(crate) const STATUS_ILLEGAL_FUNCTION: u64 = 0xc000_00af;
pub(crate) const STATUS_PIPE_DISCONNECTED: u64 = 0xc000_00b0;
pub(crate) const STATUS_IO_TIMEOUT: u64 = 0xc000_00b5;
pub(crate) const STATUS_FILE_IS_A_DIRECTORY: u64 = 0xc000_00ba;
pub(crate) const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
pub(crate) const STATUS_DIRECTORY_NOT_EMPTY: u64 = 0xc000_0101;
pub(crate) const STATUS_NOT_A_DIRECTORY: u64 = 0xc000_0103;
pub(crate) const STATUS_TOO_MANY_OPENED_FILES: u64 = 0xc000_011f;
pub(crate) const STATUS_DEVICE_BUSY: u64 = 0x8000_0011;
pub(crate) const STATUS_REPARSE_POINT_NOT_RESOLVED: u64 = 0xc000_0280;

const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

/// Preserve the VFS errno distinction at the NT file boundary. # C: O(1)
pub(crate) fn status_from_errno(rv: i64) -> u64 {
    let value = rv.unsigned_abs() as i32;
    if value == Errno::Eagain.as_i32() { return STATUS_SHARING_VIOLATION; }
    if value == Errno::Ebadf.as_i32() { return STATUS_INVALID_HANDLE; }
    if value == Errno::Ebusy.as_i32() { return STATUS_DEVICE_BUSY; }
    if value == Errno::Enospc.as_i32() { return STATUS_DISK_FULL; }
    if value == Errno::Eperm.as_i32() || value == Errno::Erofs.as_i32()
        || value == Errno::Eacces.as_i32() { return STATUS_ACCESS_DENIED; }
    if value == Errno::Enotdir.as_i32() { return STATUS_OBJECT_PATH_NOT_FOUND; }
    if value == Errno::Enoent.as_i32() { return STATUS_OBJECT_NAME_NOT_FOUND; }
    if value == Errno::Eisdir.as_i32() { return STATUS_INVALID_DEVICE_REQUEST; }
    if value == Errno::Emfile.as_i32() || value == Errno::Enfile.as_i32() { return STATUS_TOO_MANY_OPENED_FILES; }
    if value == Errno::Einval.as_i32() { return STATUS_INVALID_PARAMETER; }
    if value == Errno::Enotempty.as_i32() { return STATUS_DIRECTORY_NOT_EMPTY; }
    if value == Errno::Epipe.as_i32() || value == Errno::Econnreset.as_i32() { return STATUS_PIPE_DISCONNECTED; }
    if value == Errno::Eio.as_i32() { return STATUS_DEVICE_NOT_READY; }
    if value == Errno::Enxio.as_i32() { return STATUS_NO_SUCH_DEVICE; }
    if value == Errno::Enotty.as_i32() || value == Errno::Eopnotsupp.as_i32() { return STATUS_NOT_SUPPORTED; }
    if value == Errno::Efault.as_i32() { return STATUS_ACCESS_VIOLATION; }
    if value == Errno::Espipe.as_i32() { return STATUS_ILLEGAL_FUNCTION; }
    if value == Errno::Eloop.as_i32() { return STATUS_REPARSE_POINT_NOT_RESOLVED; }
    if value == Errno::Etime.as_i32() { return STATUS_IO_TIMEOUT; }
    // A name that already exists is a collision at this boundary; the
    // creating caller is the only one that can see it, and it is the status
    // a create with FILE_CREATE reports.
    if value == Errno::Eexist.as_i32() { return STATUS_OBJECT_NAME_COLLISION; }
    STATUS_UNSUCCESSFUL
}

/// The status for a name the walk did not find. A component before the last
/// one is a missing *path*; the last component alone is a missing *name*, and
/// a search that treats the two alike either stops early or never stops.
/// # C: O(1)
pub(crate) const fn missing_status(parent_resolved: bool) -> u64 {
    if parent_resolved { STATUS_OBJECT_NAME_NOT_FOUND } else { STATUS_OBJECT_PATH_NOT_FOUND }
}

/// The directory options are checked against what the opened name turned out
/// to be, after the open, never against the name's spelling. # C: O(1)
pub(crate) const fn directory_option_status(options: u32, is_directory: bool) -> Option<u64> {
    if options & FILE_DIRECTORY_FILE != 0 && !is_directory { return Some(STATUS_NOT_A_DIRECTORY); }
    if options & FILE_NON_DIRECTORY_FILE != 0 && is_directory { return Some(STATUS_FILE_IS_A_DIRECTORY); }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A loader continues its search on exactly these two statuses and stops
    /// on every other one, so a missing intermediate directory must not be
    /// reported as anything else.
    #[test]
    fn a_missing_component_reports_path_or_name_by_where_the_walk_stopped() {
        assert_eq!(missing_status(true), STATUS_OBJECT_NAME_NOT_FOUND);
        assert_eq!(missing_status(false), STATUS_OBJECT_PATH_NOT_FOUND);
        assert_eq!(status_from_errno(-(Errno::Enoent.as_i32() as i64)), STATUS_OBJECT_NAME_NOT_FOUND);
        // A component that exists but is not a directory ends the walk in the
        // path, not at the name.
        assert_eq!(status_from_errno(-(Errno::Enotdir.as_i32() as i64)), STATUS_OBJECT_PATH_NOT_FOUND);
    }

    #[test]
    fn every_file_errno_keeps_its_own_status() {
        let pairs: &[(i32, u64)] = &[
            (Errno::Eagain.as_i32(), STATUS_SHARING_VIOLATION),
            (Errno::Ebadf.as_i32(), STATUS_INVALID_HANDLE),
            (Errno::Ebusy.as_i32(), STATUS_DEVICE_BUSY),
            (Errno::Enospc.as_i32(), STATUS_DISK_FULL),
            (Errno::Eperm.as_i32(), STATUS_ACCESS_DENIED),
            (Errno::Erofs.as_i32(), STATUS_ACCESS_DENIED),
            (Errno::Eacces.as_i32(), STATUS_ACCESS_DENIED),
            (Errno::Eisdir.as_i32(), STATUS_INVALID_DEVICE_REQUEST),
            (Errno::Emfile.as_i32(), STATUS_TOO_MANY_OPENED_FILES),
            (Errno::Enfile.as_i32(), STATUS_TOO_MANY_OPENED_FILES),
            (Errno::Einval.as_i32(), STATUS_INVALID_PARAMETER),
            (Errno::Enotempty.as_i32(), STATUS_DIRECTORY_NOT_EMPTY),
            (Errno::Epipe.as_i32(), STATUS_PIPE_DISCONNECTED),
            (Errno::Econnreset.as_i32(), STATUS_PIPE_DISCONNECTED),
            (Errno::Eio.as_i32(), STATUS_DEVICE_NOT_READY),
            (Errno::Enxio.as_i32(), STATUS_NO_SUCH_DEVICE),
            (Errno::Enotty.as_i32(), STATUS_NOT_SUPPORTED),
            (Errno::Eopnotsupp.as_i32(), STATUS_NOT_SUPPORTED),
            (Errno::Efault.as_i32(), STATUS_ACCESS_VIOLATION),
            (Errno::Espipe.as_i32(), STATUS_ILLEGAL_FUNCTION),
            (Errno::Eloop.as_i32(), STATUS_REPARSE_POINT_NOT_RESOLVED),
            (Errno::Etime.as_i32(), STATUS_IO_TIMEOUT),
            (Errno::Eexist.as_i32(), STATUS_OBJECT_NAME_COLLISION),
        ];
        for (errno, status) in pairs {
            assert_eq!(status_from_errno(-(*errno as i64)), *status, "errno {errno}");
            assert_eq!(status_from_errno(*errno as i64), *status, "errno {errno}");
        }
        // An errno with no NT class of its own is a plain failure, never a
        // missing name and never an invalid argument.
        assert_eq!(status_from_errno(-(Errno::Enametoolong.as_i32() as i64)), STATUS_UNSUCCESSFUL);
    }

    #[test]
    fn the_directory_options_are_answered_from_what_the_name_turned_out_to_be() {
        assert_eq!(directory_option_status(FILE_DIRECTORY_FILE, true), None);
        assert_eq!(directory_option_status(FILE_DIRECTORY_FILE, false), Some(STATUS_NOT_A_DIRECTORY));
        assert_eq!(directory_option_status(FILE_NON_DIRECTORY_FILE, false), None);
        assert_eq!(directory_option_status(FILE_NON_DIRECTORY_FILE, true), Some(STATUS_FILE_IS_A_DIRECTORY));
        assert_eq!(directory_option_status(0, true), None);
        assert_eq!(directory_option_status(0, false), None);
    }
}
