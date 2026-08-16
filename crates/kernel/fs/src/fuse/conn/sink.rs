// The transport's return path into the channel, and the wire-errno
// translation every completed request passes through.
//
// A reply reaches the channel by one of two roads — a daemon's
// `write(/dev/fuse)` or a transport delivering a frame — and both end at
// `submit_reply`. There is one reply matcher, not one per courier.

extern crate alloc;

use super::FuseConn;
use crate::fuse::iqueue::FuseReplySink;

/// Map a NEGATIVE wire errno (`fuse_out_header.error`) back to a [`vfs::VfsError`]
/// for the VFS caller. Unknown codes collapse to `Eio`. # C: O(1)
pub(crate) fn wire_err_to_vfs(neg: i32) -> vfs::VfsError {
    vfs::VfsError::from_posix_errno(-neg)
}

#[cfg(test)]
mod tests {
    use super::wire_err_to_vfs;
    use vfs::VfsError;

    /// A daemon errno reaches the caller as ITSELF, not as a generic I/O error.
    /// `ESTALE` in particular: it was folded into `EIO`, which both hid a real
    /// server answer and made the one errno the path-resolution retry exists to
    /// act on unreachable — the retry could never fire because nothing in the
    /// tree could produce the error that triggers it. # C: O(1)
    #[test]
    fn daemon_errnos_survive_translation() {
        let cases = [
            (-1, VfsError::Eperm), (-2, VfsError::Enoent), (-5, VfsError::Eio),
            (-9, VfsError::Ebadf), (-13, VfsError::Eacces), (-17, VfsError::Eexist),
            (-20, VfsError::Enotdir), (-21, VfsError::Eisdir), (-22, VfsError::Einval),
            (-38, VfsError::Enosys), (-95, VfsError::Eopnotsupp),
            (-107, VfsError::Enotconn), (-116, VfsError::Estale),
        ];
        for (wire, want) in cases {
            assert_eq!(wire_err_to_vfs(wire), want, "wire {wire}");
        }
        // A stale handle must be distinguishable from a generic failure.
        assert_ne!(wire_err_to_vfs(-116), wire_err_to_vfs(-5));
        // An errno with no mapping is still an error, never a success.
        assert_eq!(wire_err_to_vfs(-4095), VfsError::Eio);
    }
}

impl FuseReplySink for FuseConn {
    /// A transport-delivered reply takes the same path a daemon's
    /// `write(/dev/fuse)` does — one reply-matching implementation, whichever
    /// side of the seam the bytes arrived from. A malformed or unmatched frame
    /// is dropped rather than failing the channel: the transport has no caller
    /// to report it to. # C: O(log N_inflight)
    fn deliver(&self, frame: &[u8]) { let _ = self.submit_reply(frame); }

    /// # C: O(N_inflight)
    fn disconnect(&self) { self.abort(); }
}
