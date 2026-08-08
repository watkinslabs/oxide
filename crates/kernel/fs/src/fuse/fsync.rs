// FSYNC/FSYNCDIR decisions for a mounted fuse inode.
//
// Kept out of `fops.rs` and free of any target gate so the two things that are
// easy to get silently wrong — which opcode a directory takes, and what an
// `ENOSYS` reply means — are hosted-testable. Before this existed there was no
// fsync slot for fuse at all: `fsync`/`fdatasync` on a fuse file took the
// generic default's `Ok(())` and reported durability the daemon was never
// asked for.

use super::proto::{FUSE_FSYNC, FUSE_FSYNCDIR, FUSE_FSYNC_FDATASYNC};

/// Opcode for an fsync on a file (`FUSE_FSYNC`) or a directory
/// (`FUSE_FSYNCDIR`). A directory sent `FUSE_FSYNC` is a protocol error the
/// daemon answers however it likes, which is why this is a decision and not an
/// inline conditional. # C: O(1)
pub fn fsync_opcode(is_dir: bool) -> u32 {
    if is_dir { FUSE_FSYNCDIR } else { FUSE_FSYNC }
}

/// `fuse_fsync_in.fsync_flags` — the wire form of the `datasync` argument.
/// `fdatasync` sets `FUSE_FSYNC_FDATASYNC`, `fsync` clears it; a daemon that
/// only ever sees zero cannot elide the metadata write `fdatasync` permits it
/// to skip. # C: O(1)
pub fn fsync_flags(datasync: bool) -> u32 {
    if datasync { FUSE_FSYNC_FDATASYNC } else { 0 }
}

/// What a daemon reply means for the caller's `fsync`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FsyncOutcome {
    /// The sync completed.
    Done,
    /// The daemon has no handler for this opcode. The sync reports SUCCESS —
    /// a filesystem that does not implement fsync has nothing to flush — and
    /// the connection latches the answer so no later call pays the round trip.
    Unsupported,
    /// A real failure, reported to the caller.
    Failed(vfs::VfsError),
}

/// Classify a FSYNC/FSYNCDIR reply. `ENOSYS` is the one errno that is NOT an
/// error here: it is the daemon declining to implement the op, which the
/// protocol treats as "nothing to do", not as a failed sync. Passing it
/// through would make every `fsync` on such a filesystem fail. # C: O(1)
pub fn classify_reply(r: Result<(), vfs::VfsError>) -> FsyncOutcome {
    match r {
        Ok(())                     => FsyncOutcome::Done,
        Err(vfs::VfsError::Enosys) => FsyncOutcome::Unsupported,
        Err(e)                     => FsyncOutcome::Failed(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory takes `FUSE_FSYNCDIR` and a file `FUSE_FSYNC`; the two are
    /// distinct opcodes and a daemon dispatches on them. # C: O(1)
    #[test]
    fn directory_and_file_take_different_opcodes() {
        assert_eq!(fsync_opcode(false), FUSE_FSYNC);
        assert_eq!(fsync_opcode(true), FUSE_FSYNCDIR);
        assert_ne!(fsync_opcode(false), fsync_opcode(true));
        // The wire values are the protocol's, not ours to choose.
        assert_eq!(FUSE_FSYNC, 20);
        assert_eq!(FUSE_FSYNCDIR, 30);
    }

    /// `datasync` must reach the daemon as a flag bit. The whole point of the
    /// separate `fdatasync` slot is that the backend can skip the metadata
    /// write; a request that always carries zero cannot express it. # C: O(1)
    #[test]
    fn datasync_reaches_the_wire_as_a_flag() {
        assert_eq!(fsync_flags(true), FUSE_FSYNC_FDATASYNC);
        assert_eq!(fsync_flags(false), 0);
        assert_ne!(fsync_flags(true), fsync_flags(false));
        assert_eq!(FUSE_FSYNC_FDATASYNC, 1);
    }

    /// The encoded body is the 16-byte `fh,fsync_flags,padding` request, with
    /// the padding word zeroed and the flag in the right position — an offset
    /// slip here silently syncs with the wrong flags. # C: O(1)
    #[test]
    fn fsync_body_round_trips_at_the_declared_offsets() {
        use super::super::proto::{FsyncIn, FUSE_FSYNC_IN_SIZE};
        let mut b = alloc::vec::Vec::new();
        FsyncIn { fh: 0x0102_0304_0506_0708, fsync_flags: fsync_flags(true) }.encode(&mut b);
        assert_eq!(b.len(), FUSE_FSYNC_IN_SIZE);
        assert_eq!(&b[12..16], &[0, 0, 0, 0], "padding must be zero");
        let d = FsyncIn::decode(&b).unwrap();
        assert_eq!(d.fh, 0x0102_0304_0506_0708);
        assert_eq!(d.fsync_flags, FUSE_FSYNC_FDATASYNC);
        // And the non-datasync form leaves the flag word clear.
        let mut b2 = alloc::vec::Vec::new();
        FsyncIn { fh: 7, fsync_flags: fsync_flags(false) }.encode(&mut b2);
        assert_eq!(FsyncIn::decode(&b2).unwrap().fsync_flags, 0);
    }

    /// `ENOSYS` means "no handler", which is a SUCCESSFUL fsync plus a latch —
    /// not a failure. Every other errno is reported to the caller unchanged;
    /// swallowing them is how a sync path reports durability it never got.
    /// # C: O(1)
    #[test]
    fn enosys_is_unsupported_and_every_other_errno_fails() {
        assert_eq!(classify_reply(Ok(())), FsyncOutcome::Done);
        assert_eq!(classify_reply(Err(vfs::VfsError::Enosys)), FsyncOutcome::Unsupported);
        for e in [vfs::VfsError::Eio, vfs::VfsError::Enospc, vfs::VfsError::Enotconn,
                  vfs::VfsError::Ebadf, vfs::VfsError::Eintr] {
            assert_eq!(classify_reply(Err(e)), FsyncOutcome::Failed(e), "{e:?}");
        }
    }
}
