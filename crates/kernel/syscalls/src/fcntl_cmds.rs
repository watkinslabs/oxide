// fcntl(2) command numbers (UAPI) and the one decision taken over the raw
// command before any of them runs: which commands an `O_PATH` descriptor may
// use. Ungated — `072_fcntl.rs` is kernel-target-only, so a test written inside
// it compiles out silently.
//
// The numbers live HERE and only here; the slot file uses these names.

/// Base of the Linux-specific command range.
const LINUX_SPECIFIC_BASE: u64 = 1024;

pub const F_DUPFD:   u64 = 0;
pub const F_GETFD:   u64 = 1;
pub const F_SETFD:   u64 = 2;
pub const F_GETFL:   u64 = 3;
pub const F_SETFL:   u64 = 4;
pub const F_GETLK:   u64 = 5;
pub const F_SETLK:   u64 = 6;
pub const F_SETLKW:  u64 = 7;
pub const F_SETOWN:  u64 = 8;
pub const F_GETOWN:  u64 = 9;
pub const F_SETSIG:  u64 = 10;
pub const F_GETSIG:  u64 = 11;
pub const F_SETOWN_EX: u64 = 15;
pub const F_GETOWN_EX: u64 = 16;
/// Copy out the `f_owner` credential snapshot `F_SETOWN` captured.
pub const F_GETOWNER_UIDS: u64 = 17;
pub const F_OFD_GETLK:  u64 = 36;
pub const F_OFD_SETLK:  u64 = 37;
pub const F_OFD_SETLKW: u64 = 38;

pub const F_SETLEASE: u64 = LINUX_SPECIFIC_BASE;
pub const F_GETLEASE: u64 = LINUX_SPECIFIC_BASE + 1;
pub const F_NOTIFY:   u64 = LINUX_SPECIFIC_BASE + 2;
/// "Do these two descriptors refer to the same open file description?".
pub const F_DUPFD_QUERY: u64 = LINUX_SPECIFIC_BASE + 3;
/// "Did the open that produced this fd CREATE the file?".
pub const F_CREATED_QUERY: u64 = LINUX_SPECIFIC_BASE + 4;
pub const F_DUPFD_CLOEXEC: u64 = LINUX_SPECIFIC_BASE + 6;
pub const F_SETPIPE_SZ: u64 = LINUX_SPECIFIC_BASE + 7;
pub const F_GETPIPE_SZ: u64 = LINUX_SPECIFIC_BASE + 8;
pub const F_ADD_SEALS:  u64 = LINUX_SPECIFIC_BASE + 9;
pub const F_GET_SEALS:  u64 = LINUX_SPECIFIC_BASE + 10;
pub const F_GET_RW_HINT: u64 = LINUX_SPECIFIC_BASE + 11;
pub const F_SET_RW_HINT: u64 = LINUX_SPECIFIC_BASE + 12;

/// May `cmd` be used on an `O_PATH` descriptor? Such a descriptor names a
/// location, not an open file: it has no access mode, no position and no
/// backend, so only the commands that operate on the DESCRIPTOR itself are
/// admitted. Everything else is `EBADF` — the same answer a closed descriptor
/// gets, because for these purposes an `O_PATH` fd is not an open file.
///
/// `F_GETFL` is on the list (it reports the flags the open carried) but
/// `F_SETFL` is not, and neither is any lock, lease, owner or pipe command.
/// # C: O(1)
pub fn allowed_on_o_path(cmd: u64) -> bool {
    matches!(cmd, F_CREATED_QUERY | F_DUPFD | F_DUPFD_CLOEXEC | F_DUPFD_QUERY
                  | F_GETFD | F_SETFD | F_GETFL)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The seven commands an O_PATH descriptor may use, and a representative
    // refusal from every other family: flags, locks, leases, delegations,
    // owner/signal, pipe size, seals and hints all report EBADF on such a fd.
    #[test]
    fn o_path_admits_only_descriptor_commands() {
        for c in [F_CREATED_QUERY, F_DUPFD, F_DUPFD_CLOEXEC, F_DUPFD_QUERY,
                  F_GETFD, F_SETFD, F_GETFL] {
            assert!(allowed_on_o_path(c), "cmd {c} operates on the descriptor");
        }
        for c in [F_SETFL, F_GETLK, F_SETLK, F_SETLKW, F_OFD_GETLK, F_OFD_SETLK,
                  F_OFD_SETLKW, F_GETOWN, F_SETOWN, F_GETOWN_EX, F_SETOWN_EX,
                  F_GETOWNER_UIDS, F_GETSIG, F_SETSIG, F_GETLEASE, F_SETLEASE,
                  F_NOTIFY, F_GETPIPE_SZ, F_SETPIPE_SZ, F_ADD_SEALS, F_GET_SEALS,
                  F_GET_RW_HINT, F_SET_RW_HINT, crate::fcntl_deleg::F_GETDELEG,
                  crate::fcntl_deleg::F_SETDELEG] {
            assert!(!allowed_on_o_path(c), "cmd {c} needs a real open file");
        }
        assert!(!allowed_on_o_path(u64::MAX), "an unknown command is not admitted either");
    }

    // The Linux-specific range is contiguous from its base; a wrong offset here
    // would silently alias one command onto another.
    #[test]
    fn linux_specific_numbering() {
        assert_eq!((F_SETLEASE, F_GETLEASE, F_NOTIFY), (1024, 1025, 1026));
        assert_eq!((F_DUPFD_QUERY, F_CREATED_QUERY), (1027, 1028));
        assert_eq!(F_DUPFD_CLOEXEC, 1030);
        assert_eq!((F_SETPIPE_SZ, F_GETPIPE_SZ), (1031, 1032));
        assert_eq!((F_ADD_SEALS, F_GET_SEALS), (1033, 1034));
        assert_eq!((F_GET_RW_HINT, F_SET_RW_HINT), (1035, 1036));
        // 1037/1038 (the per-file hint variants) are absent on purpose: they
        // are no longer dispatched and fall to the EINVAL default.
        assert_eq!((crate::fcntl_deleg::F_GETDELEG, crate::fcntl_deleg::F_SETDELEG),
                   (1039, 1040));
    }
}
