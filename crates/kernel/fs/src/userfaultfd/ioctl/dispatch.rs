// The command table. An unrecognised command is EINVAL (not ENOTTY), and every
// command except the API handshake is refused until that handshake has run.

use syscall::errno::Errno;

use crate::userfaultfd::{as_uffd, policy, uapi::*};

use super::structs::err;

/// `ioctl(uffd_fd, UFFDIO_*, arg)`, dispatched when the fd's inode is a
/// userfaultfd.
/// # C: O(K) for the range ops (K = pages), O(1) otherwise
pub fn handle_uffd_ioctl(inode: &vfs::InodeRef, req: u64, arg: u64) -> i64 {
    let ufd = match as_uffd(inode) { Some(u) => u, None => return err(Errno::Enotty) };
    let feats = ufd.features.load(core::sync::atomic::Ordering::Acquire);
    if let Err(e) = policy::check_ioctl_ordering(req, feats) { return err(e); }
    match req {
        UFFDIO_API          => super::api::ioc_api(&ufd, arg),
        UFFDIO_REGISTER     => super::register::ioc_register(&ufd, arg),
        UFFDIO_UNREGISTER   => super::register::ioc_unregister(&ufd, arg),
        UFFDIO_WAKE         => super::register::ioc_wake(&ufd, arg),
        UFFDIO_COPY         => super::fill::ioc_copy(&ufd, arg),
        UFFDIO_ZEROPAGE     => super::fill::ioc_zeropage(&ufd, arg),
        UFFDIO_CONTINUE     => super::fill::ioc_continue(&ufd, arg),
        UFFDIO_POISON       => super::fill::ioc_poison(&ufd, arg),
        UFFDIO_WRITEPROTECT => super::wp::ioc_writeprotect(&ufd, arg),
        UFFDIO_MOVE         => super::movepg::ioc_move(&ufd, arg),
        _ => err(Errno::Einval),
    }
}
