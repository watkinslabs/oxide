// SO_PEERPIDFD (77): hand the caller a pidfd for the process on the other end
// of a connected AF_UNIX socket.
//
// The point of the option is that a pid NUMBER is not a safe subject: between
// reading SO_PEERCRED and acting on the number the peer can exit and the
// number be reused, so the check lands on a different process. The kernel
// therefore hands out a descriptor for the identity it pinned when the
// connection was established (`sk->sk_peer_pid`), which cannot be re-targeted.
// D-Bus brokers read this at accept and forward it to authorization services
// (polkit) as `ProcessFD`; without it those services fall back to the racy
// pid path.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use syscall::errno::Errno;

const FD_BYTES: usize = 4;

fn neg(error: Errno) -> i64 { -(error.as_i32() as i64) }

/// The pinned identity of the peer process, from whichever AF_UNIX shape the
/// socket currently holds. A listening socket answers with its own owner, the
/// identity `listen(2)` published, matching Linux's `init_peercred` on the
/// listening socket. # C: O(1)
pub(super) fn peer_identity(sock: &Arc<net::sock::InetSocket>)
    -> Option<Arc<sched::pid::PidIdentity>>
{
    use net::sock::SockKind;
    match &*sock.kind.lock() {
        SockKind::Unix(pair, end) => pair.peer_identity(*end),
        SockKind::UnixMsgPair(pair, end) => pair.peer_identity(*end),
        SockKind::UnixListener(listener) => listener.owner_identity(),
        _ => None,
    }
}

/// `getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &fd, &len)`.
///
/// Linux `sk_getsockopt`: a socket that never pinned a peer identity is
/// ENODATA (not ENOPROTOOPT — the option exists, the datum does not); the
/// returned length is clamped to `sizeof(int)`; the descriptor is installed
/// close-on-exec, and only after both copyouts succeed, so a faulting caller
/// does not leak an fd. # C: O(N_fds)
pub(super) fn get(sock: &Arc<net::sock::InetSocket>, optval: u64, optlen_p: u64) -> i64 {
    let Some(identity) = peer_identity(sock) else { return neg(Errno::Enodata) };
    let Some(current) = sched::live::current() else { return neg(Errno::Ebadf) };

    let mut raw_len = [0u8; FD_BYTES];
    if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() { return neg(Errno::Efault); }
    let requested = i32::from_ne_bytes(raw_len);
    if requested < 0 { return neg(Errno::Einval); }
    let take = core::cmp::min(requested as usize, FD_BYTES);

    let prepared = match pidfd::prepare(&current, identity, pidfd::OpenOptions::default()) {
        Ok(prepared) => prepared,
        Err(pidfd::OpenError::BadFileTable) => return neg(Errno::Ebadf),
        Err(pidfd::OpenError::Install(error)) => return -(error as i64),
        Err(_) => return neg(Errno::Esrch),
    };
    let value = prepared.fd().to_ne_bytes();
    if take != 0 && uaccess::copy_to_user(optval, &value[..take]).is_err() {
        return neg(Errno::Efault);
    }
    if uaccess::copy_to_user(optlen_p, &(take as u32).to_ne_bytes()).is_err() {
        return neg(Errno::Efault);
    }
    prepared.commit();
    0
}
