// SOL_SOCKET readback copyout for slot 55. The value table and its length
// rules live in `net::sock_opts::sol_socket::get` (`docs/53§4`); this file
// only moves bytes.
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use syscall::errno::Errno;
use net::sock::InetSocket;
use net::sock_opts::sol_socket::get::{self, SockView};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Snapshot the non-generic socket state the read table needs. # C: O(1)
pub(super) fn view(sock: &Arc<InetSocket>) -> SockView {
    SockView {
        sock: net::sock_opts::describe(sock),
        reuseaddr: sock.opts.reuseaddr.load(Ordering::Acquire),
        reuseport: sock.opts.reuseport.load(Ordering::Acquire),
        keepalive: sock.opts.keepalive.load(Ordering::Acquire),
        broadcast: sock.opts.broadcast.load(Ordering::Acquire),
        oobinline: sock.opts.oobinline.load(Ordering::Acquire),
        sndbuf: sock.opts.sndbuf.load(Ordering::Acquire),
        rcvbuf: sock.opts.rcvbuf.load(Ordering::Acquire),
        priority: sock.opts.priority.load(Ordering::Acquire),
        mark: sock.opts.mark.load(Ordering::Acquire),
        passcred: sock.opts.passcred.load(Ordering::Acquire),
        timestamping_flags: sock.opts.timestamping.load(Ordering::Acquire),
        sndtimeo_ns: sock.opts.sndtimeo_ns.load(Ordering::Acquire),
        rcvtimeo_ns: sock.opts.rcvtimeo_ns.load(Ordering::Acquire),
        bound_ifindex: sock.opts.bound_ifindex.load(Ordering::Acquire) as i32,
        acceptconn: super::socket_acceptconn(sock),
        socket_type: super::socket_type(sock),
        protocol: super::socket_protocol(sock),
        netns_cookie: sock.net_ns(),
        socket_cookie: sock.opts.generic.cookie(net::sock_opts::sol_socket::next_cookie) as u64,
        // No receive path in this stack runs inside a NAPI context, so no
        // socket ever records a valid identifier and the option reads zero.
        napi_id: 0,
    }
}

/// `sk_getsockopt` for one SOL_SOCKET read: import the caller length, resolve
/// one value, truncate to the natural width, then publish value and length.
/// # C: O(1)
pub(super) fn read(sock: &Arc<InetSocket>, optname: u64, optval: u64, optlen_p: u64) -> i64 {
    let mut raw_len = [0u8; core::mem::size_of::<i32>()];
    if uaccess::copy_from_user(&mut raw_len, optlen_p).is_err() { return errno(Errno::Efault); }
    let requested = i32::from_ne_bytes(raw_len);
    if requested < 0 { return errno(Errno::Einval); }
    let value = match get::value(optname, requested, &sock.opts.generic, &view(sock)) {
        Ok(value) => value,
        Err(e) => return errno(e),
    };
    let mut bytes = [0u8; 16];
    let natural = get::encode(&value, &mut bytes);
    let take = core::cmp::min(requested as usize, natural);
    if take != 0 && uaccess::copy_to_user(optval, &bytes[..take]).is_err() {
        return errno(Errno::Efault);
    }
    if uaccess::copy_to_user(optlen_p, &(take as u32).to_ne_bytes()).is_err() {
        return errno(Errno::Efault);
    }
    0
}
