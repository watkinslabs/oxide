#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use super::out::OptOut;
use super::uapi::*;

/// `getsockopt(fd, IPPROTO_TCP, ...)`. # C: O(1)
pub(super) fn get(sock: &Arc<net::sock::InetSocket>, optname: u64, out: &OptOut) -> i64 {
    match optname {
        TCP_NODELAY => out.i32(sock.opts.tcp_nodelay.load(Ordering::Acquire)),
        TCP_CORK => out.i32(sock.opts.tcp_cork.load(Ordering::Acquire)),
        TCP_KEEPIDLE => out.i32(sock.opts.tcp_keepidle_s.load(Ordering::Acquire)),
        TCP_KEEPINTVL => out.i32(sock.opts.tcp_keepintvl_s.load(Ordering::Acquire)),
        TCP_KEEPCNT => out.i32(sock.opts.tcp_keepcnt.load(Ordering::Acquire)),
        TCP_INFO => crate::tcp_info::write_tcp_info(sock, out.optval, out.optlen_p),
        _ => -(Errno::Enoprotoopt.as_i32() as i64),
    }
}
