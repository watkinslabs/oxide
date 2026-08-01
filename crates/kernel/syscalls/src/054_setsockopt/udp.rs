#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::errno::Errno;

use super::optval::read_i32_required;
use super::uapi::*;

/// `setsockopt(fd, IPPROTO_UDP, ...)`. # C: O(pending bytes)
pub(super) fn set(sock: &Arc<net::sock::InetSocket>, optname: u64,
                  optval: u64, optlen: u32) -> i64 {
    // The level itself is unreachable on a socket that is not UDP, so the
    // operand is never imported there.
    if !net::sock_opts::sol_udp::level_supported(sock) {
        return -(Errno::Enoprotoopt.as_i32() as i64);
    }
    let val = match read_i32_required(optval, optlen) { Ok(v) => v, Err(e) => return e };
    match net::sock_opts::sol_udp::emit::setsockopt(sock, optname, val) {
        Ok(()) => 0,
        Err(error) => crate::net_errno::errno_from_neterr(error),
    }
}

// The slot's level-17 numbers and the option owner's are the same ABI; a
// drift between them would silently route one option number to another.
const _: () = {
    use net::sock_opts::sol_udp::uapi as owner;
    assert!(UDP_CORK == owner::UDP_CORK);
    assert!(UDP_ENCAP == owner::UDP_ENCAP);
    assert!(UDP_NO_CHECK6_TX == owner::UDP_NO_CHECK6_TX);
    assert!(UDP_NO_CHECK6_RX == owner::UDP_NO_CHECK6_RX);
    assert!(UDP_SEGMENT == owner::UDP_SEGMENT);
    assert!(UDP_GRO == owner::UDP_GRO);
};
