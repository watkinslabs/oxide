#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::errno::Errno;

use super::out::OptOut;
use super::uapi::*;

/// `getsockopt(fd, IPPROTO_UDP, ...)`. # C: O(1)
pub(super) fn get(sock: &Arc<net::sock::InetSocket>, optname: u64, out: &OptOut) -> i64 {
    // The level itself is unreachable on a socket that is not UDP, and there
    // the caller's length is never even read.
    if !net::sock_opts::sol_udp::level_supported(sock) {
        return -(Errno::Enoprotoopt.as_i32() as i64);
    }
    // The caller's length is imported before the option table is consulted, so
    // a faulting length pointer outranks an unknown option number.
    if let Err(e) = probe_len(out) { return e; }
    match net::sock_opts::sol_udp::getsockopt(sock, optname) {
        Ok(value) => out.i32(value),
        Err(error) => crate::net_errno::errno_from_neterr(error),
    }
}

fn probe_len(out: &OptOut) -> Result<(), i64> {
    let mut raw = [0u8; 4];
    if uaccess::copy_from_user(&mut raw, out.optlen_p).is_err() {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    if i32::from_ne_bytes(raw) < 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    Ok(())
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
