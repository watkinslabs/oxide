#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::errno::Errno;

/// `setsockopt(fd, IPPROTO_UDP, ...)`. # C: O(1)
pub(super) fn set(_sock: &Arc<net::sock::InetSocket>, _optname: u64,
                  _optval: u64, _optlen: u32) -> i64 {
    -(Errno::Enoprotoopt.as_i32() as i64)
}
