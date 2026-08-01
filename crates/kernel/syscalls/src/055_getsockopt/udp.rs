#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use syscall::errno::Errno;

use super::out::OptOut;

/// `getsockopt(fd, IPPROTO_UDP, ...)`. # C: O(1)
pub(super) fn get(_sock: &Arc<net::sock::InetSocket>, _optname: u64, _out: &OptOut) -> i64 {
    -(Errno::Enoprotoopt.as_i32() as i64)
}
