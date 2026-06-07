// AF_INET socket syscalls. v1: SOCK_DGRAM/UDP on AF_INET (IPv4).
//
// Per docs/53 §0 each socket syscall handler now lives in its own
// <NNN>_<name>.rs module; shared helpers + consts live in
// net_common.rs. This file only re-exports the handlers (and the
// mmsg pair) so callers keep using `crate::net::sys_*`.
#![cfg(target_os = "oxide-kernel")]

pub use crate::s299_recvmmsg::sys_recvmmsg;
pub use crate::s307_sendmmsg::sys_sendmmsg;

// F162: sys_recvfrom lives in net_recv.rs. Re-exported via the
// syscalls module.
