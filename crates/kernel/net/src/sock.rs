// Kernel-side AF_INET/UNIX wrapper around `crate::NetStack`.
//
// Module manifest:
// - globals: process-global stack, loopback drain, ephemeral ports.
// - types: socket kind/state structs, packet registry, constructors.
// - construct: family constructors and namespace-owner snapshots.
// - inode: VFS inode wrapper and file operations bridge.
// - io: socket read/write/poll methods.
// - udp: datagram receive/send helpers and iface source hook.
// - unix: AF_UNIX connect lifecycle and backlog waiting.
// - shutdown: protocol-owned shutdown transitions.
// - lifecycle: endpoint errors, filters, device binding, and autobind.
// - tcp_lifecycle: TCP bind, listen, and active-open reservation transitions.
// - ops: bind/connect/listen/accept lifecycle work functions.
// - send: protocol send dispatch and per-socket defaults.
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::{NetStack, LoopbackDev, Ipv4Addr, NetIfaceId, NetError};
use crate::stack::{TcpEntry, TcpListenEntry};
use sync::{Spinlock, Socket as SockLockClass};
#[cfg(target_os = "oxide-kernel")]
use crate::sock_opts::{apply_tcp_keepalive_opts, inherit_tcp_keepalive_opts};
pub use crate::sock_opts::SenderCreds;
#[cfg(target_os = "oxide-kernel")]
pub use crate::sock_io::compute_deadline_ns;

mod globals;
mod types;
mod construct;
mod iface;
#[cfg(target_os = "oxide-kernel")]
mod inode;
#[cfg(target_os = "oxide-kernel")]
mod io;
#[cfg(target_os = "oxide-kernel")]
mod udp;
#[cfg(target_os = "oxide-kernel")]
mod raw;
#[cfg(target_os = "oxide-kernel")]
mod unix;
#[cfg(target_os = "oxide-kernel")]
mod shutdown;
#[cfg(target_os = "oxide-kernel")]
mod lifecycle;
#[cfg(target_os = "oxide-kernel")]
pub(crate) mod tcp_lifecycle;
#[cfg(target_os = "oxide-kernel")]
mod ops;
#[cfg(target_os = "oxide-kernel")]
mod send;

pub use globals::*;
pub use types::*;
pub use iface::*;
#[cfg(target_os = "oxide-kernel")]
pub use inode::*;
#[cfg(target_os = "oxide-kernel")]
pub use udp::*;
#[cfg(target_os = "oxide-kernel")]
pub use raw::*;
#[cfg(target_os = "oxide-kernel")]
pub use shutdown::*;
#[cfg(target_os = "oxide-kernel")]
pub use ops::*;
#[cfg(target_os = "oxide-kernel")]
pub use send::*;
#[cfg(target_os = "oxide-kernel")]
pub use crate::sock_io::{recvfrom, recvfrom_opts, PacketAddr, Received, RecvOptions};
