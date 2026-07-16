// Kernel-side AF_INET/UNIX wrapper around `crate::NetStack`.
//
// Module manifest:
// - globals: process-global stack, loopback drain, ephemeral ports.
// - types: socket kind/state structs and constructors.
// - packet: AF_PACKET observation registry, metadata, filtering, and queues.
// - packet_metadata: AF_PACKET driver metadata and ancillary ABI values.
// - packet_options: AF_PACKET option state and work functions.
// - packet_queue: AF_PACKET byte pressure, queue accounting, and statistics.
// - packet_membership: AF_PACKET device-filter ownership and teardown.
// - construct: family constructors and namespace-owner snapshots.
// - inode: VFS inode wrapper and file operations bridge.
// - io: socket read/write/poll methods.
// - udp: datagram receive/send helpers and iface source hook.
// - raw_bind: raw IPv4/IPv6 bind lifecycle serialization.
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
mod packet;
mod packet_metadata;
mod packet_options;
mod packet_queue;
mod packet_membership;
mod construct;
mod iface;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
mod inode;
#[cfg(target_os = "oxide-kernel")]
mod io;
#[cfg(target_os = "oxide-kernel")]
mod udp;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
mod raw;
#[cfg(target_os = "oxide-kernel")]
mod unix;
#[cfg(target_os = "oxide-kernel")]
mod shutdown;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
mod lifecycle;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
mod raw_bind;
#[cfg(target_os = "oxide-kernel")]
pub(crate) mod tcp_lifecycle;
#[cfg(target_os = "oxide-kernel")]
mod ops;
#[cfg(target_os = "oxide-kernel")]
mod send;
#[cfg(test)]
mod packet_tests;
#[cfg(test)]
mod packet_membership_tests;

pub use globals::*;
pub use types::*;
pub use packet::*;
pub use packet_metadata::*;
pub use packet_options::*;
pub use packet_queue::*;
pub use packet_membership::*;
pub use iface::*;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub use inode::*;
#[cfg(target_os = "oxide-kernel")]
pub use udp::*;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub use raw::*;
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub(crate) use raw_bind::*;
#[cfg(target_os = "oxide-kernel")]
pub use shutdown::*;
#[cfg(target_os = "oxide-kernel")]
pub use ops::*;
#[cfg(target_os = "oxide-kernel")]
pub use send::*;
#[cfg(target_os = "oxide-kernel")]
pub use crate::sock_io::{recvfrom, recvfrom_opts, Received, RecvOptions};
