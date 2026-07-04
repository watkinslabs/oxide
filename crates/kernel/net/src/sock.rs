// Kernel-side AF_INET/UNIX wrapper around `crate::NetStack`.
//
// Module manifest:
// - globals: process-global stack, loopback drain, ephemeral ports.
// - types: socket kind/state structs, packet registry, constructors.
// - inode: VFS inode wrapper and file operations bridge.
// - io: socket read/write/poll methods.
// - udp: datagram receive/send helpers and iface source hook.
// - ops: bind/connect/listen/accept/sendto work functions.
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::{NetStack, LoopbackDev, Ipv4Addr, NetIfaceId, NetError};
use crate::stack::{TcpEntry, TcpListenEntry};
use sync::{Spinlock, Socket as SockLockClass};
use crate::sock_opts::{apply_tcp_keepalive_opts, inherit_tcp_keepalive_opts};
pub use crate::sock_opts::SenderCreds;
pub use crate::sock_io::compute_deadline_ns;

mod globals;
mod types;
mod inode;
mod io;
mod udp;
mod ops;

pub use globals::*;
pub use types::*;
pub use inode::*;
pub use udp::*;
pub use ops::*;
pub use crate::sock_io::{recvfrom, recvfrom_opts, Received, RecvOptions};
