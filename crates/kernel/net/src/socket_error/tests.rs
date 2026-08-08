//! Module manifest: `queue` covers publication/dequeue/pending-errno parity,
//! `origins` covers the per-origin record shapes, `abi` covers the wire
//! encoding and the two support ladders, `send_failure` covers the
//! local-origin report a refused transmit produces.

mod abi;
mod origins;
mod queue;
mod send_failure;

use crate::addr::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::socket_error::SocketErrorEntry;

/// One ICMP-origin record aimed at a v4 destination. # C: O(1)
pub(super) fn icmp4(errno: syscall::errno::Errno) -> SocketErrorEntry {
    SocketErrorEntry::icmp(errno as i32, false, 3, 1, 0,
        IpAddr::V4(Ipv4Addr::LOOPBACK), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53, 1,
        alloc::vec![1, 2])
}

/// One ICMPv6-origin record aimed at a v6 destination. # C: O(1)
pub(super) fn icmp6(errno: syscall::errno::Errno) -> SocketErrorEntry {
    SocketErrorEntry::icmp(errno as i32, true, 1, 4, 0,
        IpAddr::V6(Ipv6Addr::LOOPBACK), IpAddr::V6(Ipv6Addr::LOOPBACK), 53, 1, alloc::vec![9])
}
