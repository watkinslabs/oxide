#![cfg(target_os = "oxide-kernel")]

// SOL_SOCKET option numbers live in `net::sock_opts::sol_socket`.
pub(super) use net::sock_opts::sol_socket::{SOL_SOCKET, SO_BINDTODEVICE, SO_ERROR,
    SO_GET_FILTER, SO_LOCK_FILTER, SO_MEMINFO, SO_PEERCRED, SO_PEERGROUPS, SO_PEERNAME,
    SO_PEERPIDFD, SO_PEERSEC};


pub(super) const IPPROTO_IP: u64 = 0;
pub(super) const IPPROTO_TCP: u64 = 6;
pub(super) const IPPROTO_UDP: u64 = 17;
pub(super) const IPPROTO_IPV6: u64 = 41;
pub(super) const IPPROTO_ICMP: u8 = 1;
pub(super) const IPPROTO_ICMPV6: u8 = 58;
pub(super) const IPPROTO_RAW: u64 = 255;

pub(super) const IP_TOS: u64 = 1;
pub(super) const IP_TTL: u64 = 2;
pub(super) const IP_HDRINCL: u64 = 3;
pub(super) const IP_PKTINFO: u64 = 8;
pub(super) const IP_MTU_DISCOVER: u64 = 10;
pub(super) const IP_RECVERR: u64 = 11;
pub(super) const IP_MTU: u64 = 14;
pub(super) const IP_MULTICAST_TTL: u64 = 33;
pub(super) const IP_MULTICAST_LOOP: u64 = 34;
pub(super) const IP_MSFILTER: u64 = 41;

pub(super) const IPV6_CHECKSUM: u64 = 7;
pub(super) const IPV6_UNICAST_HOPS: u64 = 16;
pub(super) const IPV6_MULTICAST_IF: u64 = 17;
pub(super) const IPV6_MULTICAST_HOPS: u64 = 18;
pub(super) const IPV6_MULTICAST_LOOP: u64 = 19;
pub(super) const IPV6_MTU_DISCOVER: u64 = 23;
pub(super) const IPV6_MTU: u64 = 24;
pub(super) const IPV6_RECVERR: u64 = 25;
pub(super) const IPV6_V6ONLY: u64 = 26;
pub(super) const IPV6_HDRINCL: u64 = 36;
pub(super) const IPV6_RECVTCLASS: u64 = 66;
pub(super) const IPV6_TCLASS: u64 = 67;
pub(super) const IPV6_RECVPKTINFO: u64 = 49;
pub(super) const IPV6_RECVHOPLIMIT: u64 = 51;

pub(super) const SOL_ICMPV6: u64 = 58;
pub(super) const ICMP_FILTER: u64 = 1;
pub(super) const ICMP6_FILTER: u64 = 1;
/// `struct icmp6_filter` — eight 32-bit words.
pub(super) const ICMP6_FILTER_BYTES: usize = 32;
pub(super) const MCAST_MSFILTER: u64 = 48;


/// Linux default outbound multicast hop limit when `IPV6_MULTICAST_HOPS` is unset.
pub(super) const IPV6_DEFAULT_MULTICAST_HOPS: i32 = 1;
