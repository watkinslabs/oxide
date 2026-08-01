#![cfg(target_os = "oxide-kernel")]

// SOL_SOCKET option numbers live in `net::sock_opts::sol_socket`.
pub(super) use net::sock_opts::sol_socket::{SOL_SOCKET, SO_BINDTODEVICE};
pub(super) const SO_ATTACH_FILTER: u64 = 26;
pub(super) const SO_DETACH_FILTER: u64 = 27;
pub(super) const SO_LOCK_FILTER: u64 = 44;
pub(super) const SO_ATTACH_BPF: u64 = 50;

pub(super) const SOCK_FPROG_SIZE: u32 = 16;
pub(super) const SOCK_FPROG_FILTER_OFFSET: u64 = 8;
pub(super) const BPF_INSN_SIZE: usize = 8;
pub(super) const BPF_MAXINSNS: usize = 4096;

pub(super) const IPPROTO_IP: u64 = 0;
pub(super) const IP_TOS: u64 = 1;
pub(super) const IP_TTL: u64 = 2;
pub(super) const IP_HDRINCL: u64 = 3;
pub(super) const IP_PKTINFO: u64 = 8;
pub(super) const IP_MTU_DISCOVER: u64 = 10;
pub(super) const IP_RECVERR: u64 = 11;
pub(super) const IP_RECVTTL: u64 = 12;
pub(super) const IP_MULTICAST_IF: u64 = 32;
pub(super) const IP_MULTICAST_TTL: u64 = 33;
pub(super) const IP_MULTICAST_LOOP: u64 = 34;
pub(super) const IP_ADD_MEMBERSHIP: u64 = 35;
pub(super) const IP_DROP_MEMBERSHIP: u64 = 36;
pub(super) const IP_UNBLOCK_SOURCE: u64 = 37;
pub(super) const IP_BLOCK_SOURCE: u64 = 38;
pub(super) const IP_ADD_SOURCE_MEMBERSHIP: u64 = 39;
pub(super) const IP_DROP_SOURCE_MEMBERSHIP: u64 = 40;
pub(super) const IP_MSFILTER: u64 = 41;
pub(super) const MCAST_JOIN_GROUP: u64 = 42;
pub(super) const MCAST_BLOCK_SOURCE: u64 = 43;
pub(super) const MCAST_UNBLOCK_SOURCE: u64 = 44;
pub(super) const MCAST_LEAVE_GROUP: u64 = 45;
pub(super) const MCAST_JOIN_SOURCE_GROUP: u64 = 46;
pub(super) const MCAST_LEAVE_SOURCE_GROUP: u64 = 47;
pub(super) const MCAST_MSFILTER: u64 = 48;

pub(super) const IPPROTO_IPV6: u64 = 41;
pub(super) const IPV6_CHECKSUM: u64 = 7;
pub(super) const IPV6_UNICAST_HOPS: u64 = 16;
pub(super) const IPV6_MULTICAST_IF: u64 = 17;
pub(super) const IPV6_MULTICAST_HOPS: u64 = 18;
pub(super) const IPV6_MULTICAST_LOOP: u64 = 19;
pub(super) const IPV6_JOIN_GROUP: u64 = 20;
pub(super) const IPV6_LEAVE_GROUP: u64 = 21;
pub(super) const IPV6_RECVERR: u64 = 25;
pub(super) const IPV6_MTU_DISCOVER: u64 = 23;
pub(super) const IPV6_V6ONLY: u64 = 26;
pub(super) const IPV6_HDRINCL: u64 = 36;
pub(super) const IPV6_RECVTCLASS: u64 = 66;
pub(super) const IPV6_TCLASS: u64 = 67;
pub(super) const IPV6_RECVPKTINFO: u64 = 49;
pub(super) const IPV6_RECVHOPLIMIT: u64 = 51;

pub(super) const IPPROTO_ICMP: u8 = 1;
pub(super) const IPPROTO_ICMPV6: u8 = 58;
pub(super) const SOL_ICMPV6: u64 = 58;
pub(super) const IPPROTO_RAW: u64 = 255;
pub(super) const ICMP_FILTER: u64 = 1;
pub(super) const ICMP6_FILTER: u64 = 1;

pub(super) const IPPROTO_UDP: u64 = 17;

pub(super) const IPPROTO_TCP: u64 = 6;
pub(super) const TCP_NODELAY: u64 = 1;
pub(super) const TCP_CORK: u64 = 3;
pub(super) const TCP_KEEPIDLE: u64 = 4;
pub(super) const TCP_KEEPINTVL: u64 = 5;
pub(super) const TCP_KEEPCNT: u64 = 6;

pub(super) const UDP_CORK: u64 = 1;
pub(super) const UDP_ENCAP: u64 = 100;
pub(super) const UDP_NO_CHECK6_TX: u64 = 101;
pub(super) const UDP_NO_CHECK6_RX: u64 = 102;
pub(super) const UDP_SEGMENT: u64 = 103;
pub(super) const UDP_GRO: u64 = 104;
