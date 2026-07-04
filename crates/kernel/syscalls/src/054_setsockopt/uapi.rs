#![cfg(target_os = "oxide-kernel")]

pub(super) const SOL_SOCKET: u64 = 1;
pub(super) const SO_SNDBUF: u64 = 7;
pub(super) const SO_RCVBUF: u64 = 8;
pub(super) const SO_BINDTODEVICE: u64 = 25;
pub(super) const SO_TIMESTAMP_OLD: u64 = 29;
pub(super) const SO_SNDBUFFORCE: u64 = 32;
pub(super) const SO_RCVBUFFORCE: u64 = 33;
pub(super) const SO_TIMESTAMPNS_OLD: u64 = 35;
pub(super) const SO_TIMESTAMPING_OLD: u64 = 37;
pub(super) const SO_TIMESTAMP_NEW: u64 = 63;
pub(super) const SO_TIMESTAMPNS_NEW: u64 = 64;
pub(super) const SO_TIMESTAMPING_NEW: u64 = 65;

pub(super) const IPPROTO_IP: u64 = 0;
pub(super) const IP_TOS: u64 = 1;
pub(super) const IP_TTL: u64 = 2;
pub(super) const IP_PKTINFO: u64 = 8;
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
pub(super) const IPV6_JOIN_GROUP: u64 = 20;
pub(super) const IPV6_LEAVE_GROUP: u64 = 21;
pub(super) const IPV6_V6ONLY: u64 = 26;

pub(super) const IPPROTO_TCP: u64 = 6;
pub(super) const TCP_CORK: u64 = 3;
pub(super) const TCP_KEEPIDLE: u64 = 4;
pub(super) const TCP_KEEPINTVL: u64 = 5;
pub(super) const TCP_KEEPCNT: u64 = 6;
