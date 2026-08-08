//! `MSG_ERRQUEUE` wire encoding, shared by every family and by both
//! `recvmsg` and `recvmmsg`.
//!
//! Nothing here is target-gated: the layout choices and the two support
//! ladders (does this record fill `msg_name`, does it name an offender) are
//! decided in ordinary Rust so they are testable without a kernel build.

use alloc::vec::Vec;

use crate::addr::{IpAddr, Ipv6Addr};

use super::entry::SocketErrorEntry;
use super::uapi::{is_icmp_origin, SOCK_EXTENDED_ERR_LEN, SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_LOCAL};

pub const AF_UNSPEC: u16 = 0;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// Wire size of `sockaddr_in`.
pub const SOCKADDR_IN_LEN: usize = 16;
/// Wire size of `sockaddr_in6`.
pub const SOCKADDR_IN6_LEN: usize = 28;

/// Ancillary slot one family answers `MSG_ERRQUEUE` on.
pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_IPV6: i32 = 41;
pub const IP_RECVERR: i32 = 11;
pub const IPV6_RECVERR: i32 = 25;

/// The `(level, type)` ancillary slot a socket family answers on. # C: O(1)
pub const fn cmsg_slot(family_v6: bool) -> (i32, i32) {
    if family_v6 { (IPPROTO_IPV6, IPV6_RECVERR) } else { (IPPROTO_IP, IP_RECVERR) }
}

/// Sockaddr length the offender field of one socket family occupies. # C: O(1)
pub const fn offender_len(family_v6: bool) -> usize {
    if family_v6 { SOCKADDR_IN6_LEN } else { SOCKADDR_IN_LEN }
}

/// Whether `recvmsg` fills `msg_name` for this record.
///
/// Some origins carry a usable address even with no payload and no port; the
/// rest are addressable only when the record recorded a port. # C: O(1)
pub const fn supports_name(origin: u8, family_v6: bool, port: u16) -> bool {
    if port != 0 { return true; }
    if origin == SO_EE_ORIGIN_LOCAL { return true; }
    if family_v6 { is_icmp_origin(origin) } else { origin == SO_EE_ORIGIN_ICMP }
}

/// Whether the ancillary record names an offender.
///
/// A received ICMP error always names its speaker. A locally generated error
/// never does. Transmit-completion origins name one only when the record
/// recorded an egress interface, and on IPv4 only when the socket asked for
/// ancillary data alongside its timestamps. # C: O(1)
pub const fn supports_offender(origin: u8, family_v6: bool, ifindex: u32,
    tstamp_opt_cmsg: bool) -> bool
{
    if origin == SO_EE_ORIGIN_ICMP { return true; }
    if family_v6 && is_icmp_origin(origin) { return true; }
    if origin == SO_EE_ORIGIN_LOCAL { return false; }
    if ifindex == 0 { return false; }
    family_v6 || tstamp_opt_cmsg
}

/// Encode one `sockaddr_in`/`sockaddr_in6` for the socket's family. # C: O(1)
pub fn sockaddr_bytes(addr: IpAddr, port: u16, family_v6: bool, ifindex: u32) -> Vec<u8> {
    if family_v6 {
        let ip = match addr {
            IpAddr::V4(ip) => Ipv6Addr::from_v4_mapped(ip),
            IpAddr::V6(ip) => ip,
        };
        let mut out = alloc::vec![0u8; SOCKADDR_IN6_LEN];
        out[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        out[2..4].copy_from_slice(&port.to_be_bytes());
        out[8..24].copy_from_slice(&ip.0);
        if ip.is_link_local() { out[24..28].copy_from_slice(&ifindex.to_ne_bytes()); }
        return out;
    }
    match addr {
        IpAddr::V4(ip) => {
            let mut out = alloc::vec![0u8; SOCKADDR_IN_LEN];
            out[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            out[2..4].copy_from_slice(&port.to_be_bytes());
            out[4..8].copy_from_slice(&ip.octets());
            out
        }
        IpAddr::V6(ip) => {
            let mut out = alloc::vec![0u8; SOCKADDR_IN6_LEN];
            out[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            out[2..4].copy_from_slice(&port.to_be_bytes());
            out[8..24].copy_from_slice(&ip.0);
            out
        }
    }
}

/// The `msg_name` bytes one record reports, or `None` when the record has no
/// addressable origin and `msg_namelen` must stay zero. # C: O(1)
pub fn name_bytes(entry: &SocketErrorEntry, family_v6: bool) -> Option<Vec<u8>> {
    if !supports_name(entry.origin, family_v6, entry.destination_port) { return None; }
    Some(sockaddr_bytes(entry.destination, entry.destination_port, family_v6, entry.ifindex))
}

/// Encode the 16-byte `sock_extended_err` head of the ancillary record.
/// # C: O(1)
pub fn extended_err_bytes(entry: &SocketErrorEntry) -> [u8; SOCK_EXTENDED_ERR_LEN] {
    let mut out = [0u8; SOCK_EXTENDED_ERR_LEN];
    out[0..4].copy_from_slice(&(entry.errno as u32).to_ne_bytes());
    out[4] = entry.origin;
    out[5] = entry.kind;
    out[6] = entry.code;
    out[8..12].copy_from_slice(&entry.info.to_ne_bytes());
    out[12..16].copy_from_slice(&entry.data.to_ne_bytes());
    out
}

/// Encode the full `IP_RECVERR`/`IPV6_RECVERR` ancillary payload: the
/// extended error followed by the offender sockaddr, which is all zeroes when
/// the record names no offender. # C: O(1)
pub fn errhdr_bytes(entry: &SocketErrorEntry, family_v6: bool, tstamp_opt_cmsg: bool) -> Vec<u8> {
    let mut out = alloc::vec![0u8; SOCK_EXTENDED_ERR_LEN + offender_len(family_v6)];
    out[..SOCK_EXTENDED_ERR_LEN].copy_from_slice(&extended_err_bytes(entry));
    if supports_offender(entry.origin, family_v6, entry.ifindex, tstamp_opt_cmsg) {
        let offender = sockaddr_bytes(entry.offender, 0, family_v6, entry.ifindex);
        out[SOCK_EXTENDED_ERR_LEN..].copy_from_slice(&offender);
    }
    out
}
