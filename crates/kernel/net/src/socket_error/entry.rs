//! One extended-error queue record and the per-origin constructors that
//! decide which `sock_extended_err` fields each origin owns.

use alloc::vec::Vec;

use crate::addr::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::uapi::{SO_EE_CODE_ZEROCOPY_COPIED, SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_ICMP6,
    SO_EE_ORIGIN_LOCAL, SO_EE_ORIGIN_TIMESTAMPING, SO_EE_ORIGIN_TXTIME, SO_EE_ORIGIN_ZEROCOPY};

/// One Linux extended-error queue record for `MSG_ERRQUEUE`.
///
/// `offender` is the source of the notification (the ICMP speaker); the
/// `destination`/`destination_port` pair is the address of the packet that
/// provoked it, which `recvmsg` reports through `msg_name`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketErrorEntry {
    pub errno: i32,
    pub origin: u8,
    pub kind: u8,
    pub code: u8,
    pub info: u32,
    pub data: u32,
    pub offender: IpAddr,
    pub destination: IpAddr,
    pub destination_port: u16,
    pub ifindex: u32,
    pub payload: Vec<u8>,
}

/// The unspecified address of the family a destination belongs to. # C: O(1)
fn unspecified_like(destination: IpAddr) -> IpAddr {
    match destination {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::ANY),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::ANY),
    }
}

impl SocketErrorEntry {
    /// Record produced by a received ICMP or ICMPv6 error. # C: O(1)
    pub fn icmp(errno: i32, v6: bool, kind: u8, code: u8, info: u32, offender: IpAddr,
        destination: IpAddr, destination_port: u16, ifindex: u32, payload: Vec<u8>) -> Self
    {
        Self {
            errno,
            origin: if v6 { SO_EE_ORIGIN_ICMP6 } else { SO_EE_ORIGIN_ICMP },
            kind, code, info, data: 0,
            offender, destination, destination_port, ifindex, payload,
        }
    }

    /// Record a locally detected transmit failure produces. `info` carries the
    /// path MTU for the size failures that report one. # C: O(1)
    pub fn local(errno: i32, destination: IpAddr, destination_port: u16, info: u32) -> Self {
        Self {
            errno, origin: SO_EE_ORIGIN_LOCAL, kind: 0, code: 0, info, data: 0,
            offender: unspecified_like(destination),
            destination, destination_port, ifindex: 0, payload: Vec::new(),
        }
    }

    /// Record one transmit timestamp: `ee_info` selects which timestamp this
    /// is, `ee_data` carries the sender-assigned key. # C: O(1)
    pub fn timestamping(tstype: u32, tskey: u32, family_v6: bool, ifindex: u32) -> Self {
        let any = if family_v6 { IpAddr::V6(Ipv6Addr::ANY) } else { IpAddr::V4(Ipv4Addr::ANY) };
        Self {
            errno: syscall::errno::Errno::Enomsg as i32,
            origin: SO_EE_ORIGIN_TIMESTAMPING,
            kind: 0, code: 0, info: tstype, data: tskey,
            offender: any, destination: any, destination_port: 0, ifindex, payload: Vec::new(),
        }
    }

    /// Record one zero-copy send completion covering identifiers `lo..=hi`.
    /// A completion that had to fall back to copying carries the copied code.
    /// # C: O(1)
    pub fn zerocopy(lo: u32, hi: u32, copied: bool, family_v6: bool) -> Self {
        let any = if family_v6 { IpAddr::V6(Ipv6Addr::ANY) } else { IpAddr::V4(Ipv4Addr::ANY) };
        Self {
            errno: 0, origin: SO_EE_ORIGIN_ZEROCOPY, kind: 0,
            code: if copied { SO_EE_CODE_ZEROCOPY_COPIED } else { 0 },
            info: lo, data: hi,
            offender: any, destination: any, destination_port: 0, ifindex: 0, payload: Vec::new(),
        }
    }

    /// Record one transmit-time scheduling failure. The requested transmit
    /// time is split low half into `ee_info`, high half into `ee_data`.
    /// # C: O(1)
    pub fn txtime(errno: i32, code: u8, txtime: u64, family_v6: bool) -> Self {
        let any = if family_v6 { IpAddr::V6(Ipv6Addr::ANY) } else { IpAddr::V4(Ipv4Addr::ANY) };
        Self {
            errno, origin: SO_EE_ORIGIN_TXTIME, kind: 0, code,
            info: txtime as u32, data: (txtime >> 32) as u32,
            offender: any, destination: any, destination_port: 0, ifindex: 0, payload: Vec::new(),
        }
    }

    /// Receive-memory this record charges against the socket budget. # C: O(1)
    pub fn charged_bytes(&self) -> usize {
        self.payload.len() + super::uapi::SOCK_ERRQUEUE_RECORD_OVERHEAD
    }

    /// Extend a queued zero-copy range by `len` identifiers when the new range
    /// starts exactly at the queued one's end. # C: O(1)
    pub fn extend_zerocopy(&mut self, lo: u32, len: u32) -> bool {
        if self.origin != SO_EE_ORIGIN_ZEROCOPY { return false; }
        let (old_lo, old_hi) = (self.info as u64, self.data as u64);
        if old_hi.wrapping_sub(old_lo) + 1 + len as u64 >= 1u64 << 32 { return false; }
        if lo as u64 != old_hi + 1 { return false; }
        self.data = self.data.wrapping_add(len);
        true
    }
}
