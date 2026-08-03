// Per-socket `NETLINK_F_*` flag word and the SOL_NETLINK option decision.
//
// The decision is a pure function of (protocol, optname) so it is hosted-
// testable: the syscall shim only copies the value in and reports the errno.
// One flag word is the single owner of every boolean SOL_NETLINK option —
// `NETLINK_NO_ENOBUFS` reads and writes the same bit `getsockopt` reports.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::proto;
use crate::sockopt as opt;

/// `NETLINK_PKTINFO`: attach `struct nl_pktinfo` to every received message.
pub const F_RECV_PKTINFO: u32 = 1 << 0;
/// `NETLINK_BROADCAST_ERROR`: report broadcast delivery failure to the sender.
pub const F_BROADCAST_SEND_ERROR: u32 = 1 << 1;
/// `NETLINK_NO_ENOBUFS`: suppress the multicast-overrun error report.
pub const F_RECV_NO_ENOBUFS: u32 = 1 << 2;
/// `NETLINK_LISTEN_ALL_NSID`: receive multicast from every network namespace.
pub const F_LISTEN_ALL_NSID: u32 = 1 << 3;
/// `NETLINK_CAP_ACK`: truncate the `NLMSG_ERROR` payload to the request header.
pub const F_CAP_ACK: u32 = 1 << 4;
/// `NETLINK_EXT_ACK`: carry extended-ack attributes on `NLMSG_ERROR`.
pub const F_EXT_ACK: u32 = 1 << 5;
/// `NETLINK_GET_STRICT_CHK`: validate dump requests strictly and honour their
/// header filters.
pub const F_STRICT_CHK: u32 = 1 << 6;

/// The `NETLINK_F_*` word of one socket.
pub struct NetlinkFlags(AtomicU32);

impl NetlinkFlags {
    /// # C: O(1)
    pub const fn new() -> Self { Self(AtomicU32::new(0)) }

    /// # C: O(1)
    pub fn get(&self, bit: u32) -> bool { self.0.load(Ordering::Acquire) & bit != 0 }

    /// # C: O(1)
    pub fn assign(&self, bit: u32, on: bool) {
        if on { self.0.fetch_or(bit, Ordering::AcqRel); }
        else  { self.0.fetch_and(!bit, Ordering::AcqRel); }
    }
}

impl Default for NetlinkFlags { fn default() -> Self { Self::new() } }

/// Protocols whose control socket permits multicast subscription without
/// `CAP_NET_ADMIN` (`NL_CFG_F_NONROOT_RECV`). Everything else — netfilter
/// among them — requires the capability to (un)subscribe a group.
/// # C: O(1)
pub fn nonroot_recv(protocol: u16) -> bool {
    matches!(protocol,
        proto::NETLINK_ROUTE | proto::NETLINK_GENERIC | proto::NETLINK_SOCK_DIAG
        | proto::NETLINK_AUDIT | proto::NETLINK_KOBJECT_UEVENT)
}

/// What `setsockopt(SOL_NETLINK, optname, …)` must do.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SetAction {
    /// Assign one flag bit from `val != 0`.
    Flag(u32),
    /// Assign one flag bit, but only for a caller holding `CAP_NET_BROADCAST`
    /// in the socket namespace's user namespace.
    PrivilegedFlag(u32),
    /// Subscribe (`true`) or unsubscribe (`false`) one group NUMBER.
    Membership { add: bool },
    /// Assign `F_RECV_NO_ENOBUFS`, and on enable clear the congestion latch.
    NoEnobufs,
    /// Not a settable option: `ENOPROTOOPT`.
    Unknown,
}

/// # C: O(1)
pub fn set_action(optname: u64) -> SetAction {
    match optname {
        opt::NETLINK_PKTINFO           => SetAction::Flag(F_RECV_PKTINFO),
        opt::NETLINK_ADD_MEMBERSHIP    => SetAction::Membership { add: true },
        opt::NETLINK_DROP_MEMBERSHIP   => SetAction::Membership { add: false },
        opt::NETLINK_BROADCAST_ERROR   => SetAction::Flag(F_BROADCAST_SEND_ERROR),
        opt::NETLINK_NO_ENOBUFS        => SetAction::NoEnobufs,
        opt::NETLINK_LISTEN_ALL_NSID   => SetAction::PrivilegedFlag(F_LISTEN_ALL_NSID),
        opt::NETLINK_CAP_ACK           => SetAction::Flag(F_CAP_ACK),
        opt::NETLINK_EXT_ACK           => SetAction::Flag(F_EXT_ACK),
        opt::NETLINK_GET_STRICT_CHK    => SetAction::Flag(F_STRICT_CHK),
        _                              => SetAction::Unknown,
    }
}

/// What `getsockopt(SOL_NETLINK, optname, …)` must report.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum GetAnswer {
    /// One `int`: whether the flag bit is set.
    Flag(u32),
    /// The subscription bitmap as `u32` words.
    Memberships,
    /// Not a readable option: `ENOPROTOOPT`.
    Unknown,
}

/// # C: O(1)
pub fn get_answer(optname: u64) -> GetAnswer {
    match optname {
        opt::NETLINK_PKTINFO           => GetAnswer::Flag(F_RECV_PKTINFO),
        opt::NETLINK_BROADCAST_ERROR   => GetAnswer::Flag(F_BROADCAST_SEND_ERROR),
        opt::NETLINK_NO_ENOBUFS        => GetAnswer::Flag(F_RECV_NO_ENOBUFS),
        opt::NETLINK_LIST_MEMBERSHIPS  => GetAnswer::Memberships,
        opt::NETLINK_LISTEN_ALL_NSID   => GetAnswer::Flag(F_LISTEN_ALL_NSID),
        opt::NETLINK_CAP_ACK           => GetAnswer::Flag(F_CAP_ACK),
        opt::NETLINK_EXT_ACK           => GetAnswer::Flag(F_EXT_ACK),
        opt::NETLINK_GET_STRICT_CHK    => GetAnswer::Flag(F_STRICT_CHK),
        _                              => GetAnswer::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_settable_optname_maps_to_its_linux_action() {
        assert_eq!(set_action(opt::NETLINK_PKTINFO), SetAction::Flag(F_RECV_PKTINFO));
        assert_eq!(set_action(opt::NETLINK_ADD_MEMBERSHIP), SetAction::Membership { add: true });
        assert_eq!(set_action(opt::NETLINK_DROP_MEMBERSHIP), SetAction::Membership { add: false });
        assert_eq!(set_action(opt::NETLINK_BROADCAST_ERROR), SetAction::Flag(F_BROADCAST_SEND_ERROR));
        assert_eq!(set_action(opt::NETLINK_NO_ENOBUFS), SetAction::NoEnobufs);
        assert_eq!(set_action(opt::NETLINK_LISTEN_ALL_NSID), SetAction::PrivilegedFlag(F_LISTEN_ALL_NSID));
        assert_eq!(set_action(opt::NETLINK_CAP_ACK), SetAction::Flag(F_CAP_ACK));
        assert_eq!(set_action(opt::NETLINK_EXT_ACK), SetAction::Flag(F_EXT_ACK));
        assert_eq!(set_action(opt::NETLINK_GET_STRICT_CHK), SetAction::Flag(F_STRICT_CHK));
    }

    #[test]
    fn the_packet_ring_options_are_not_settable() {
        // Linux compiled out `NETLINK_RX_RING`/`NETLINK_TX_RING`; both fall to
        // the switch default rather than being silently accepted.
        assert_eq!(set_action(opt::NETLINK_RX_RING), SetAction::Unknown);
        assert_eq!(set_action(opt::NETLINK_TX_RING), SetAction::Unknown);
    }

    #[test]
    fn list_memberships_is_read_only_and_get_strict_chk_is_readable() {
        assert_eq!(set_action(opt::NETLINK_LIST_MEMBERSHIPS), SetAction::Unknown);
        assert_eq!(get_answer(opt::NETLINK_LIST_MEMBERSHIPS), GetAnswer::Memberships);
        assert_eq!(get_answer(opt::NETLINK_GET_STRICT_CHK), GetAnswer::Flag(F_STRICT_CHK));
    }

    #[test]
    fn membership_is_write_only() {
        assert_eq!(get_answer(opt::NETLINK_ADD_MEMBERSHIP), GetAnswer::Unknown);
        assert_eq!(get_answer(opt::NETLINK_DROP_MEMBERSHIP), GetAnswer::Unknown);
    }

    #[test]
    fn an_unknown_optname_is_neither_settable_nor_readable() {
        assert_eq!(set_action(u64::MAX), SetAction::Unknown);
        assert_eq!(get_answer(u64::MAX), GetAnswer::Unknown);
        assert_eq!(set_action(0), SetAction::Unknown);
    }

    #[test]
    fn no_enobufs_reads_back_through_the_same_bit_it_writes() {
        let flags = NetlinkFlags::new();
        assert!(!flags.get(F_RECV_NO_ENOBUFS));
        flags.assign(F_RECV_NO_ENOBUFS, true);
        assert!(flags.get(F_RECV_NO_ENOBUFS));
        assert_eq!(get_answer(opt::NETLINK_NO_ENOBUFS), GetAnswer::Flag(F_RECV_NO_ENOBUFS));
        flags.assign(F_RECV_NO_ENOBUFS, false);
        assert!(!flags.get(F_RECV_NO_ENOBUFS));
    }

    #[test]
    fn the_flag_bits_do_not_overlap() {
        let bits = [F_RECV_PKTINFO, F_BROADCAST_SEND_ERROR, F_RECV_NO_ENOBUFS,
                    F_LISTEN_ALL_NSID, F_CAP_ACK, F_EXT_ACK, F_STRICT_CHK];
        let mut seen = 0u32;
        for b in bits { assert_eq!(seen & b, 0); seen |= b; }
        assert_eq!(seen.count_ones(), bits.len() as u32);
    }

    #[test]
    fn setting_one_flag_leaves_every_other_alone() {
        let flags = NetlinkFlags::new();
        flags.assign(F_EXT_ACK, true);
        flags.assign(F_STRICT_CHK, true);
        flags.assign(F_EXT_ACK, false);
        assert!(!flags.get(F_EXT_ACK));
        assert!(flags.get(F_STRICT_CHK));
    }

    #[test]
    fn the_control_protocols_permit_unprivileged_subscription() {
        assert!(nonroot_recv(proto::NETLINK_ROUTE));
        assert!(nonroot_recv(proto::NETLINK_GENERIC));
        assert!(nonroot_recv(proto::NETLINK_SOCK_DIAG));
        assert!(nonroot_recv(proto::NETLINK_AUDIT));
        assert!(nonroot_recv(proto::NETLINK_KOBJECT_UEVENT));
        // netfilter declares no `NL_CFG_F_NONROOT_RECV`.
        assert!(!nonroot_recv(proto::NETLINK_NETFILTER));
    }
}
