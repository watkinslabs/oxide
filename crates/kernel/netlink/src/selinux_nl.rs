// SELinux event notifications (`NETLINK_SELINUX`).
//
// Kernel-to-userspace ONLY. The kernel multicasts two events to
// `SELNLGRP_AVC` — the enforcement mode changed, and a policy was loaded —
// and the userspace AVC in `libselinux` opens a socket on this protocol, binds
// that group, and reads them so it can drop cached decisions the new policy
// may answer differently. A datagram sent BY userspace on this protocol
// reaches no handler: the family registers no receive path, so a send with a
// kernel destination is accepted and dropped, exactly as a protocol with no
// `input` callback behaves. A read with nothing pending blocks, or reports
// `EAGAIN` on the non-blocking socket the AVC opens.
//
// Ungated so the wire format and the delivery rule run under hosted
// `cargo test` (`docs/53`): userspace decides whether to flush its cache from
// these bytes, and a wrong header or a message delivered to an unsubscribed
// socket is invisible to a kernel-only build.

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use sync::{Socket as SockLockClass, Spinlock};

use crate::netlink_socket::NetlinkSocket;
use crate::wire::Nlmsghdr;

/// `selinux_netlink.h` message types, groups and payload shapes.
pub mod uapi {
    /// First SELinux netlink message type.
    pub const SELNL_MSG_BASE: u16 = 0x10;
    /// Enforcement mode changed; payload is `selnl_msg_setenforce`.
    pub const SELNL_MSG_SETENFORCE: u16 = SELNL_MSG_BASE;
    /// Policy loaded; payload is `selnl_msg_policyload`.
    pub const SELNL_MSG_POLICYLOAD: u16 = SELNL_MSG_BASE + 1;

    /// Group number of the AVC notification group (1-based, as every netlink
    /// group number is). `libselinux` binds it as the `nl_groups` bit
    /// `SELNL_GRP_AVC` = 0x1.
    pub const SELNLGRP_AVC: u32 = 1;
    /// Highest group this protocol defines. Netlink floors every protocol's
    /// subscribable group count at a full word regardless.
    pub const SELNLGRP_MAX: u32 = 1;

    /// `struct selnl_msg_setenforce { __s32 val; }`.
    pub const SETENFORCE_BYTES: usize = 4;
    /// `struct selnl_msg_policyload { __u32 seqno; }`.
    pub const POLICYLOAD_BYTES: usize = 4;
}

/// Live `NETLINK_SELINUX` subscribers (the userspace AVC in every process
/// linked against `libselinux`). Weak so a closed socket drops out.
static SELINUX_LISTENERS: Spinlock<Vec<Weak<NetlinkSocket>>, SockLockClass> =
    Spinlock::new(Vec::new());

/// Register a `NETLINK_SELINUX` socket to receive the notifications. Called
/// at socket creation; the group subscription itself arrives later, through
/// `bind` `nl_groups` or `NETLINK_ADD_MEMBERSHIP`.
/// # C: O(N_listeners) — prunes dead weaks.
pub fn register_selinux_listener(sock: &Arc<NetlinkSocket>) {
    let mut g = SELINUX_LISTENERS.lock();
    g.retain(|w| w.strong_count() > 0);
    g.push(Arc::downgrade(sock));
}

/// One kernel-originated notification: header with port 0, sequence 0, no
/// flags, followed by the fixed four-byte payload. `nlmsg_len` covers header
/// plus payload and needs no alignment round — a four-byte payload is already
/// aligned. # C: O(1)
fn encode(msgtype: u16, payload: [u8; 4]) -> Vec<u8> {
    let len = Nlmsghdr::SIZE + payload.len();
    let mut msg = vec![0u8; len];
    Nlmsghdr {
        nlmsg_len: len as u32,
        nlmsg_type: msgtype,
        nlmsg_flags: 0,
        nlmsg_seq: 0,
        nlmsg_pid: 0,
    }.write_to(&mut msg);
    msg[Nlmsghdr::SIZE..].copy_from_slice(&payload);
    msg
}

/// `SELNL_MSG_SETENFORCE` for one enforcement mode. # C: O(1)
pub fn encode_setenforce(val: i32) -> Vec<u8> {
    encode(uapi::SELNL_MSG_SETENFORCE, val.to_ne_bytes())
}

/// `SELNL_MSG_POLICYLOAD` for one policy sequence number. # C: O(1)
pub fn encode_policyload(seqno: u32) -> Vec<u8> {
    encode(uapi::SELNL_MSG_POLICYLOAD, seqno.to_ne_bytes())
}

/// Deliver one notification to every `NETLINK_SELINUX` socket in the INITIAL
/// network namespace subscribed to `SELNLGRP_AVC`. Returns the number of
/// sockets reached.
///
/// The kernel end of this protocol exists once, in the initial namespace, so a
/// socket in another namespace subscribes to a group nothing broadcasts to —
/// the same shape as every other protocol whose kernel socket is
/// `init_net`-only. # C: O(N_listeners)
fn broadcast(msg: &[u8]) -> usize {
    let subscribed: Vec<_> = {
        let mut g = SELINUX_LISTENERS.lock();
        g.retain(|w| w.strong_count() > 0);
        g.iter().filter_map(Weak::upgrade)
            .filter(|s| s.groups.test(uapi::SELNLGRP_AVC))
            .collect()
    };
    // Nothing subscribed: the notification is a no-op, and answering it
    // without reaching for the namespace registry keeps a caller on a kernel
    // with no AVC socket open — every boot before the first `libselinux`
    // process — free of that lookup.
    if subscribed.is_empty() { return 0; }
    let init_ns = network_namespace::initial().id().as_u64();
    let mut n = 0;
    for s in subscribed.into_iter().filter(|s| s.net_ns.id().as_u64() == init_ns) {
        if s.enqueue_multicast(msg.to_vec(), uapi::SELNLGRP_AVC, None) { n += 1; }
    }
    n
}

/// The enforcement mode changed. Returns the number of subscribers reached.
/// # C: O(N_listeners)
pub fn notify_setenforce(enforcing: bool) -> usize {
    broadcast(&encode_setenforce(i32::from(enforcing)))
}

/// A policy was loaded, or a boolean commit made every cached decision stale.
/// Carries the policy sequence number the change produced, which is what
/// userspace compares against the one it last saw.
/// # C: O(N_listeners)
pub fn notify_policyload(seqno: u32) -> usize {
    broadcast(&encode_policyload(seqno))
}

#[cfg(test)]
#[path = "netlink_tests/selinux_nl.rs"]
mod tests;
