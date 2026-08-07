// Generic-netlink multicast fan-out.
//
// A genetlink group is addressed by a FLAT group id, so delivery is "every
// NETLINK_GENERIC socket in the target network namespace whose subscription
// bitmap carries that id, except the excluded port". Producers name a
// family-relative group INDEX; the family's `mcgrp_offset` maps it to the id.
// Delivering to nobody is `ESRCH`, which is how the kernel distinguishes "no
// listener" from a real send failure.

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sync::{Socket as SockLockClass, Spinlock};

use crate::netlink_socket::NetlinkSocket;
use super::family::GenlFamily;

/// Multicast failure in Linux's errno vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenlMcastError {
    /// Group index is outside the family's group table.
    Einval,
    /// Nobody was subscribed to the group.
    Esrch,
}

/// Live `NETLINK_GENERIC` sockets eligible for multicast delivery. Weak so
/// closed sockets drop out on the next fan-out.
static GENL_LISTENERS: Spinlock<Vec<Weak<NetlinkSocket>>, SockLockClass> =
    Spinlock::new(Vec::new());

/// Register a `NETLINK_GENERIC` socket for multicast. Subscription happens
/// later through bind `nl_groups` or `NETLINK_ADD_MEMBERSHIP`.
/// # C: O(N_listeners) — prunes dead weaks.
pub fn register_genl_listener(sock: &Arc<NetlinkSocket>) {
    let mut g = GENL_LISTENERS.lock();
    g.retain(|w| w.strong_count() > 0);
    g.push(Arc::downgrade(sock));
}

/// Deliver `msg` to every subscriber of the flat group id. `net_ns` of `None`
/// crosses every namespace (`allns`); `exclude_portid` skips the sender, which
/// is `0` for kernel-originated messages and therefore excludes nothing.
/// # C: O(N_listeners)
fn deliver(net_ns: Option<u64>, group_id: u32, msg: &[u8], exclude_portid: u32) -> usize {
    let targets: Vec<_> = {
        let mut g = GENL_LISTENERS.lock();
        g.retain(|w| w.strong_count() > 0);
        g.iter().filter_map(Weak::upgrade).filter(|s| {
            if let Some(ns) = net_ns { if s.net_ns.id().as_u64() != ns { return false; } }
            if exclude_portid != 0 && s.port_id.load(Ordering::Acquire) == exclude_portid {
                return false;
            }
            s.groups.test(group_id)
        }).collect()
    };
    let mut n = 0;
    for s in targets {
        if s.enqueue_multicast(msg.to_vec(), group_id, None) { n += 1; }
    }
    n
}

/// `genlmsg_multicast_netns`: broadcast a family message inside ONE network
/// namespace. `group` is the family-relative index. # C: O(N_listeners)
pub fn genlmsg_multicast_netns(
    family: &GenlFamily, net_ns: u64, group: usize, msg: &[u8], exclude_portid: u32,
) -> Result<usize, GenlMcastError> {
    let Some(group_id) = family.group_id(group) else { return Err(GenlMcastError::Einval); };
    match deliver(Some(net_ns), group_id, msg, exclude_portid) {
        0 => Err(GenlMcastError::Esrch),
        n => Ok(n),
    }
}

/// `genlmsg_multicast_allns`: broadcast a family message to subscribers in
/// EVERY network namespace, reporting `ESRCH` only when no namespace had one.
/// # C: O(N_listeners)
pub fn genlmsg_multicast_allns(
    family: &GenlFamily, group: usize, msg: &[u8], exclude_portid: u32,
) -> Result<usize, GenlMcastError> {
    let Some(group_id) = family.group_id(group) else { return Err(GenlMcastError::Einval); };
    match deliver(None, group_id, msg, exclude_portid) {
        0 => Err(GenlMcastError::Esrch),
        n => Ok(n),
    }
}

/// `genlmsg_multicast`: `genlmsg_multicast_netns` against the initial network
/// namespace, which is where kernel-originated family events originate.
/// # C: O(N_listeners)
pub fn genlmsg_multicast(
    family: &GenlFamily, group: usize, msg: &[u8], exclude_portid: u32,
) -> Result<usize, GenlMcastError> {
    genlmsg_multicast_netns(family, initial_net_ns(), group, msg, exclude_portid)
}

/// Initial network namespace id — the `init_net` genetlink events target.
/// # C: O(1)
pub fn initial_net_ns() -> u64 { network_namespace::initial().id().as_u64() }
