extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Socket as SockLockClass, Spinlock};

use crate::netlink_socket::NetlinkSocket;

/// Live `NETLINK_KOBJECT_UEVENT` subscribers (udev/systemd-udevd). Weak so
/// closed sockets drop out. `emit_uevent` enqueues to each.
static UEVENT_LISTENERS: Spinlock<Vec<Weak<NetlinkSocket>>, SockLockClass> =
    Spinlock::new(Vec::new());
/// Monotonic uevent sequence number (`SEQNUM=` in each message).
static UEVENT_SEQNUM: AtomicU32 = AtomicU32::new(1);

#[cfg(feature = "debug-uevent")]
fn trace_uevent_emit(action: &str, devpath: &str, recipients: usize) {
    klog::write_raw(b"[UEV-EMIT action=");
    klog::write_raw(action.as_bytes());
    klog::write_raw(b" devpath=");
    klog::write_raw(devpath.as_bytes());
    klog::write_raw(b" recipients=");
    klog::write_dec_u64(recipients as u64);
    klog::write_raw(b"]\n");
}

/// Current kobject uevent sequence counter exposed through
/// `/sys/kernel/uevent_seqnum`. # C: O(1)
pub fn uevent_seqnum() -> u32 {
    UEVENT_SEQNUM.load(Ordering::Relaxed)
}

/// Register a `NETLINK_KOBJECT_UEVENT` socket to receive broadcast device
/// uevents. Called when such a socket is created.
/// # C: O(N_listeners) — prunes dead weaks.
pub fn register_uevent_listener(sock: &Arc<NetlinkSocket>) {
    let mut g = UEVENT_LISTENERS.lock();
    g.retain(|w| w.strong_count() > 0);
    g.push(Arc::downgrade(sock));
}

/// Broadcast a kobject uevent to every live `NETLINK_KOBJECT_UEVENT`
/// subscriber (`docs/19`). Format is the Linux raw string blob:
/// `"<action>@<devpath>\0ACTION=<action>\0DEVPATH=<devpath>\0
/// SUBSYSTEM=<subsystem>\0SEQNUM=<n>\0"`. udev parses these to build its
/// device model. Returns the number of subscribers reached.
/// # C: O(N_listeners)
pub fn emit_uevent(action: &str, devpath: &str, subsystem: &str) -> usize {
    emit_uevent_with_env(action, devpath, subsystem, &[])
}

/// Broadcast a kobject uevent with extra environment key/value strings such
/// as `DEVNAME=ttyS0` or `MAJOR=4`. Extra entries must already be formatted
/// as `KEY=value`.
/// # C: O(N_listeners + N_extra)
pub fn emit_uevent_with_env(action: &str, devpath: &str, subsystem: &str, extra: &[&str]) -> usize {
    let seq = UEVENT_SEQNUM.fetch_add(1, Ordering::Relaxed);
    let mut msg: Vec<u8> = Vec::with_capacity(96);
    let push = |m: &mut Vec<u8>, s: &str| { m.extend_from_slice(s.as_bytes()); m.push(0); };
    msg.extend_from_slice(action.as_bytes());
    msg.push(b'@');
    msg.extend_from_slice(devpath.as_bytes());
    msg.push(0);
    push(&mut msg, &alloc::format!("ACTION={}", action));
    push(&mut msg, &alloc::format!("DEVPATH={}", devpath));
    push(&mut msg, &alloc::format!("SUBSYSTEM={}", subsystem));
    for entry in extra { push(&mut msg, entry); }
    push(&mut msg, &alloc::format!("SEQNUM={}", seq));
    let targets: Vec<_> = {
        let mut g = UEVENT_LISTENERS.lock();
        g.retain(|w| w.strong_count() > 0);
        g.iter().filter_map(Weak::upgrade).filter(|s| {
            s.groups.load(Ordering::Acquire) & 1 != 0
        }).collect()
    };
    let mut n = 0;
    for s in targets {
        s.enqueue(msg.clone());
        n += 1;
    }
    #[cfg(feature = "debug-uevent")]
    trace_uevent_emit(action, devpath, n);
    n
}

/// UNICAST a uevent-socket message to the single listener whose `port_id`
/// matches `dest_pid` (Linux `netlink_unicast`). Returns 1 if the
/// destination socket was found and delivered, else 0. # C: O(N_listeners)
pub fn unicast_uevent_to_port(dest_pid: u32, msg: &[u8], src_port: u32) -> usize {
    let target = {
        let mut g = UEVENT_LISTENERS.lock();
        g.retain(|w| w.strong_count() > 0);
        g.iter().filter_map(Weak::upgrade)
            .find(|s| s.port_id.load(Ordering::Acquire) == dest_pid)
    };
    let Some(target) = target else { return 0; };
    target.enqueue_from(msg.to_vec(), src_port);
    1
}

/// Re-broadcast a COOKED libudev uevent that a userspace daemon (systemd-udevd)
/// sent on its `NETLINK_KOBJECT_UEVENT` socket to the monitor clients.
/// Returns the number of monitors reached.
/// # C: O(N_listeners)
pub fn rebroadcast_cooked_uevent(msg: &[u8], dest_groups: u32, sender: &NetlinkSocket) -> usize {
    let targets: Vec<_> = {
        let mut g = UEVENT_LISTENERS.lock();
        g.retain(|w| w.strong_count() > 0);
        g.iter().filter_map(Weak::upgrade).filter(|s| {
            if core::ptr::eq(Arc::as_ptr(s), sender as *const NetlinkSocket) { return false; }
            let grp = s.groups.load(Ordering::Acquire);
            grp & 1 == 0 && grp & dest_groups != 0
        }).collect()
    };
    let mut n = 0;
    let src_port = sender.port_id.load(Ordering::Acquire);
    for s in targets {
        s.enqueue_from(msg.to_vec(), src_port);
        n += 1;
    }
    n
}

/// Live `NETLINK_ROUTE` sockets eligible for multicast delivery (`ip
/// monitor`, systemd-networkd, NetworkManager). Weak so closed sockets
/// drop out. `rtnl_multicast` enqueues to those whose `groups` mask
/// carries the target group bit.
static RTNL_LISTENERS: Spinlock<Vec<Weak<NetlinkSocket>>, SockLockClass> =
    Spinlock::new(Vec::new());

/// Register a `NETLINK_ROUTE` socket for multicast. Called at socket
/// creation. Subscription (group bits) is set later via bind nl_groups or
/// NETLINK_ADD_MEMBERSHIP. # C: O(N_listeners) — prunes dead weaks.
pub fn register_rtnl_listener(sock: &Arc<NetlinkSocket>) {
    let mut g = RTNL_LISTENERS.lock();
    g.retain(|w| w.strong_count() > 0);
    g.push(Arc::downgrade(sock));
}

/// Broadcast `msg` in the calling task's network namespace.
/// Returns the number of sockets reached. # C: O(N_listeners)
pub fn rtnl_multicast(group: u32, msg: &[u8]) -> usize {
    rtnl_multicast_in(net::netdev::current_net_ns(), group, msg)
}

/// Broadcast `msg` (kernel-originated nlmsg(s): seq 0, pid 0) to every
/// `NETLINK_ROUTE` socket in `net_ns` subscribed to `group`.
/// Returns the number of sockets reached. # C: O(N_listeners)
pub fn rtnl_multicast_in(net_ns: u64, group: u32, msg: &[u8]) -> usize {
    if group == 0 || group > 32 { return 0; }
    let bit = 1u32 << (group - 1);
    let targets: Vec<_> = {
        let mut g = RTNL_LISTENERS.lock();
        g.retain(|w| w.strong_count() > 0);
        g.iter().filter_map(Weak::upgrade).filter(|s| {
            s.net_ns.id().as_u64() == net_ns
                && s.groups.load(Ordering::Acquire) & bit != 0
        }).collect()
    };
    let mut n = 0;
    for s in targets {
        s.enqueue(msg.to_vec());
        n += 1;
    }
    n
}
