// Netlink socket family (`AF_NETLINK` = 16) per Linux
// `include/uapi/linux/netlink.h`. v1 surface is the framing +
// dispatch substrate that `ip(8)`, DHCP clients, nftables, and
// any future "configure the iface" tool plug into.
//
// Wire format
//   `struct nlmsghdr` (16 bytes, host-endian) prefixes every message.
//   `nlmsghdr.nlmsg_type` (e.g. RTM_GETLINK, RTM_NEWADDR) picks a
//   handler. Multi-message replies end with NLMSG_DONE.
//
// Protocols
//   Each `socket(AF_NETLINK, SOCK_RAW, protocol)` call selects a
//   protocol family (NETLINK_ROUTE, NETLINK_GENERIC, NETLINK_KOBJECT_-
//   UEVENT, ...). Per-protocol message-type tables route messages to
//   handler fn pointers registered at boot. F88 ships the scaffold;
//   per-protocol handlers land in follow-up F89+ PRs.

#![no_std]

extern crate alloc;

pub mod rtnetlink;
mod rtnetlink_lookup;
pub mod rtnetlink_rule;
pub mod genetlink;
pub mod mcast;
pub mod sock_diag;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use sync::{Spinlock, Socket as SockLockClass};

/// Function signature for an external protocol handler. Receives
/// one nlmsghdr-prefixed request buffer, returns the reply bytes
/// to push onto the socket's RX queue. Used by NETLINK_NETFILTER
/// (and any future protocol whose handler lives in a sibling
/// crate) — netlink can't depend on those crates directly without
/// circular deps, so they install their handler here.
pub type ProtoHandler = fn(&[u8]) -> Vec<u8>;

static NETFILTER_HANDLER: AtomicPtr<()> =
    AtomicPtr::new(core::ptr::null_mut());

/// Install the NETLINK_NETFILTER protocol handler. Idempotent;
/// the netfilter crate calls this once at boot. # C: O(1)
pub fn install_netfilter_handler(f: ProtoHandler) {
    NETFILTER_HANDLER.store(f as *mut (), Ordering::Release);
}

fn invoke_netfilter(msg: &[u8]) -> Vec<u8> {
    let raw = NETFILTER_HANDLER.load(Ordering::Acquire);
    if raw.is_null() {
        // No handler installed: bare NLMSG_DONE ack.
        if let Some(hdr) = Nlmsghdr::parse(msg) {
            let mut done = alloc::vec![0u8; Nlmsghdr::SIZE];
            Nlmsghdr::done(hdr.nlmsg_seq, hdr.nlmsg_pid).write_to(&mut done);
            return done;
        }
        return alloc::vec::Vec::new();
    }
    // SAFETY: raw was installed via install_netfilter_handler with
    // the documented `fn(&[u8]) -> Vec<u8>` signature.
    let f: ProtoHandler = unsafe { core::mem::transmute(raw) };
    f(msg)
}

/// `AF_NETLINK` numeric. Used by sys_socket dispatch.
pub const AF_NETLINK: u16 = 16;

/// `NETLINK_*` protocol family ids per `linux/netlink.h`.
pub mod proto {
    pub const NETLINK_ROUTE:          u16 =  0;
    pub const NETLINK_USERSOCK:       u16 =  2;
    pub const NETLINK_FIREWALL:       u16 =  3;
    pub const NETLINK_SOCK_DIAG:      u16 =  4;
    pub const NETLINK_NFLOG:          u16 =  5;
    pub const NETLINK_XFRM:           u16 =  6;
    pub const NETLINK_SELINUX:        u16 =  7;
    pub const NETLINK_ISCSI:          u16 =  8;
    pub const NETLINK_AUDIT:          u16 =  9;
    pub const NETLINK_FIB_LOOKUP:     u16 = 10;
    pub const NETLINK_CONNECTOR:      u16 = 11;
    pub const NETLINK_NETFILTER:      u16 = 12;
    pub const NETLINK_IP6_FW:         u16 = 13;
    pub const NETLINK_DNRTMSG:        u16 = 14;
    pub const NETLINK_KOBJECT_UEVENT: u16 = 15;
    pub const NETLINK_GENERIC:        u16 = 16;
    pub const NETLINK_SCSITRANSPORT:  u16 = 18;
    pub const NETLINK_ECRYPTFS:       u16 = 19;
    pub const NETLINK_RDMA:           u16 = 20;
    pub const NETLINK_CRYPTO:         u16 = 21;
}

/// `struct nlmsghdr` flags per `linux/netlink.h`.
pub mod flags {
    pub const NLM_F_REQUEST:   u16 = 0x0001;
    pub const NLM_F_MULTI:     u16 = 0x0002;
    pub const NLM_F_ACK:       u16 = 0x0004;
    pub const NLM_F_ECHO:      u16 = 0x0008;
    pub const NLM_F_DUMP_INTR: u16 = 0x0010;
    // GET request modifiers:
    pub const NLM_F_ROOT:      u16 = 0x0100;
    pub const NLM_F_MATCH:     u16 = 0x0200;
    pub const NLM_F_ATOMIC:    u16 = 0x0400;
    pub const NLM_F_DUMP:      u16 = NLM_F_ROOT | NLM_F_MATCH;
    // NEW request modifiers:
    pub const NLM_F_REPLACE:   u16 = 0x0100;
    pub const NLM_F_EXCL:      u16 = 0x0200;
    pub const NLM_F_CREATE:    u16 = 0x0400;
    pub const NLM_F_APPEND:    u16 = 0x0800;
}

/// Reserved `nlmsg_type` values. Per-protocol types start at 16.
pub mod msg {
    pub const NLMSG_NOOP:    u16 = 1;
    pub const NLMSG_ERROR:   u16 = 2;
    pub const NLMSG_DONE:    u16 = 3;
    pub const NLMSG_OVERRUN: u16 = 4;
}

/// 16-byte `struct nlmsghdr` (host-endian; Linux netlink runs on
/// the local byte order).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Nlmsghdr {
    pub nlmsg_len:   u32, // length including this header
    pub nlmsg_type:  u16, // message type (NLMSG_* or per-protocol)
    pub nlmsg_flags: u16, // NLM_F_* bitmask
    pub nlmsg_seq:   u32, // sequence (echoed in reply)
    pub nlmsg_pid:   u32, // sender port id (0 = kernel)
}

impl Nlmsghdr {
    pub const SIZE: usize = 16;

    /// Decode the leading header out of a buffer. Caller validates
    /// `buf.len() >= Nlmsghdr::SIZE` first.
    /// # C: O(1)
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE { return None; }
        let nlmsg_len   = u32::from_ne_bytes(buf[0..4].try_into().ok()?);
        let nlmsg_type  = u16::from_ne_bytes(buf[4..6].try_into().ok()?);
        let nlmsg_flags = u16::from_ne_bytes(buf[6..8].try_into().ok()?);
        let nlmsg_seq   = u32::from_ne_bytes(buf[8..12].try_into().ok()?);
        let nlmsg_pid   = u32::from_ne_bytes(buf[12..16].try_into().ok()?);
        Some(Self { nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid })
    }

    /// Serialize into the leading bytes of `buf`.
    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[ 0.. 4].copy_from_slice(&self.nlmsg_len.to_ne_bytes());
        buf[ 4.. 6].copy_from_slice(&self.nlmsg_type.to_ne_bytes());
        buf[ 6.. 8].copy_from_slice(&self.nlmsg_flags.to_ne_bytes());
        buf[ 8..12].copy_from_slice(&self.nlmsg_seq.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.nlmsg_pid.to_ne_bytes());
    }

    /// Build a NLMSG_DONE terminator with the given seq/pid.
    /// # C: O(1)
    pub fn done(seq: u32, pid: u32) -> Self {
        Self {
            nlmsg_len:   Self::SIZE as u32,
            nlmsg_type:  msg::NLMSG_DONE,
            nlmsg_flags: 0,
            nlmsg_seq:   seq,
            nlmsg_pid:   pid,
        }
    }
}

/// Netlink message round to 4 bytes (NLMSG_ALIGNTO).
/// # C: O(1)
#[inline]
pub fn nlmsg_align(len: usize) -> usize { (len + 3) & !3 }

static NEXT_KERNEL_PID: AtomicU32 = AtomicU32::new(1);

/// Allocate a fresh port-id for a newly-opened socket. PID 0 is
/// reserved for kernel-originated messages.
/// # C: O(1)
pub fn alloc_port_id() -> u32 {
    NEXT_KERNEL_PID.fetch_add(1, Ordering::AcqRel)
}

/// AF_NETLINK socket. Owns an in-memory RX queue of nlmsg-aligned
/// reply buffers. Writes (sendmsg/sendto) parse the leading
/// `nlmsghdr`, dispatch by `(protocol, nlmsg_type)` into the
/// per-protocol handler registry, and push any reply onto the RX
/// queue. Reads (recvmsg/recvfrom) pop the head reply.
pub struct NetlinkSocket {
    pub protocol:  u16,
    pub port_id:   AtomicU32,
    /// Group-mask set via `bind`. Subscribe to multicast groups
    /// (e.g. RTM_GETLINK NEWLINK notifications). v1 stores but
    /// doesn't yet publish notifications.
    pub groups:    AtomicU32,
    /// FIFO of pending reply datagrams, each already nlmsg-aligned. The `u32`
    /// is the SENDER's port_id (Linux `NETLINK_CB(skb).portid`; 0 = kernel), so
    /// a consuming recvmsg can stamp the true source pid + SCM_CREDENTIALS —
    /// required for systemd-udevd's manager to identify a worker's completion.
    pub rx_queue:  Spinlock<VecDeque<(Vec<u8>, u32)>, SockLockClass>,
    /// Per-fd epoll/poll subscribers (shared into the socket's inode via
    /// `make_netlink_socket_inode`'s `poll_subs_arc`). `enqueue` calls
    /// `notify()` so a task parked in `epoll_wait`/`ppoll` on this netlink fd
    /// wakes when a datagram (uevent, rtnetlink reply) arrives. Without this a
    /// uevent delivered to systemd-udevd's monitor socket sat in `rx_queue`
    /// while udevd slept forever — no coldplug, no /run/udev/data, no seat.
    pub poll_subs: alloc::sync::Arc<vfs::PollSubscribers>,
}

/// Live `NETLINK_KOBJECT_UEVENT` subscribers (udev/systemd-udevd). Weak so
/// closed sockets drop out. `emit_uevent` enqueues to each.
static UEVENT_LISTENERS: Spinlock<Vec<alloc::sync::Weak<NetlinkSocket>>, SockLockClass>
    = Spinlock::new(Vec::new());
/// Monotonic uevent sequence number (`SEQNUM=` in each message).
static UEVENT_SEQNUM: AtomicU32 = AtomicU32::new(1);

/// Register a `NETLINK_KOBJECT_UEVENT` socket to receive broadcast device
/// uevents. Called when such a socket is created.
/// # C: O(N_listeners) — prunes dead weaks.
pub fn register_uevent_listener(sock: &alloc::sync::Arc<NetlinkSocket>) {
    let mut g = UEVENT_LISTENERS.lock();
    g.retain(|w| w.strong_count() > 0);
    g.push(alloc::sync::Arc::downgrade(sock));
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
    // Header line "<action>@<devpath>" (no trailing NUL until the env list).
    msg.extend_from_slice(action.as_bytes());
    msg.push(b'@');
    msg.extend_from_slice(devpath.as_bytes());
    msg.push(0);
    push(&mut msg, &alloc::format!("ACTION={}", action));
    push(&mut msg, &alloc::format!("DEVPATH={}", devpath));
    push(&mut msg, &alloc::format!("SUBSYSTEM={}", subsystem));
    for entry in extra { push(&mut msg, entry); }
    push(&mut msg, &alloc::format!("SEQNUM={}", seq));
    let mut g = UEVENT_LISTENERS.lock();
    g.retain(|w| w.strong_count() > 0);
    let mut n = 0;
    for w in g.iter() {
        if let Some(s) = w.upgrade() {
            // Raw kernel uevents go to NETLINK_KOBJECT_UEVENT group 1 ONLY
            // (Linux `netlink_broadcast(uevent_sock, …, group=1)`). systemd-
            // udevd binds nl_groups=1 (KERNEL) to receive them, applies rules,
            // and re-broadcasts COOKED libudev messages (with the "libudev"
            // magic header) for its clients. systemd PID1's sd-device monitor
            // binds nl_groups=0 (it consumes only cooked messages). Delivering
            // a RAW kernel blob to that group-0/cooked monitor makes libudev
            // peek it, fail the magic check, and never consume it → the socket
            // stays poll-readable and PID1 busy-loops ("Looping too fast").
            // Deliver only to group-1 members (udevd); skip everyone else.
            if (s.groups.load(Ordering::Acquire) & 1) == 0 { continue; }
            s.enqueue(msg.clone());
            n += 1;
        }
    }
    n
}

/// UNICAST a uevent-socket message to the single listener whose `port_id`
/// matches `dest_pid` (Linux `netlink_unicast`). systemd-udevd's per-event
/// worker signals COMPLETION to the manager by sending the processed device
/// ADDRESSED to the manager's netlink port (`nl_pid = manager port`,
/// `nl_groups = 0`) — a unicast, NOT a group broadcast. Without honouring the
/// destination pid, that completion was group-broadcast (or dropped), the
/// manager never learned the event finished, and it RE-DISPATCHED each event to
/// a fresh worker ~20× (measured) — starving the queue so card0 was never
/// processed → no master-of-seat tag → CAN_GRAPHICAL=0 → no gdm greeter.
/// `src_port` is stamped as the datagram's sender so the manager's recvmsg sees
/// the worker's pid in the source address / SCM_CREDENTIALS. Returns 1 if the
/// destination socket was found and delivered, else 0. # C: O(N_listeners)
pub fn unicast_uevent_to_port(dest_pid: u32, msg: &[u8], src_port: u32) -> usize {
    let mut g = UEVENT_LISTENERS.lock();
    g.retain(|w| w.strong_count() > 0);
    for w in g.iter() {
        if let Some(s) = w.upgrade() {
            if s.port_id.load(Ordering::Acquire) == dest_pid {
                s.enqueue_from(msg.to_vec(), src_port);
                return 1;
            }
        }
    }
    0
}

/// Re-broadcast a COOKED libudev uevent that a userspace daemon (systemd-udevd)
/// sent on its `NETLINK_KOBJECT_UEVENT` socket to the monitor clients
/// (systemd PID1 / logind). This is the userspace→userspace multicast half of
/// the uevent path: the kernel emits RAW events to group 1 (udevd); udevd
/// applies rules and re-broadcasts the COOKED message (with the "libudev"
/// magic header) to a monitor group; that cooked message must reach the monitor
/// subscribers here. Deliver to every uevent listener whose group mask
/// intersects `dest_groups`, PLUS group-0 monitors (systemd's sd-device monitor
/// binds `nl_groups=0`), EXCEPT the sender itself and EXCEPT group-1-only
/// sockets (udevd's raw receivers — they must not get the cooked echo).
/// Returns the number of monitors reached.
/// # C: O(N_listeners)
pub fn rebroadcast_cooked_uevent(msg: &[u8], dest_groups: u32, sender: &NetlinkSocket) -> usize {
    let mut g = UEVENT_LISTENERS.lock();
    g.retain(|w| w.strong_count() > 0);
    let mut n = 0;
    for w in g.iter() {
        if let Some(s) = w.upgrade() {
            if core::ptr::eq(alloc::sync::Arc::as_ptr(&s), sender as *const NetlinkSocket) { continue; }
            let grp = s.groups.load(Ordering::Acquire);
            // Skip udevd's raw group-1 receivers; deliver to cooked monitors
            // (matching dest group, or the group-0 monitors systemd uses).
            if (grp & 1) != 0 { continue; }
            if grp != 0 && (grp & dest_groups) == 0 { continue; }
            s.enqueue_from(msg.to_vec(), sender.port_id.load(Ordering::Acquire));
            n += 1;
        }
    }
    n
}

/// Live `NETLINK_ROUTE` sockets eligible for multicast delivery (`ip
/// monitor`, systemd-networkd, NetworkManager). Weak so closed sockets
/// drop out. `rtnl_multicast` enqueues to those whose `groups` mask
/// carries the target group bit. Mirrors Linux's per-netns netlink table.
static RTNL_LISTENERS: Spinlock<Vec<alloc::sync::Weak<NetlinkSocket>>, SockLockClass>
    = Spinlock::new(Vec::new());

/// Register a `NETLINK_ROUTE` socket for multicast. Called at socket
/// creation. Subscription (group bits) is set later via bind nl_groups or
/// NETLINK_ADD_MEMBERSHIP. # C: O(N_listeners) — prunes dead weaks.
pub fn register_rtnl_listener(sock: &alloc::sync::Arc<NetlinkSocket>) {
    let mut g = RTNL_LISTENERS.lock();
    g.retain(|w| w.strong_count() > 0);
    g.push(alloc::sync::Arc::downgrade(sock));
}

/// Broadcast `msg` (kernel-originated nlmsg(s): seq 0, pid 0) to every
/// `NETLINK_ROUTE` socket subscribed to `group` (an `RTNLGRP_*` number;
/// the socket's `groups` bitmask carries bit `group-1`, the legacy
/// `RTMGRP_*` layout). Mirrors `nlmsg_multicast`/`netlink_broadcast`.
/// Returns the number of sockets reached. # C: O(N_listeners)
pub fn rtnl_multicast(group: u32, msg: &[u8]) -> usize {
    if group == 0 || group > 32 { return 0; }
    let bit = 1u32 << (group - 1);
    let mut g = RTNL_LISTENERS.lock();
    g.retain(|w| w.strong_count() > 0);
    let mut n = 0;
    for w in g.iter() {
        if let Some(s) = w.upgrade() {
            if (s.groups.load(Ordering::Acquire) & bit) != 0 {
                s.enqueue(msg.to_vec());
                n += 1;
            }
        }
    }
    n
}

impl NetlinkSocket {
    /// # C: O(1)
    pub fn new(protocol: u16) -> Self {
        Self {
            protocol,
            port_id:  AtomicU32::new(alloc_port_id()),
            groups:   AtomicU32::new(0),
            rx_queue: Spinlock::new(VecDeque::new()),
            poll_subs: alloc::sync::Arc::new(vfs::PollSubscribers::new()),
        }
    }

    /// `bind` nl_groups: subscribe to the given group bitmask (legacy
    /// `RTMGRP_*` layout, bit `g-1` = group `g`). # C: O(1)
    pub fn set_group_mask(&self, mask: u32) { self.groups.store(mask, Ordering::Release); }
    /// `NETLINK_ADD_MEMBERSHIP`: subscribe to one `RTNLGRP_*` group. # C: O(1)
    pub fn add_membership(&self, group: u32) {
        if group != 0 && group <= 32 { self.groups.fetch_or(1u32 << (group - 1), Ordering::AcqRel); }
    }
    /// `NETLINK_DROP_MEMBERSHIP`: unsubscribe one group. # C: O(1)
    pub fn drop_membership(&self, group: u32) {
        if group != 0 && group <= 32 { self.groups.fetch_and(!(1u32 << (group - 1)), Ordering::AcqRel); }
    }

    /// Drop a fully-formatted reply buffer onto the RX queue. The
    /// caller has already serialized the nlmsghdr(s) and aligned to
    /// 4-byte boundaries.
    /// # C: O(1) under rx_queue.lock()
    pub fn enqueue(&self, msg: Vec<u8>) { self.enqueue_from(msg, 0); }

    /// As [`enqueue`] but records the datagram's SENDER port_id (0 = kernel),
    /// so a consuming recvmsg stamps the true source pid + SCM_CREDENTIALS.
    /// # C: O(1) under rx_queue.lock()
    pub fn enqueue_from(&self, msg: Vec<u8>, src_port: u32) {
        self.rx_queue.lock().push_back((msg, src_port));
        // Wake any epoll/ppoll waiter on this fd (Linux `sk_data_ready` →
        // `wake_up_interruptible` on the netlink socket's sleep queue). A queued
        // datagram is useless if the consumer (systemd-udevd's sd-event loop)
        // never wakes to read it.
        self.poll_subs.notify();
    }

    /// Pop the head (datagram, sender_port) if present.
    /// # C: O(1) under rx_queue.lock()
    pub fn dequeue(&self) -> Option<(Vec<u8>, u32)> {
        self.rx_queue.lock().pop_front()
    }

    /// Clone the head (datagram, sender_port) WITHOUT removing it (MSG_PEEK).
    /// libsystemd's sd-netlink sizes its receive buffer with a
    /// `recvmsg(MSG_PEEK|MSG_TRUNC)` before the real consuming read; the
    /// peek must leave the datagram queued or the next read sees nothing
    /// and sd_netlink times out waiting for the ack.
    /// # C: O(msg len) under rx_queue.lock()
    pub fn peek_front(&self) -> Option<(Vec<u8>, u32)> {
        self.rx_queue.lock().front().cloned()
    }

    /// Dispatch a single parsed request header. Routes by
    /// `(self.protocol, hdr.nlmsg_type)` into the appropriate
    /// per-protocol handler; on no match emits a NLMSG_DONE
    /// terminator so dump-style clients don't hang.
    /// # C: O(reply build)
    fn handle_one(&self, hdr: &Nlmsghdr, msg: &[u8]) {
        let reply = match (self.protocol, hdr.nlmsg_type) {
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETLINK) => {
                rtnetlink::handle_getlink(hdr)
            }
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETADDR) => {
                rtnetlink::handle_getaddr(hdr)
            }
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWADDR) => {
                rtnetlink::handle_newaddr(hdr, msg)
            }
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELADDR) => {
                rtnetlink::handle_deladdr(hdr, msg)
            }
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETROUTE) => {
                rtnetlink::handle_getroute(hdr, msg)
            }
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETRULE) => {
                rtnetlink_rule::handle_getrule(hdr, msg)
            }
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWRULE) => {
                rtnetlink_rule::handle_newrule(hdr, msg)
            }
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELRULE) => {
                rtnetlink_rule::handle_delrule(hdr, msg)
            }
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWROUTE) => {
                rtnetlink::handle_newroute(hdr, msg)
            }
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELROUTE) => {
                rtnetlink::handle_delroute(hdr, msg)
            }
            // RTM_NEWLINK/SETLINK: bring iface up/down — really mutates the
            // registry's flag state (see handle_setlink).
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWLINK)
            | (proto::NETLINK_ROUTE, rtnetlink::RTM_SETLINK) => {
                rtnetlink::handle_setlink(hdr, msg)
            }
            (proto::NETLINK_GENERIC, _) => genetlink::handle(msg),
            (proto::NETLINK_NETFILTER, _) => invoke_netfilter(msg),
            (proto::NETLINK_SOCK_DIAG, sock_diag::SOCK_DIAG_BY_FAMILY)
            | (proto::NETLINK_SOCK_DIAG, sock_diag::TCPDIAG_GETSOCK) => {
                sock_diag::handle(hdr, msg)
            }
            _ => {
                // A request with NLM_F_ACK expects an NLMSG_ERROR ack, not
                // NLMSG_DONE (which terminates a dump). Without this an
                // ack-waiting sd_netlink_call never completes.
                if (hdr.nlmsg_flags & flags::NLM_F_ACK) != 0 {
                    rtnetlink::nlmsg_ack_pub(hdr, 0)
                } else {
                    let mut done = alloc::vec![0u8; Nlmsghdr::SIZE];
                    Nlmsghdr::done(hdr.nlmsg_seq, hdr.nlmsg_pid).write_to(&mut done);
                    done
                }
            }
        };
        // Stamp the destination port (this socket's nl_pid) into every
        // nlmsghdr in the reply. sd_netlink DROPS any non-broadcast reply
        // whose `nlmsg_pid != nl->sockaddr.nl.nl_pid` (the port it learned
        // via getsockname) — netlink-socket.c parse_message_one. Echoing
        // the request's pid (often 0) mismatched the socket's port, so the
        // reply was silently dropped and async callbacks (loopback_setup's
        // RTM_SETLINK) never fired and blocked to their timeout. The kernel
        // addresses a reply to the requester's port, so set nlmsg_pid to
        // this socket's port_id (== what getsockname reports).
        let mut reply = reply;
        let port = self.port_id.load(Ordering::Acquire);
        let mut off = 0usize;
        while off + Nlmsghdr::SIZE <= reply.len() {
            let len = u32::from_ne_bytes([reply[off], reply[off+1], reply[off+2], reply[off+3]]) as usize;
            if len < Nlmsghdr::SIZE || off + len > reply.len() { break; }
            reply[off + 12..off + 16].copy_from_slice(&port.to_ne_bytes());
            off += nlmsg_align(len);
        }
        self.enqueue(reply);
    }
}

/// `ino()` high tag identifying a netlink socket inode (so its inode numbers
/// don't collide with fs / AF_INET socket inode space). # C: O(1)
pub const NETLINK_INO_TAG: u64 = 0x4E4C_534B_0000_0000;

impl NetlinkSocket {
    /// Pop one queued reply into `buf` (datagram semantics; `0` = empty).
    /// # C: O(msg len)
    pub fn read(&self, buf: &mut [u8]) -> vfs::KResult<usize> {
        match self.dequeue() {
            Some((reply, _src)) => {
                let n = reply.len().min(buf.len());
                buf[..n].copy_from_slice(&reply[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }

    /// Parse + dispatch every nlmsghdr in `buf`; returns the bytes consumed
    /// (the whole buffer, mirroring Linux netlink `sendmsg`). # C: O(buf len)
    pub fn write(&self, buf: &[u8]) -> vfs::KResult<usize> {
        self.write_to_groups(buf, 0)
    }

    /// Write one userspace netlink datagram with the destination group mask
    /// supplied by sockaddr_nl.nl_groups. Kobject udev's cooked rebroadcasts
    /// are plain libudev blobs, not nlmsghdr messages, so multicast them
    /// before falling back to the request/reply dispatcher.
    /// # C: O(buf len + listeners)
    pub fn write_to_groups(&self, buf: &[u8], dest_groups: u32) -> vfs::KResult<usize> {
        let consumed = buf.len();
        if self.protocol == proto::NETLINK_KOBJECT_UEVENT {
            let is_cooked = buf.len() >= 8 && &buf[..8] == b"libudev\0";
            if is_cooked || dest_groups != 0 {
                rebroadcast_cooked_uevent(buf, dest_groups, self);
                return Ok(consumed);
            }
        }
        let mut off = 0;
        while off + Nlmsghdr::SIZE <= buf.len() {
            let hdr = match Nlmsghdr::parse(&buf[off..]) {
                Some(h) => h,
                None    => break,
            };
            let msg_len = hdr.nlmsg_len as usize;
            if msg_len < Nlmsghdr::SIZE || off + msg_len > buf.len() {
                break;
            }
            self.handle_one(&hdr, &buf[off..off + msg_len]);
            off += nlmsg_align(msg_len);
        }
        Ok(consumed)
    }

    /// `f_op->poll` readiness: always writable, readable when the rx queue is
    /// non-empty. # C: O(1)
    pub fn poll(&self) -> u32 {
        use vfs::{POLL_IN, POLL_OUT};
        let mut mask = POLL_OUT;
        if !self.rx_queue.lock().is_empty() { mask |= POLL_IN; }
        mask
    }
}

/// `file_operations` for a netlink-socket inode — delegates the data path to
/// the `NetlinkSocket` stored in `i_private`.
struct NetlinkFileOps;

impl vfs::FileOps for NetlinkFileOps {
    fn read(&self, inode: &vfs::Inode, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        match inode.private::<NetlinkSocket>() {
            Some(s) => s.read(buf),
            None => Err(vfs::VfsError::Einval),
        }
    }
    fn write(&self, inode: &vfs::Inode, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        match inode.private::<NetlinkSocket>() {
            Some(s) => s.write(buf),
            None => Err(vfs::VfsError::Einval),
        }
    }
    fn poll(&self, inode: &vfs::Inode) -> u32 {
        inode.private::<NetlinkSocket>().map(|s| s.poll()).unwrap_or(vfs::POLL_OUT)
    }
}

/// Build the `Arc<Inode>` wrapping a netlink socket fd. The socket lives in
/// `i_private` (recover it with [`netlink_from_inode`]); the inode's `ino()`
/// carries [`NETLINK_INO_TAG`] OR'd with the socket pointer's low bits.
/// # C: O(1)
pub fn make_netlink_socket_inode(sock: alloc::sync::Arc<NetlinkSocket>) -> vfs::InodeRef {
    let ino = NETLINK_INO_TAG | (alloc::sync::Arc::as_ptr(&sock) as u64 & 0xFFFF_FFFF);
    // S_IFSOCK so fstat()/sd_is_socket() recognise the netlink fd as a
    // socket — systemd-udevd's listen_fds() rejects the inherited
    // NETLINK_KOBJECT_UEVENT fd otherwise (-EINVAL). Linux netlink fds
    // are S_IFSOCK.
    // Share the socket's PollSubscribers into the inode so `epoll_ctl(ADD)`
    // subscribes to the SAME object `enqueue().notify()` wakes (mirrors the
    // AF_INET/AF_UNIX poll_subs_arc wiring). Without this the inode's default
    // subscribers were a distinct object and a uevent enqueue never reached the
    // epoll (udevd slept through every device event).
    let subs = sock.poll_subs.clone();
    vfs::InodeBuilder::new(ino, vfs::mk_mode(vfs::FileType::Socket, 0o600),
        vfs::default_inode_ops(), alloc::sync::Arc::new(NetlinkFileOps))
        .private(sock)
        .poll_subs_arc(subs)
        .build()
}

/// Recover the `&NetlinkSocket` stored in a netlink-socket inode's `i_private`
/// (e.g. `getsockopt(SO_PROTOCOL)` reading `protocol`). # C: O(1)
pub fn netlink_from_inode(inode: &vfs::Inode) -> Option<&NetlinkSocket> {
    inode.private::<NetlinkSocket>()
}

/// Recover an owning `Arc<NetlinkSocket>` from a netlink-socket inode. # C: O(1)
pub fn netlink_arc_from_inode(inode: &vfs::InodeRef) -> Option<alloc::sync::Arc<NetlinkSocket>> {
    inode.i_private().clone().downcast::<NetlinkSocket>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nlmsghdr_roundtrip() {
        let h = Nlmsghdr {
            nlmsg_len:   24,
            nlmsg_type:  0x12,
            nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
            nlmsg_seq:   0xDEAD_BEEF,
            nlmsg_pid:   42,
        };
        let mut buf = [0u8; Nlmsghdr::SIZE];
        h.write_to(&mut buf);
        let p = Nlmsghdr::parse(&buf).unwrap();
        assert_eq!(p.nlmsg_len,   24);
        assert_eq!(p.nlmsg_type,  0x12);
        assert_eq!(p.nlmsg_flags, flags::NLM_F_REQUEST | flags::NLM_F_DUMP);
        assert_eq!(p.nlmsg_seq,   0xDEAD_BEEF);
        assert_eq!(p.nlmsg_pid,   42);
    }

    #[test]
    fn nlmsg_align_rounds_up_to_4() {
        assert_eq!(nlmsg_align(0),  0);
        assert_eq!(nlmsg_align(1),  4);
        assert_eq!(nlmsg_align(3),  4);
        assert_eq!(nlmsg_align(4),  4);
        assert_eq!(nlmsg_align(5),  8);
        assert_eq!(nlmsg_align(13), 16);
    }

    #[test]
    fn port_ids_are_unique() {
        let a = alloc_port_id();
        let b = alloc_port_id();
        assert_ne!(a, b);
    }

    #[test]
    fn membership_bits_map_group_minus_one() {
        let s = NetlinkSocket::new(proto::NETLINK_ROUTE);
        s.add_membership(1);  // RTNLGRP_LINK → bit 0
        s.add_membership(5);  // RTNLGRP_IPV4_IFADDR → bit 4
        assert_eq!(s.groups.load(Ordering::Acquire), (1 << 0) | (1 << 4));
        s.drop_membership(1);
        assert_eq!(s.groups.load(Ordering::Acquire), 1 << 4);
        s.set_group_mask(0xF);  // bind nl_groups replaces the mask
        assert_eq!(s.groups.load(Ordering::Acquire), 0xF);
        s.add_membership(0);  // group 0 is a no-op (RTNLGRP_NONE)
        assert_eq!(s.groups.load(Ordering::Acquire), 0xF);
    }

    #[test]
    fn rtnl_multicast_delivers_only_to_subscribers() {
        use alloc::sync::Arc;
        let a = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE)); // RTNLGRP_LINK
        let b = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE)); // RTNLGRP_IPV4_IFADDR
        a.add_membership(1);
        b.add_membership(5);
        register_rtnl_listener(&a);
        register_rtnl_listener(&b);
        let msg = alloc::vec![0xABu8; 8];

        let n = rtnl_multicast(1, &msg);  // RTNLGRP_LINK
        assert_eq!(n, 1);
        assert!(a.dequeue().is_some());   // subscriber got it
        assert!(b.dequeue().is_none());   // non-subscriber did not

        let n = rtnl_multicast(5, &msg);  // RTNLGRP_IPV4_IFADDR
        assert_eq!(n, 1);
        assert!(a.dequeue().is_none());
        assert!(b.dequeue().is_some());

        assert_eq!(rtnl_multicast(0, &msg), 0);  // RTNLGRP_NONE reaches nobody
    }

    #[test]
    fn raw_uevent_delivers_only_to_kernel_group() {
        use alloc::sync::Arc;
        let udevd = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        let monitor = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        udevd.set_group_mask(1);   // KERNEL group
        monitor.set_group_mask(0); // cooked monitor
        register_uevent_listener(&udevd);
        register_uevent_listener(&monitor);

        let n = emit_uevent("add", "/devices/virtual/drm/card0", "drm");
        assert_eq!(n, 1);
        assert!(udevd.dequeue().is_some());
        assert!(monitor.dequeue().is_none());
    }

    #[test]
    fn cooked_uevent_reaches_only_udev_group_monitors() {
        use alloc::sync::Arc;
        let sender = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        let kernel_listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        let group0_monitor = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        let udev_monitor = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        sender.set_group_mask(2);
        kernel_listener.set_group_mask(1);
        group0_monitor.set_group_mask(0);
        udev_monitor.set_group_mask(2);
        register_uevent_listener(&sender);
        register_uevent_listener(&kernel_listener);
        register_uevent_listener(&group0_monitor);
        register_uevent_listener(&udev_monitor);

        let msg = b"libudev\0ACTION=add\0SUBSYSTEM=drm\0";
        let n = rebroadcast_cooked_uevent(msg, 2, &sender);
        assert_eq!(n, 2);
        assert!(sender.dequeue().is_none());
        assert!(kernel_listener.dequeue().is_none());
        assert_eq!(group0_monitor.dequeue().map(|(m, _)| m).as_deref(), Some(&msg[..]));
        assert_eq!(udev_monitor.dequeue().map(|(m, _)| m).as_deref(), Some(&msg[..]));
    }

    #[test]
    fn unicast_reaches_only_target_port_with_sender_stamped() {
        use alloc::sync::Arc;
        // systemd-udevd manager dispatches an event to ONE worker by addressing
        // the worker's netlink port (nl_pid), not a group broadcast. A broadcast
        // would make every worker process every event (the ~20× amplification
        // that starved card0). Verify unicast hits only the target + carries the
        // sender pid so the receiver can identify who sent it.
        let manager = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        let worker_a = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        let worker_b = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        worker_a.set_group_mask(0);
        worker_b.set_group_mask(0);
        register_uevent_listener(&manager);
        register_uevent_listener(&worker_a);
        register_uevent_listener(&worker_b);

        let mgr_port = manager.port_id.load(Ordering::Acquire);
        let a_port = worker_a.port_id.load(Ordering::Acquire);
        let msg = b"libudev\0ACTION=add\0SEQNUM=42\0";
        let delivered = unicast_uevent_to_port(a_port, msg, mgr_port);
        assert_eq!(delivered, 1, "unicast found the target port");
        assert!(worker_b.dequeue().is_none(), "non-target worker got nothing");
        let got = worker_a.dequeue().expect("target worker got the datagram");
        assert_eq!(got.0.as_slice(), &msg[..]);
        assert_eq!(got.1, mgr_port, "sender port stamped for the receiver");
    }
}
