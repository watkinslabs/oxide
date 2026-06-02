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
pub mod genetlink;

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
    /// FIFO of pending reply buffers, each already nlmsg-aligned.
    pub rx_queue:  Spinlock<VecDeque<Vec<u8>>, SockLockClass>,
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
    push(&mut msg, &alloc::format!("SEQNUM={}", seq));
    let mut g = UEVENT_LISTENERS.lock();
    g.retain(|w| w.strong_count() > 0);
    let mut n = 0;
    for w in g.iter() {
        if let Some(s) = w.upgrade() { s.enqueue(msg.clone()); n += 1; }
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
        }
    }

    /// Drop a fully-formatted reply buffer onto the RX queue. The
    /// caller has already serialized the nlmsghdr(s) and aligned to
    /// 4-byte boundaries.
    /// # C: O(1) under rx_queue.lock()
    pub fn enqueue(&self, msg: Vec<u8>) {
        self.rx_queue.lock().push_back(msg);
    }

    /// Pop the head reply buffer if present.
    /// # C: O(1) under rx_queue.lock()
    pub fn dequeue(&self) -> Option<Vec<u8>> {
        self.rx_queue.lock().pop_front()
    }

    /// Clone the head reply buffer WITHOUT removing it (MSG_PEEK).
    /// libsystemd's sd-netlink sizes its receive buffer with a
    /// `recvmsg(MSG_PEEK|MSG_TRUNC)` before the real consuming read; the
    /// peek must leave the datagram queued or the next read sees nothing
    /// and sd_netlink times out waiting for the ack.
    /// # C: O(msg len) under rx_queue.lock()
    pub fn peek_front(&self) -> Option<Vec<u8>> {
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
                rtnetlink::handle_getroute(hdr)
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

impl vfs::Inode for NetlinkSocket {
    fn ino(&self) -> vfs::Ino {
        // High tag chosen so netlink inode numbers don't collide
        // with fs / AF_INET socket inode space.
        0x4E4C_534B_0000_0000u64 | (self as *const _ as u64 & 0xFFFF_FFFF) as vfs::Ino
    }
    // Expose the concrete socket so getsockopt(SO_PROTOCOL) reads `protocol`.
    fn as_any(&self) -> Option<&dyn core::any::Any> { Some(self) }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> {
        Err(vfs::VfsError::Enotdir)
    }
    fn read(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        match self.dequeue() {
            Some(reply) => {
                let n = reply.len().min(buf.len());
                buf[..n].copy_from_slice(&reply[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }
    fn write(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        let consumed = buf.len();
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
    fn poll(&self) -> u32 {
        use vfs::{POLL_IN, POLL_OUT};
        let mut mask = POLL_OUT;
        if !self.rx_queue.lock().is_empty() { mask |= POLL_IN; }
        mask
    }
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
}
