extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use network_namespace::NetworkNamespaceRef;
use sync::{Socket as SockLockClass, Spinlock};

use crate::{flags, genetlink, invoke_netfilter, listeners, proto, rtnetlink, rtnetlink_rule, sock_diag, Nlmsghdr, nlmsg_align};
use crate::wire::alloc_port_id;

/// AF_NETLINK socket. Owns an in-memory RX queue of nlmsg-aligned
/// reply buffers.
pub struct NetlinkSocket {
    pub protocol: u16,
    pub net_ns: NetworkNamespaceRef,
    pub port_id: AtomicU32,
    pub groups: AtomicU32,
    /// Canonical Linux `sk_err`.
    pub error: net::SocketError,
    pub rx_queue: Spinlock<VecDeque<(Vec<u8>, u32)>, SockLockClass>,
    pub poll_subs: Arc<vfs::PollSubscribers>,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
}

impl NetlinkSocket {
    fn rtnl_mutation(typ: u16) -> bool {
        matches!(typ,
            rtnetlink::RTM_NEWADDR | rtnetlink::RTM_DELADDR
            | rtnetlink::RTM_NEWROUTE | rtnetlink::RTM_DELROUTE
            | rtnetlink::RTM_NEWRULE | rtnetlink::RTM_DELRULE
            | rtnetlink::RTM_NEWLINK | rtnetlink::RTM_SETLINK)
    }

    fn may_mutate_rtnl(&self) -> bool {
        #[cfg(target_os = "oxide-kernel")]
        { sched::current().is_some_and(|cur| nscg::has_net_admin_for(cur, &self.net_ns)) }
        #[cfg(not(target_os = "oxide-kernel"))]
        { true }
    }

    /// Create a socket retaining its concrete network namespace owner. # C: O(1)
    pub fn new(protocol: u16, net_ns: &NetworkNamespaceRef) -> Self {
        Self {
            protocol,
            net_ns: Arc::clone(net_ns),
            port_id: AtomicU32::new(alloc_port_id()),
            groups: AtomicU32::new(0),
            error: net::SocketError::new(),
            rx_queue: Spinlock::new(VecDeque::new()),
            poll_subs: Arc::new(vfs::PollSubscribers::new()),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
        }
    }

    /// `bind` nl_groups: subscribe to the given group bitmask.
    /// # C: O(1)
    pub fn set_group_mask(&self, mask: u32) { self.groups.store(mask, Ordering::Release); }

    /// Record the latest positive Linux receive errno until it is consumed. # C: O(1)
    pub fn set_pending_recv_error(&self, errno: i32) -> bool {
        let _queue = self.rx_queue.lock();
        let changed = self.error.set(errno);
        if changed {
            #[cfg(target_os = "oxide-kernel")]
            self.waiters.wake_all();
            self.poll_subs.notify_mask(vfs::POLL_ERR);
        }
        changed
    }

    /// Consume the pending positive Linux receive errno, or zero. # C: O(1)
    pub fn take_pending_recv_error(&self) -> i32 {
        self.error.take()
    }

    /// Observe whether a socket error is pending without consuming it. # C: O(1)
    pub fn has_pending_recv_error(&self) -> bool { self.error.has() }

    /// `NETLINK_ADD_MEMBERSHIP`: subscribe to one `RTNLGRP_*` group. # C: O(1)
    pub fn add_membership(&self, group: u32) {
        if group != 0 && group <= 32 { self.groups.fetch_or(1u32 << (group - 1), Ordering::AcqRel); }
    }

    /// `NETLINK_DROP_MEMBERSHIP`: unsubscribe one group. # C: O(1)
    pub fn drop_membership(&self, group: u32) {
        if group != 0 && group <= 32 { self.groups.fetch_and(!(1u32 << (group - 1)), Ordering::AcqRel); }
    }

    /// Drop a fully-formatted reply buffer onto the RX queue.
    /// # C: O(1) under rx_queue.lock()
    pub fn enqueue(&self, msg: Vec<u8>) { self.enqueue_from(msg, 0); }

    /// As [`enqueue`] but records the datagram's SENDER port_id (0 = kernel).
    /// # C: O(1) under rx_queue.lock()
    pub fn enqueue_from(&self, msg: Vec<u8>, src_port: u32) {
        self.rx_queue.lock().push_back((msg, src_port));
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        self.poll_subs.notify();
    }

    /// Pop the head (datagram, sender_port) if present.
    /// # C: O(1) under rx_queue.lock()
    pub fn dequeue(&self) -> Option<(Vec<u8>, u32)> {
        self.rx_queue.lock().pop_front()
    }

    /// Clone the head (datagram, sender_port) WITHOUT removing it (MSG_PEEK).
    /// # C: O(msg len) under rx_queue.lock()
    pub fn peek_front(&self) -> Option<(Vec<u8>, u32)> {
        self.rx_queue.lock().front().cloned()
    }

    /// Length of the next readable netlink datagram for `FIONREAD`. # C: O(1)
    pub fn front_len(&self) -> u32 {
        self.rx_queue.lock().front().map(|(m, _)| m.len() as u32).unwrap_or(0)
    }

    /// Dispatch a single parsed request header.
    /// # C: O(reply build)
    fn handle_one(&self, hdr: &Nlmsghdr, msg: &[u8]) {
        let net_ns = self.net_ns.id().as_u64();
        let reply = if self.protocol == proto::NETLINK_ROUTE && Self::rtnl_mutation(hdr.nlmsg_type)
            && !self.may_mutate_rtnl() {
            rtnetlink::nlmsg_ack_pub(hdr, -1)
        } else { match (self.protocol, hdr.nlmsg_type) {
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETLINK) => rtnetlink::handle_getlink_in(net_ns, hdr),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETADDR) => rtnetlink::handle_getaddr_in(net_ns, hdr),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWADDR) => rtnetlink::handle_newaddr_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELADDR) => rtnetlink::handle_deladdr_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETROUTE) => rtnetlink::handle_getroute_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETRULE) => rtnetlink_rule::handle_getrule_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWRULE) => rtnetlink_rule::handle_newrule_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELRULE) => rtnetlink_rule::handle_delrule_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWROUTE) => rtnetlink::handle_newroute_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELROUTE) => rtnetlink::handle_delroute_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWLINK)
            | (proto::NETLINK_ROUTE, rtnetlink::RTM_SETLINK) => rtnetlink::handle_setlink_in(net_ns, hdr, msg),
            (proto::NETLINK_GENERIC, _) => genetlink::handle(msg),
            (proto::NETLINK_AUDIT, _) => crate::audit::handle(hdr, msg),
            (proto::NETLINK_NETFILTER, _) => invoke_netfilter(msg),
            (proto::NETLINK_SOCK_DIAG, sock_diag::SOCK_DIAG_BY_FAMILY)
            | (proto::NETLINK_SOCK_DIAG, sock_diag::TCPDIAG_GETSOCK) =>
                sock_diag::handle_in(net_ns, hdr, msg),
            _ => {
                if (hdr.nlmsg_flags & flags::NLM_F_ACK) != 0 {
                    rtnetlink::nlmsg_ack_pub(hdr, 0)
                } else {
                    let mut done = alloc::vec![0u8; Nlmsghdr::SIZE];
                    Nlmsghdr::done(hdr.nlmsg_seq, hdr.nlmsg_pid).write_to(&mut done);
                    done
                }
            }
        }};
        let mut reply = reply;
        let port = self.port_id.load(Ordering::Acquire);
        let mut off = 0usize;
        while off + Nlmsghdr::SIZE <= reply.len() {
            let len = u32::from_ne_bytes([reply[off], reply[off + 1], reply[off + 2], reply[off + 3]]) as usize;
            if len < Nlmsghdr::SIZE || off + len > reply.len() { break; }
            reply[off + 12..off + 16].copy_from_slice(&port.to_ne_bytes());
            off += nlmsg_align(len);
        }
        self.enqueue(reply);
    }

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

    /// Parse + dispatch every nlmsghdr in `buf`; returns the bytes consumed.
    /// # C: O(buf len)
    pub fn write(&self, buf: &[u8]) -> vfs::KResult<usize> {
        self.write_to_groups(buf, 0)
    }

    /// Write one userspace netlink datagram with the destination group mask.
    /// # C: O(buf len + listeners)
    pub fn write_to_groups(&self, buf: &[u8], dest_groups: u32) -> vfs::KResult<usize> {
        let consumed = buf.len();
        if self.protocol == proto::NETLINK_KOBJECT_UEVENT {
            let is_cooked = buf.len() >= 8 && &buf[..8] == b"libudev\0";
            if is_cooked || dest_groups != 0 {
                listeners::rebroadcast_cooked_uevent(buf, dest_groups, self);
                return Ok(consumed);
            }
        }
        let mut off = 0;
        while off + Nlmsghdr::SIZE <= buf.len() {
            let hdr = match Nlmsghdr::parse(&buf[off..]) {
                Some(h) => h,
                None => break,
            };
            let msg_len = hdr.nlmsg_len as usize;
            if msg_len < Nlmsghdr::SIZE || off + msg_len > buf.len() { break; }
            self.handle_one(&hdr, &buf[off..off + msg_len]);
            off += nlmsg_align(msg_len);
        }
        Ok(consumed)
    }

    /// `f_op->poll` readiness: always writable, readable when the rx queue is
    /// non-empty. # C: O(1)
    pub fn poll(&self) -> u32 {
        use vfs::{POLL_ERR, POLL_IN, POLL_OUT};
        let mut mask = POLL_OUT;
        if !self.rx_queue.lock().is_empty() { mask |= POLL_IN; }
        if self.has_pending_recv_error() { mask |= POLL_ERR; }
        mask
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::NetlinkSocket;
    use crate::{flags, proto, rtnetlink, Nlmsghdr};
    use crate::netlink_tests::test_namespace;

    fn request(ty: u16, body: &[u8]) -> alloc::vec::Vec<u8> {
        let hdr = Nlmsghdr {
            nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
            nlmsg_type: ty,
            nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
            nlmsg_seq: 71,
            nlmsg_pid: 72,
        };
        let mut msg = alloc::vec![0u8; hdr.nlmsg_len as usize];
        hdr.write_to(&mut msg);
        msg[Nlmsghdr::SIZE..].copy_from_slice(body);
        msg
    }

    fn reply_ifindices(reply: &[u8], ty: u16) -> alloc::vec::Vec<u32> {
        let mut out = alloc::vec::Vec::new();
        let mut off = 0;
        while off + Nlmsghdr::SIZE <= reply.len() {
            let Some(hdr) = Nlmsghdr::parse(&reply[off..]) else { break; };
            let len = hdr.nlmsg_len as usize;
            if len < Nlmsghdr::SIZE || off + len > reply.len() { break; }
            if hdr.nlmsg_type == ty {
                let start = off + Nlmsghdr::SIZE + 4;
                out.push(u32::from_ne_bytes(reply[start..start + 4].try_into().unwrap()));
            }
            off += crate::nlmsg_align(len);
        }
        out
    }

    fn ack_errno(reply: &[u8]) -> i32 {
        i32::from_ne_bytes(reply[Nlmsghdr::SIZE..Nlmsghdr::SIZE + 4].try_into().unwrap())
    }

    #[test]
    fn pending_recv_error_overwrites_with_latest_positive_errno() {
        let namespace = network_namespace::initial();
        let sock = NetlinkSocket::new(0, &namespace);
        assert_eq!(sock.take_pending_recv_error(), 0);
        assert!(!sock.set_pending_recv_error(0));
        assert!(!sock.set_pending_recv_error(-5));
        assert!(sock.set_pending_recv_error(111));
        assert!(sock.set_pending_recv_error(104));
        assert_eq!(sock.take_pending_recv_error(), 104);
        assert_eq!(sock.take_pending_recv_error(), 0);
    }

    #[test]
    fn explicit_namespace_is_captured_by_socket() {
        let namespace = test_namespace();
        let sock = NetlinkSocket::new(0, &namespace);
        assert!(Arc::ptr_eq(&sock.net_ns, &namespace));
    }

    #[test]
    fn route_dump_uses_socket_namespace() {
        let namespace = test_namespace();
        let ns = namespace.id().as_u64();
        let row = rtnetlink::RouteRow {
            ns, table: rtnetlink::RT_TABLE_MAIN as u32,
            protocol: rtnetlink::RTPROT_STATIC, scope: rtnetlink::RT_SCOPE_LINK,
            kind: rtnetlink::RTN_UNICAST, dst: Some(([198, 18, 23, 0], 24)),
            gateway: None, oif_ifindex: 5511, prefsrc: None,
            metric: 0, mtu: None, flags: 0, weight: 1, nh_flags: 0,
        };
        rtnetlink::route_insert(row);
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let hdr = Nlmsghdr {
            nlmsg_len: (Nlmsghdr::SIZE + rtnetlink::Rtmsg::SIZE) as u32,
            nlmsg_type: rtnetlink::RTM_GETROUTE,
            nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
            nlmsg_seq: 1, nlmsg_pid: 2,
        };
        let mut msg = alloc::vec![0u8; hdr.nlmsg_len as usize];
        hdr.write_to(&mut msg);
        msg[Nlmsghdr::SIZE] = rtnetlink::AF_INET;
        sock.write(&msg).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert!(reply.windows(4).any(|bytes| bytes == [198, 18, 23, 0]));
        assert_eq!(rtnetlink::route_remove(ns, row.table, row.dst, row.oif_ifindex, row.gateway), 1);
    }

    #[test]
    fn passed_socket_keeps_captured_namespace_for_link_dump_and_mutation() {
        let owner_namespace = test_namespace();
        let receiver_namespace = test_namespace();
        let owner_ns = owner_namespace.id().as_u64();
        let receiver_ns = receiver_namespace.id().as_u64();
        let stack = net::global_stack();
        let owner = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), owner_ns);
        let receiver = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), receiver_ns);
        let passed = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &owner_namespace));
        let received_fd = Arc::clone(&passed);

        received_fd.write(&request(rtnetlink::RTM_GETLINK, &[])).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        let indices = reply_ifindices(&reply, rtnetlink::RTM_NEWLINK);
        assert!(indices.contains(&owner.raw()));
        assert!(!indices.contains(&receiver.raw()));

        let mut ifi = rtnetlink::Ifinfomsg::default();
        ifi.ifi_index = receiver.raw() as i32;
        ifi.ifi_change = rtnetlink::iff::IFF_UP;
        let mut body = [0u8; rtnetlink::Ifinfomsg::SIZE];
        ifi.write_to(&mut body);
        received_fd.write(&request(rtnetlink::RTM_SETLINK, &body)).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), -19, "owner socket cannot mutate receiver namespace link");

        ifi.ifi_index = owner.raw() as i32;
        ifi.ifi_flags = 0;
        ifi.write_to(&mut body);
        received_fd.write(&request(rtnetlink::RTM_SETLINK, &body)).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), 0);
        assert_eq!(stack.ifaces.iface_flags(owner).unwrap() & rtnetlink::iff::IFF_UP, 0);
        let _ = stack.ifaces.unregister(owner);
        let _ = stack.ifaces.unregister(receiver);
    }

    #[test]
    fn passed_socket_keeps_captured_namespace_for_addr_mutation_and_dump() {
        let owner_namespace = test_namespace();
        let receiver_namespace = test_namespace();
        let owner_ns = owner_namespace.id().as_u64();
        let receiver_ns = receiver_namespace.id().as_u64();
        let stack = net::global_stack();
        let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), owner_ns);
        let passed = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &owner_namespace));
        let received_fd = Arc::clone(&passed);
        let receiver = NetlinkSocket::new(proto::NETLINK_ROUTE, &receiver_namespace);
        let addr = [198, 18, 25, 1];
        let mut ifa = rtnetlink::Ifaddrmsg::default();
        ifa.ifa_family = rtnetlink::AF_INET;
        ifa.ifa_prefixlen = 24;
        ifa.ifa_scope = rtnetlink::RT_SCOPE_UNIVERSE;
        ifa.ifa_index = iface.raw();
        let mut body = alloc::vec![0u8; rtnetlink::Ifaddrmsg::SIZE];
        ifa.write_to(&mut body);
        rtnetlink::put_nlattr(&mut body, rtnetlink::ifa::IFA_LOCAL, &addr);

        received_fd.write(&request(rtnetlink::RTM_NEWADDR, &body)).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), 0);
        assert!(rtnetlink::addr_snapshot_ns(owner_ns).iter().any(|row| row.ifindex == iface.raw() && row.addr == addr));
        assert!(rtnetlink::addr_snapshot_ns(receiver_ns).is_empty());

        received_fd.write(&request(rtnetlink::RTM_GETADDR, &[])).unwrap();
        let (owner_dump, _) = received_fd.dequeue().unwrap();
        assert!(reply_ifindices(&owner_dump, rtnetlink::RTM_NEWADDR).contains(&iface.raw()));
        receiver.write(&request(rtnetlink::RTM_GETADDR, &[])).unwrap();
        let (receiver_dump, _) = receiver.dequeue().unwrap();
        assert!(!reply_ifindices(&receiver_dump, rtnetlink::RTM_NEWADDR).contains(&iface.raw()));

        receiver.write(&request(rtnetlink::RTM_DELADDR, &body)).unwrap();
        let (reply, _) = receiver.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), -19);
        assert_eq!(rtnetlink::addr_snapshot_ns(owner_ns).len(), 1);
        received_fd.write(&request(rtnetlink::RTM_DELADDR, &body)).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), 0);
        assert!(rtnetlink::addr_snapshot_ns(owner_ns).is_empty());
        let _ = stack.ifaces.unregister(iface);
    }
}
