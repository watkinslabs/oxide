extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use network_namespace::NetworkNamespaceRef;
use sync::{Socket as SockLockClass, Spinlock};

use crate::{flags, genetlink, invoke_netfilter, listeners, proto, rtnetlink, rtnetlink_rule, sock_diag, Nlmsghdr, nlmsg_align};
use crate::wire::alloc_port_id;

pub const NETLINK_SNDBUF_DEFAULT: usize = 212_992;
pub const NETLINK_SEND_OVERHEAD: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendError {
    Emsgsize,
    Backend(vfs::VfsError),
}

/// Checked aggregate byte length for one vectored datagram. # C: O(iov count)
pub(crate) fn checked_iov_len(mut lens: impl Iterator<Item = usize>) -> vfs::KResult<usize> {
    lens.try_fold(0usize, |sum, len| sum.checked_add(len).ok_or(vfs::VfsError::Einval))
}

fn snapshot_iov<'a>(bufs: impl Iterator<Item = &'a [u8]> + Clone) -> vfs::KResult<Vec<u8>> {
    let len = checked_iov_len(bufs.clone().map(|buf| buf.len()))?;
    let mut datagram = Vec::new();
    datagram.try_reserve_exact(len).map_err(|_| vfs::VfsError::Enomem)?;
    for buf in bufs { datagram.extend_from_slice(buf); }
    Ok(datagram)
}

/// AF_NETLINK socket. Owns an in-memory RX queue of nlmsg-aligned
/// reply buffers.
pub struct NetlinkSocket {
    pub protocol: u16,
    pub net_ns: NetworkNamespaceRef,
    pub port_id: AtomicU32,
    pub groups: AtomicU32,
    pub sndbuf: AtomicUsize,
    /// Canonical Linux `sk_err`.
    pub error: net::SocketError,
    pub bpf_filter: Arc<net::bpf_filter::SocketFilter>,
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
            sndbuf: AtomicUsize::new(NETLINK_SNDBUF_DEFAULT),
            error: net::SocketError::new(),
            bpf_filter: Arc::new(net::bpf_filter::SocketFilter::new()),
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

    /// Admit one userspace datagram before payload pages are copied. # C: O(1)
    pub fn preflight_send(&self, len: usize) -> Result<(), SendError> {
        let limit = self.sndbuf.load(Ordering::Acquire).saturating_sub(NETLINK_SEND_OVERHEAD);
        if len > limit { Err(SendError::Emsgsize) } else { Ok(()) }
    }

    /// Commit one admitted userspace datagram through canonical protocol routing. # C: O(len + listeners)
    pub fn send_to(&self, buf: &[u8], dest_groups: u32, dest_port: u32)
        -> Result<usize, SendError>
    {
        self.preflight_send(buf.len())?;
        if self.protocol == proto::NETLINK_KOBJECT_UEVENT && dest_port != 0 && dest_groups == 0 {
            let source = self.port_id.load(Ordering::Acquire);
            listeners::unicast_uevent_to_port(dest_port, buf, source);
            return Ok(buf.len());
        }
        self.write_to_groups(buf, dest_groups).map_err(SendError::Backend)
    }

    /// `NETLINK_ADD_MEMBERSHIP`: subscribe to one `RTNLGRP_*` group. # C: O(1)
    pub fn add_membership(&self, group: u32) {
        if group != 0 && group <= 32 { self.groups.fetch_or(1u32 << (group - 1), Ordering::AcqRel); }
    }

    /// `NETLINK_DROP_MEMBERSHIP`: unsubscribe one group. # C: O(1)
    pub fn drop_membership(&self, group: u32) {
        if group != 0 && group <= 32 { self.groups.fetch_and(!(1u32 << (group - 1)), Ordering::AcqRel); }
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

    /// Parse + dispatch every nlmsghdr in `buf`; returns the bytes consumed.
    /// # C: O(buf len)
    pub fn write(&self, buf: &[u8]) -> vfs::KResult<usize> {
        self.write_to_groups(buf, 0)
    }

    /// Parse + dispatch one vectored userspace netlink datagram. # C: O(sum lens)
    pub fn write_iter(&self, bufs: &[&[u8]]) -> vfs::KResult<usize> {
        self.write_iter_to_groups(bufs, 0)
    }

    /// Write one userspace netlink datagram with the destination group mask.
    /// # C: O(buf len + listeners)
    pub fn write_to_groups(&self, buf: &[u8], dest_groups: u32) -> vfs::KResult<usize> {
        self.write_iter_to_groups(&[buf], dest_groups)
    }

    /// Write one vectored userspace netlink datagram with destination groups. # C: O(sum lens)
    pub fn write_iter_to_groups(&self, bufs: &[&[u8]], dest_groups: u32) -> vfs::KResult<usize> {
        let datagram = snapshot_iov(bufs.iter().copied())?;
        self.write_datagram(datagram, dest_groups)
    }

    #[cfg(test)]
    /// Snapshot, mutate source storage, then parse for TOCTOU regression coverage. # C: O(sum lens)
    pub(crate) fn write_mutating_scatter_for_test(&self, mut bufs: Vec<Vec<u8>>,
        mutate: impl FnOnce(&mut [Vec<u8>])) -> vfs::KResult<usize> {
        let datagram = snapshot_iov(bufs.iter().map(Vec::as_slice))?;
        mutate(&mut bufs);
        self.write_datagram(datagram, 0)
    }

    fn write_datagram(&self, datagram: Vec<u8>, dest_groups: u32) -> vfs::KResult<usize> {
        let consumed = datagram.len();
        if consumed == 0 { return Err(vfs::VfsError::Enodata); }
        if self.protocol == proto::NETLINK_KOBJECT_UEVENT {
            let is_cooked = datagram.starts_with(b"libudev\0");
            if is_cooked || dest_groups != 0 {
                listeners::rebroadcast_cooked_uevent(&datagram, dest_groups, self);
                return Ok(consumed);
            }
        }
        let mut off = 0usize;
        while off < consumed {
            if consumed - off < Nlmsghdr::SIZE { return Err(vfs::VfsError::Einval); }
            let Some(hdr) = Nlmsghdr::parse(&datagram[off..]) else {
                return Err(vfs::VfsError::Einval);
            };
            let msg_len = hdr.nlmsg_len as usize;
            if msg_len < Nlmsghdr::SIZE || msg_len > consumed - off {
                return Err(vfs::VfsError::Einval);
            }
            self.handle_one(&hdr, &datagram[off..off + msg_len]);
            off = match off.checked_add(nlmsg_align(msg_len)) {
                Some(next) if next <= consumed => next,
                _ => return Err(vfs::VfsError::Einval),
            };
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
    fn send_preflight_enforces_linux_sndbuf_overhead_boundary() {
        let sock = NetlinkSocket::new(0, &network_namespace::initial());
        let limit = super::NETLINK_SNDBUF_DEFAULT - super::NETLINK_SEND_OVERHEAD;
        assert_eq!(sock.preflight_send(limit), Ok(()));
        assert_eq!(sock.preflight_send(limit + 1), Err(super::SendError::Emsgsize));
    }

    #[test]
    fn empty_vectored_datagram_reaches_backend_enodata() {
        let sock = NetlinkSocket::new(0, &network_namespace::initial());
        assert_eq!(sock.write_iter(&[]), Err(vfs::VfsError::Enodata));
        assert_eq!(sock.write(&[]), Err(vfs::VfsError::Enodata));
    }

    #[test]
    fn malformed_netlink_frames_return_einval() {
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
        assert_eq!(sock.write(&[0u8; Nlmsghdr::SIZE - 1]), Err(vfs::VfsError::Einval));

        let mut short = alloc::vec![0u8; Nlmsghdr::SIZE];
        short[..2].copy_from_slice(&((Nlmsghdr::SIZE - 1) as u16).to_ne_bytes());
        assert_eq!(sock.write(&short), Err(vfs::VfsError::Einval));

        let mut overrun = alloc::vec![0u8; Nlmsghdr::SIZE];
        overrun[..2].copy_from_slice(&((Nlmsghdr::SIZE + 1) as u16).to_ne_bytes());
        assert_eq!(sock.write(&overrun), Err(vfs::VfsError::Einval));

        let mut misaligned = alloc::vec![0u8; Nlmsghdr::SIZE + 1];
        misaligned[..2].copy_from_slice(&(Nlmsghdr::SIZE as u16).to_ne_bytes());
        assert_eq!(sock.write(&misaligned), Err(vfs::VfsError::Einval));
    }

    #[test]
    fn explicit_namespace_is_captured_by_socket() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let namespace = test_namespace();
        let sock = NetlinkSocket::new(0, &namespace);
        assert!(Arc::ptr_eq(&sock.net_ns, &namespace));
    }

    #[test]
    fn route_dump_uses_socket_namespace() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
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
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let owner_namespace = test_namespace();
        let receiver_namespace = test_namespace();
        let owner_ns = owner_namespace.id().as_u64();
        let receiver_ns = receiver_namespace.id().as_u64();
        let stack = net::global_stack();
        let owner = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), owner_ns);
        let receiver = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), receiver_ns);
        let owner_ifindex = stack.ifaces.ifindex_in_ns(owner, owner_ns).unwrap();
        let receiver_ifindex = stack.ifaces.ifindex_in_ns(receiver, receiver_ns).unwrap();
        let passed = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &owner_namespace));
        let received_fd = Arc::clone(&passed);

        received_fd.write(&request(rtnetlink::RTM_GETLINK, &[])).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        let indices = reply_ifindices(&reply, rtnetlink::RTM_NEWLINK);
        assert!(indices.contains(&owner_ifindex));
        assert_eq!(indices.len(), 1);

        let mut ifi = rtnetlink::Ifinfomsg::default();
        // Both namespace-local loopbacks are ifindex 1. An index identifies
        // only an interface in the socket's captured namespace, so use an
        // absent owner-namespace index to verify the ENODEV boundary.
        ifi.ifi_index = receiver_ifindex.saturating_add(1) as i32;
        ifi.ifi_change = rtnetlink::iff::IFF_UP;
        let mut body = [0u8; rtnetlink::Ifinfomsg::SIZE];
        ifi.write_to(&mut body);
        received_fd.write(&request(rtnetlink::RTM_SETLINK, &body)).unwrap();
        let (reply, _) = received_fd.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), -19, "owner socket cannot mutate receiver namespace link");

        ifi.ifi_index = owner_ifindex as i32;
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
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let owner_namespace = test_namespace();
        let receiver_namespace = test_namespace();
        let owner_ns = owner_namespace.id().as_u64();
        let receiver_ns = receiver_namespace.id().as_u64();
        let stack = net::global_stack();
        let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), owner_ns);
        let ifindex = stack.ifaces.ifindex_in_ns(iface, owner_ns).unwrap();
        let passed = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &owner_namespace));
        let received_fd = Arc::clone(&passed);
        let receiver = NetlinkSocket::new(proto::NETLINK_ROUTE, &receiver_namespace);
        let addr = [198, 18, 25, 1];
        let mut ifa = rtnetlink::Ifaddrmsg::default();
        ifa.ifa_family = rtnetlink::AF_INET;
        ifa.ifa_prefixlen = 24;
        ifa.ifa_scope = rtnetlink::RT_SCOPE_UNIVERSE;
        ifa.ifa_index = ifindex;
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
        assert!(reply_ifindices(&owner_dump, rtnetlink::RTM_NEWADDR).contains(&ifindex));
        receiver.write(&request(rtnetlink::RTM_GETADDR, &[])).unwrap();
        let (receiver_dump, _) = receiver.dequeue().unwrap();
        assert!(!reply_ifindices(&receiver_dump, rtnetlink::RTM_NEWADDR).contains(&ifindex));

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
