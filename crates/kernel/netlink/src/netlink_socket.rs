extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use network_namespace::NetworkNamespaceRef;
use sync::{Socket as SockLockClass, Spinlock};

use crate::{flags, genetlink, listeners, nlmsg_align, proto, rtnetlink, rtnetlink_rule, sock_diag, Nlmsghdr};
use crate::receive::ReceiveQueue;
use crate::wire::alloc_port_id;

mod netfilter;
mod ack_response;

pub const NETLINK_SNDBUF_DEFAULT: usize = 212_992;
/// Linux default NETLINK receive budget; one owner keeps loss, `sk_err`, and poll coherent.
pub const NETLINK_RCVBUF_DEFAULT: usize = NETLINK_SNDBUF_DEFAULT;
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

/// AF_NETLINK socket owning its nlmsg-aligned receive queue.
pub struct NetlinkSocket {
    /// Effective receive timeout shared by generic socket options and netlink
    /// wait interruption. `0` means no timeout.
    pub rcvtimeo_ns: core::sync::atomic::AtomicU64,
    pub protocol: u16,
    pub net_ns: NetworkNamespaceRef,
    /// Socket-file opener credentials retained by the socket owner. Cross-netns
    /// multicast checks this immutable snapshot, never the broadcaster task.
    opener_user_ns: namespace_identity::NamespacePin,
    opener_caps: u64,
    pub port_id: AtomicU32,
    pub groups: crate::groups::GroupBitmap,
    pub dst_port_id: AtomicU32,
    pub dst_groups: AtomicU32,
    pub connected: AtomicBool,
    /// `sk_scm_credentials`, in the type every credential-carrying family
    /// shares. Not netlink-private state: the flag, its family gate and the
    /// receive decision all live with `net::scm`.
    pub scm: net::scm::ScmCredentials,
    /// `sk_scm_security`, sharing its state type with every SCM-capable
    /// family while this standalone socket type has no `InetSocket` base.
    pub scm_security: net::scm::ScmSecurity,
    pub sndbuf: AtomicUsize,
    pub rcvbuf: AtomicUsize,
    /// The pseudo-inode number of the file this socket is reachable through,
    /// which `/proc/net/netlink` reports and `ss` matches against `/proc/*/fd`.
    /// Zero until the inode is built.
    pub ino: core::sync::atomic::AtomicU64,
    /// Canonical `NETLINK_F_*` word: the single owner of every boolean
    /// SOL_NETLINK option, written by `setsockopt` and read by `getsockopt`.
    pub flags: crate::sockflags::NetlinkFlags,
    pub rx_congested: AtomicBool, pub rx_drops: AtomicUsize,
    /// Canonical Linux `sk_err`.
    pub error: net::SocketError,
    pub bpf_filter: Arc<net::bpf_filter::SocketFilter>,
    pub(crate) rx_queue: Spinlock<ReceiveQueue, SockLockClass>,
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
            | rtnetlink::RTM_NEWNEIGH | rtnetlink::RTM_DELNEIGH
            | rtnetlink::RTM_NEWLINK | rtnetlink::RTM_SETLINK
            | rtnetlink::RTM_NEWNSID)
    }

    /// Route an nsfs-backed namespace-ID request through the calling task's
    /// pinned descriptor table. # C: O(N peers)
    #[cfg(target_os = "oxide-kernel")]
    fn handle_nsid(&self, hdr: &Nlmsghdr, msg: &[u8]) -> Vec<u8> {
        let Some(cur) = sched::live::current() else {
            return rtnetlink::nlmsg_ack_pub(hdr, -(syscall::errno::Errno::Ebadf.as_i32()));
        };
        let Some(fdt) = cur.clone_fd_table() else {
            return rtnetlink::nlmsg_ack_pub(hdr, -(syscall::errno::Errno::Ebadf.as_i32()));
        };
        let body = &msg[Nlmsghdr::SIZE..];
        match hdr.nlmsg_type {
            rtnetlink::RTM_NEWNSID => rtnetlink::handle_newnsid(hdr, body, &self.net_ns, &fdt, &cur),
            rtnetlink::RTM_GETNSID if rtnetlink::is_dump(hdr) =>
                rtnetlink::handle_dumpnsid(hdr, body, &self.net_ns, &cur),
            rtnetlink::RTM_GETNSID => rtnetlink::handle_getnsid(hdr, body, &self.net_ns, &fdt, &cur),
            _ => rtnetlink::nlmsg_ack_pub(hdr, -(vfs::VfsError::Eopnotsupp as i32)),
        }
    }

    #[cfg(not(target_os = "oxide-kernel"))]
    fn handle_nsid(&self, hdr: &Nlmsghdr, _msg: &[u8]) -> Vec<u8> {
        rtnetlink::nlmsg_ack_pub(hdr, -(syscall::errno::Errno::Ebadf.as_i32()))
    }

    fn may_admin_net(&self) -> bool {
        self.may_admin_net_for(&self.net_ns)
    }

    fn may_admin_net_for(&self, _target: &NetworkNamespaceRef) -> bool {
        #[cfg(target_os = "oxide-kernel")]
        { sched::current().is_some_and(|cur| nscg::has_net_admin_for(cur, _target)) }
        #[cfg(not(target_os = "oxide-kernel"))]
        { true }
    }

    /// Create a socket retaining its concrete network namespace owner. # C: O(1)
    pub fn new(protocol: u16, net_ns: &NetworkNamespaceRef) -> Self {
        Self::new_with_cred(protocol, net_ns,
            namespace_identity::initial(namespace_identity::NamespaceKind::User).pin(), u64::MAX)
    }

    /// Create a socket retaining the opener's effective capability snapshot.
    /// # C: O(1)
    pub fn new_with_cred(protocol: u16, net_ns: &NetworkNamespaceRef,
        opener_user_ns: namespace_identity::NamespacePin, opener_caps: u64) -> Self {
        Self {
            rcvtimeo_ns: core::sync::atomic::AtomicU64::new(0),
            protocol,
            net_ns: Arc::clone(net_ns),
            opener_user_ns,
            opener_caps,
            port_id: AtomicU32::new(alloc_port_id()),
            groups: crate::groups::GroupBitmap::new(),
            dst_port_id: AtomicU32::new(crate::NETLINK_UNCONNECTED_PORT_ID),
            dst_groups: AtomicU32::new(crate::NETLINK_UNCONNECTED_GROUPS),
            connected: AtomicBool::new(false),
            scm: net::scm::ScmCredentials::new(),
            scm_security: net::scm::ScmSecurity::new(),
            sndbuf: AtomicUsize::new(NETLINK_SNDBUF_DEFAULT),
            rcvbuf: AtomicUsize::new(NETLINK_RCVBUF_DEFAULT),
            ino: core::sync::atomic::AtomicU64::new(0),
            flags: crate::sockflags::NetlinkFlags::new(),
            rx_congested: AtomicBool::new(false),
            rx_drops: AtomicUsize::new(0),
            error: net::SocketError::new(),
            bpf_filter: Arc::new(net::bpf_filter::SocketFilter::new()),
            rx_queue: Spinlock::new(ReceiveQueue::new()),
            poll_subs: Arc::new(vfs::PollSubscribers::new()),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
        }
    }

    /// Linux `file_ns_capable(socket_file, source_user_ns, CAP_NET_BROADCAST)`
    /// for cross-network-namespace multicast delivery. # C: O(ns depth)
    pub(crate) fn may_receive_cross_ns(&self, source: &NetworkNamespaceRef) -> bool {
        self.opener_caps & (1u64 << sched::cap::NET_BROADCAST) != 0
            && nscg::proc_ns::user_ns_is_ancestor(&self.opener_user_ns, &source.owner_user_namespace())
    }

    /// Linux `sock_no_shutdown` for AF_NETLINK after namespace security admission.
    /// `how` is intentionally not validated: Linux reaches the family operation
    /// after LSM and `sock_no_shutdown` returns EOPNOTSUPP for every value.
    /// # C: O(1)
    pub fn shutdown_raw(&self, _how: u32) -> net::NetResult<()> {
        net::security_admission::check(
            net::net_ns::namespace_id(&self.net_ns), net::socket_args::AF_NETLINK_WIRE,
            security::network::Operation::Shutdown,
        )?;
        Err(net::NetError::Eopnotsupp)
    }

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

    /// Commit one admitted userspace datagram through canonical protocol routing.
    /// Taking the decoded destination whole keeps the port and the group from
    /// ever being supplied in the wrong order. # C: O(len + listeners)
    pub fn send_to(&self, buf: &[u8], dest: crate::NlDest) -> Result<usize, SendError> {
        self.preflight_send(buf.len())?;
        if dest.port_id != 0 {
            if !crate::unicast_port(self, dest.port_id, buf) {
                return Err(SendError::Backend(vfs::VfsError::Econnrefused));
            }
            if dest.group == 0 { return Ok(buf.len()); }
        }
        self.write_to_groups(buf, dest.group).map_err(SendError::Backend)
    }

    /// Dispatch a single parsed request header.
    /// # C: O(reply build)
    fn handle_one(&self, hdr: &Nlmsghdr, msg: &[u8]) {
        let net_ns = self.net_ns.id().as_u64();
        // `NETLINK_GET_STRICT_CHK`: the client asked for its dump requests to be
        // validated and their header filters honoured.
        let strict = self.flags.get(crate::sockflags::F_STRICT_CHK);
        if !crate::rcv_skb::reaches_handler(self.protocol, hdr) {
            // Netlink core acknowledges a control message or a non-request only
            // when the sender asked for one, and never runs a handler for it.
            if (hdr.nlmsg_flags & flags::NLM_F_ACK) != 0 {
                let mut reply = rtnetlink::nlmsg_ack_pub(hdr, 0);
                ack_response::shape(&mut reply, msg, self.flags.get(crate::sockflags::F_CAP_ACK), self.flags.get(crate::sockflags::F_EXT_ACK));
                self.enqueue(reply);
            }
            return;
        }
        let reply = if self.protocol == proto::NETLINK_ROUTE && Self::rtnl_mutation(hdr.nlmsg_type)
            && !self.may_admin_net() {
            rtnetlink::nlmsg_ack_pub(hdr, -1)
        } else { match (self.protocol, hdr.nlmsg_type) {
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWNSID)
            | (proto::NETLINK_ROUTE, rtnetlink::RTM_GETNSID) => self.handle_nsid(hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETLINK) => rtnetlink::handle_getlink_in(net_ns, hdr, msg, strict),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETADDR) if rtnetlink::is_dump(hdr) => rtnetlink::handle_getaddr_with_access(net_ns, hdr, msg, strict, |target| self.may_admin_net_for(target)),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETADDR) => rtnetlink::handle_getaddr6_one_with_access(net_ns, hdr, msg, |target| self.may_admin_net_for(target)),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETMULTICAST) if rtnetlink::is_dump(hdr) => rtnetlink::handle_getmulticast_in(net_ns, hdr, msg, strict),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETANYCAST) if rtnetlink::is_dump(hdr) => rtnetlink::handle_getanycast_in(net_ns, hdr, msg, strict),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWADDR) => rtnetlink::handle_newaddr_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELADDR) => rtnetlink::handle_deladdr_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETROUTE) => rtnetlink::handle_getroute_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETNEIGH) if rtnetlink::is_dump(hdr) => rtnetlink::handle_getneigh_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETNEIGH) => rtnetlink::handle_getneigh_one_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWNEIGH) => rtnetlink::handle_newneigh_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELNEIGH) => rtnetlink::handle_delneigh_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETRULE) if rtnetlink::is_dump(hdr) => rtnetlink_rule::handle_getrule_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWRULE) => rtnetlink_rule::handle_newrule_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELRULE) => rtnetlink_rule::handle_delrule_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWROUTE) => rtnetlink::handle_newroute_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELROUTE) => rtnetlink::handle_delroute_in(net_ns, hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWLINK)
            | (proto::NETLINK_ROUTE, rtnetlink::RTM_SETLINK) => rtnetlink::handle_setlink_in(net_ns, hdr, msg),
            (proto::NETLINK_GENERIC, _) => genetlink::handle(msg, net_ns, self.genl_cred()),
            (proto::NETLINK_AUDIT, _) => crate::audit::handle(hdr, msg),
            (proto::NETLINK_SOCK_DIAG, sock_diag::SOCK_DIAG_BY_FAMILY)
            | (proto::NETLINK_SOCK_DIAG, sock_diag::TCPDIAG_GETSOCK) =>
                sock_diag::handle_in(net_ns, hdr, msg),
            _ => {
                if self.protocol == proto::NETLINK_ROUTE {
                    // Linux rtnetlink_rcv_msg begins at -EOPNOTSUPP when no
                    // RTM handler owns the request; netlink core serializes
                    // that dispatch error as NLMSG_ERROR for the sender.
                    rtnetlink::nlmsg_ack_pub(hdr, -(vfs::VfsError::Eopnotsupp as i32))
                } else if (hdr.nlmsg_flags & flags::NLM_F_ACK) != 0 {
                    rtnetlink::nlmsg_ack_pub(hdr, 0)
                } else {
                    let mut done = alloc::vec![0u8; Nlmsghdr::SIZE];
                    Nlmsghdr::done(hdr.nlmsg_seq, hdr.nlmsg_pid).write_to(&mut done);
                    done
                }
            }
        }};
        let mut reply = reply;
        ack_response::shape(&mut reply, msg, self.flags.get(crate::sockflags::F_CAP_ACK), self.flags.get(crate::sockflags::F_EXT_ACK));
        let port = self.port_id.load(Ordering::Acquire);
        let mut off = 0usize;
        while off + Nlmsghdr::SIZE <= reply.len() {
            let len = u32::from_ne_bytes([reply[off], reply[off + 1], reply[off + 2], reply[off + 3]]) as usize;
            if len < Nlmsghdr::SIZE || off + len > reply.len() { break; }
            reply[off + 12..off + 16].copy_from_slice(&port.to_ne_bytes());
            off += nlmsg_align(len);
        }
        #[cfg(feature = "debug-netlink")]
        {
            let rtype = if reply.len() >= Nlmsghdr::SIZE {
                u16::from_ne_bytes([reply[4], reply[5]]) } else { 0 };
            let rerr = if reply.len() >= Nlmsghdr::SIZE + 4 && rtype == crate::msg::NLMSG_ERROR {
                i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]) } else { i32::MIN };
            klog::write_raw(b"[NL-REQ proto="); klog::write_dec_u64(self.protocol as u64);
            klog::write_raw(b" type="); klog::write_dec_u64(hdr.nlmsg_type as u64);
            klog::write_raw(b" seq="); klog::write_dec_u64(hdr.nlmsg_seq as u64);
            klog::write_raw(b" fl="); klog::write_dec_u64(hdr.nlmsg_flags as u64);
            klog::write_raw(b" -> rtype="); klog::write_dec_u64(rtype as u64);
            klog::write_raw(b" rlen="); klog::write_dec_u64(reply.len() as u64);
            if rerr != i32::MIN {
                klog::write_raw(b" err=");
                if rerr < 0 { klog::write_raw(b"-"); klog::write_dec_u64((-(rerr as i64)) as u64); }
                else { klog::write_dec_u64(rerr as u64); }
            }
            klog::write_raw(b"]\n");
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
        if self.protocol == proto::NETLINK_NETFILTER {
            return netfilter::dispatch(self, &datagram, consumed);
        }
        // The walk itself never fails the send. Netlink core hands the whole
        // datagram to the protocol receive path and discards its verdict, so a
        // malformed or unhandled message becomes an NLMSG_ERROR reply, never a
        // failed `sendto`. Framing that runs out mid-message simply ends the
        // walk with every byte still reported as accepted — which is what makes
        // a fixed-size request buffer with zeroed padding behind its one
        // message work.
        let mut off = 0usize;
        while let Some(frame) = crate::rcv_skb::frame_at(&datagram, off) {
            self.handle_one(&frame.hdr, &datagram[off..off + frame.msg_len]);
            off += frame.advance;
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

    /// Malformed framing is never a send failure: netlink core stops walking
    /// and reports every byte accepted, leaving the sender to learn about a bad
    /// request from an NLMSG_ERROR reply instead of a failed `sendto`.
    #[test]
    fn malformed_netlink_frames_are_accepted_without_a_send_error() {
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
        let runt = [0u8; Nlmsghdr::SIZE - 1];
        assert_eq!(sock.write(&runt), Ok(runt.len()));

        let mut short = alloc::vec![0u8; Nlmsghdr::SIZE];
        short[..2].copy_from_slice(&((Nlmsghdr::SIZE - 1) as u16).to_ne_bytes());
        assert_eq!(sock.write(&short), Ok(short.len()));

        let mut overrun = alloc::vec![0u8; Nlmsghdr::SIZE];
        overrun[..2].copy_from_slice(&((Nlmsghdr::SIZE + 1) as u16).to_ne_bytes());
        assert_eq!(sock.write(&overrun), Ok(overrun.len()));

        assert!(sock.dequeue().is_none(), "no reply is produced for unparsable framing");
    }

    /// `ip(8)` sends a fixed-size request buffer: `nlmsg_len` covers only the
    /// leading dump request and the rest of the buffer is zero. The request
    /// must be answered and the send must report the whole buffer accepted.
    #[test]
    fn zero_padded_dump_request_is_answered_and_fully_accepted() {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &test_namespace());
        let mut buf = request(rtnetlink::RTM_GETADDR, &[0u8; rtnetlink::Ifaddrmsg::SIZE]);
        let msg_len = buf.len();
        buf.resize(msg_len + 128, 0);
        assert_eq!(sock.write(&buf), Ok(msg_len + 128));
        let (reply, _) = sock.dequeue().expect("the padded dump request is answered");
        assert!(reply_ends_with_done(&reply));
        assert!(sock.dequeue().is_none(), "the padding produces no second reply");
    }

    /// A final message whose ALIGNED length runs past the datagram is accepted
    /// and dispatched; the walk clamps to the datagram end.
    #[test]
    fn unaligned_final_message_is_dispatched_not_rejected() {
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
        let unknown = rtnetlink::RTM_MAX + 1;
        let mut msg = request(unknown, &[0u8]);
        assert_eq!(msg.len(), Nlmsghdr::SIZE + 1);
        msg[..4].copy_from_slice(&((Nlmsghdr::SIZE + 1) as u32).to_ne_bytes());
        assert_eq!(sock.write(&msg), Ok(Nlmsghdr::SIZE + 1));
        let (reply, _) = sock.dequeue().expect("the trailing message still dispatched");
        assert_eq!(ack_errno(&reply), -(vfs::VfsError::Eopnotsupp as i32));
    }

    /// Reserved control types and non-request messages never reach a handler;
    /// they are acknowledged only when the sender set NLM_F_ACK.
    #[test]
    fn control_and_non_request_messages_skip_the_handler() {
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
        let mut noop = request(crate::msg::NLMSG_NOOP, &[]);
        assert_eq!(sock.write(&noop), Ok(noop.len()));
        assert!(sock.dequeue().is_none(), "a control message without NLM_F_ACK is silent");

        noop[6..8].copy_from_slice(&(flags::NLM_F_REQUEST | flags::NLM_F_ACK).to_ne_bytes());
        assert_eq!(sock.write(&noop), Ok(noop.len()));
        let (reply, _) = sock.dequeue().expect("NLM_F_ACK on a control message is answered");
        assert_eq!(ack_errno(&reply), 0);

        let mut not_request = request(rtnetlink::RTM_GETLINK, &[]);
        not_request[6..8].copy_from_slice(&0u16.to_ne_bytes());
        assert_eq!(sock.write(&not_request), Ok(not_request.len()));
        assert!(sock.dequeue().is_none(), "a non-request never runs the handler");
    }

    #[test]
    fn unknown_rtnetlink_request_queues_linux_eopnotsupp() {
        let socket = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
        let unknown = rtnetlink::RTM_MAX + 1;
        socket.write(&request(unknown, &[])).unwrap();
        let (reply, _) = socket.dequeue().expect("unsupported RTNL request has error reply");
        assert_eq!(ack_errno(&reply), -(vfs::VfsError::Eopnotsupp as i32));
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
            metric: 0, metrics: net::RouteMetrics::NONE,
            flags: 0, weight: 1, nh_flags: 0,
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
        assert!(rtnetlink::addr_snapshot_ns(owner_ns).iter().any(|row|
            row.iface == iface && row.addr == net::Ipv4Addr::from_u32(u32::from_be_bytes(addr))));
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

    const NEIGH_IP: [u8; 4] = [198, 18, 40, 7];
    const NEIGH_MAC: [u8; 6] = [0x02, 0x00, 0x5e, 0x00, 0x00, 0x07];

    /// One decoded RTM_NEWNEIGH reply: state + NDA_DST + optional NDA_LLADDR.
    fn parse_neigh_replies(reply: &[u8]) -> alloc::vec::Vec<(u16, alloc::vec::Vec<u8>, Option<[u8; 6]>)> {
        let mut out = alloc::vec::Vec::new();
        let mut off = 0;
        while off + Nlmsghdr::SIZE <= reply.len() {
            let Some(hdr) = Nlmsghdr::parse(&reply[off..]) else { break; };
            let len = hdr.nlmsg_len as usize;
            if len < Nlmsghdr::SIZE || off + len > reply.len() { break; }
            if hdr.nlmsg_type == rtnetlink::RTM_NEWNEIGH {
                let ndm = &reply[off + Nlmsghdr::SIZE..off + Nlmsghdr::SIZE + rtnetlink::Ndmsg::SIZE];
                let state = u16::from_ne_bytes([ndm[8], ndm[9]]);
                let mut dst = alloc::vec::Vec::new();
                let mut mac = None;
                let mut ao = off + Nlmsghdr::SIZE + rtnetlink::Ndmsg::SIZE;
                while ao + 4 <= off + len {
                    let al = u16::from_ne_bytes([reply[ao], reply[ao + 1]]) as usize;
                    let at = u16::from_ne_bytes([reply[ao + 2], reply[ao + 3]]) & 0x3fff;
                    if al < 4 || ao + al > off + len { break; }
                    let pl = &reply[ao + 4..ao + al];
                    if at == rtnetlink::nda::NDA_DST { dst = pl.to_vec(); }
                    else if at == rtnetlink::nda::NDA_LLADDR && pl.len() == 6 {
                        mac = Some([pl[0], pl[1], pl[2], pl[3], pl[4], pl[5]]);
                    }
                    ao += crate::nlmsg_align(al);
                }
                out.push((state, dst, mac));
            }
            off += crate::nlmsg_align(len);
        }
        out
    }

    fn reply_ends_with_done(reply: &[u8]) -> bool {
        let mut off = 0;
        let mut last = None;
        while off + Nlmsghdr::SIZE <= reply.len() {
            let Some(hdr) = Nlmsghdr::parse(&reply[off..]) else { break; };
            let len = hdr.nlmsg_len as usize;
            if len < Nlmsghdr::SIZE || off + len > reply.len() { break; }
            last = Some(hdr.nlmsg_type);
            off += crate::nlmsg_align(len);
        }
        last == Some(crate::msg::NLMSG_DONE)
    }

    fn neigh_body(family: u8, ifindex: u32, ip: &[u8], mac: Option<[u8; 6]>, state: u16)
        -> alloc::vec::Vec<u8>
    {
        let mut ndm = rtnetlink::Ndmsg::default();
        ndm.ndm_family = family;
        ndm.ndm_ifindex = ifindex as i32;
        ndm.ndm_state = state;
        ndm.ndm_type = rtnetlink::RTN_UNICAST;
        let mut body = alloc::vec![0u8; rtnetlink::Ndmsg::SIZE];
        ndm.write_to(&mut body);
        rtnetlink::put_nlattr(&mut body, rtnetlink::nda::NDA_DST, ip);
        if let Some(m) = mac { rtnetlink::put_nlattr(&mut body, rtnetlink::nda::NDA_LLADDR, &m); }
        body
    }

    fn seed_neigh_iface() -> (network_namespace::NetworkNamespaceRef, u64, net::NetIfaceId, u32) {
        let domain = net::hosted_fixture::init_net_domain();
        domain.set_notifier(crate::mcast::notify_control_event);
        let namespace = test_namespace();
        let ns = namespace.id().as_u64();
        let stack = net::global_stack();
        let iface = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), ns);
        let ifindex = stack.ifaces.ifindex_in_ns(iface, ns).unwrap();
        (namespace, ns, iface, ifindex)
    }

    #[test]
    fn getneigh_dump_reports_seeded_arp_entry_and_terminates_with_done() {
        let (namespace, ns, iface, ifindex) = seed_neigh_iface();
        let stack = net::global_stack();
        let ip = net::Ipv4Addr::new(NEIGH_IP[0], NEIGH_IP[1], NEIGH_IP[2], NEIGH_IP[3]);
        stack.neigh_add_v4(ns, ifindex, ip, net::MacAddr(NEIGH_MAC), true).unwrap();

        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        sock.write(&request(rtnetlink::RTM_GETNEIGH, &[])).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert!(reply_ends_with_done(&reply), "dump ends with NLMSG_DONE");
        let rows = parse_neigh_replies(&reply);
        let row = rows.iter().find(|(_, dst, _)| dst.as_slice() == NEIGH_IP)
            .expect("seeded neighbour present in dump");
        assert_eq!(row.2, Some(NEIGH_MAC), "NDA_LLADDR matches");
        assert!(row.0 & rtnetlink::nud::NUD_PERMANENT != 0, "permanent NUD state");
        let _ = stack.ifaces.unregister(iface);
    }

    #[test]
    fn getneigh_one_reads_one_canonical_arp_entry_without_done() {
        let (namespace, ns, iface, ifindex) = seed_neigh_iface();
        let stack = net::global_stack();
        let ip = net::Ipv4Addr::new(NEIGH_IP[0], NEIGH_IP[1], NEIGH_IP[2], NEIGH_IP[3]);
        stack.neigh_add_v4(ns, ifindex, ip, net::MacAddr(NEIGH_MAC), true).unwrap();
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let body = neigh_body(rtnetlink::AF_INET, ifindex, &NEIGH_IP, None, 0);
        let mut msg = request(rtnetlink::RTM_GETNEIGH, &body);
        msg[6..8].copy_from_slice(&flags::NLM_F_REQUEST.to_ne_bytes());
        sock.write(&msg).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert!(!reply_ends_with_done(&reply));
        let rows = parse_neigh_replies(&reply);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, NEIGH_IP);
        assert_eq!(rows[0].2, Some(NEIGH_MAC));
        let _ = stack.ifaces.unregister(iface);
    }

    #[test]
    fn getneigh_one_reports_enoent_for_an_absent_canonical_entry() {
        let (namespace, _ns, iface, ifindex) = seed_neigh_iface();
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let body = neigh_body(rtnetlink::AF_INET, ifindex, &NEIGH_IP, None, 0);
        let mut msg = request(rtnetlink::RTM_GETNEIGH, &body);
        msg[6..8].copy_from_slice(&flags::NLM_F_REQUEST.to_ne_bytes());
        sock.write(&msg).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), -(vfs::VfsError::Enoent as i32));
        let _ = net::global_stack().ifaces.unregister(iface);
    }

    #[test]
    fn getaddr6_one_reads_one_canonical_address_without_done() {
        let (namespace, _ns, iface, ifindex) = seed_neigh_iface();
        let addr = net::Ipv6Addr([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]);
        net::global_stack().add_v6_addr(iface, addr);
        let mut body = alloc::vec![0u8; rtnetlink::Ifaddrmsg::SIZE];
        body[0] = rtnetlink::AF_INET6;
        body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        rtnetlink::put_nlattr(&mut body, rtnetlink::ifa::IFA_ADDRESS, &addr.0);
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let mut msg = request(rtnetlink::RTM_GETADDR, &body);
        msg[6..8].copy_from_slice(&flags::NLM_F_REQUEST.to_ne_bytes());
        sock.write(&msg).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert!(!reply_ends_with_done(&reply));
        let hdr = Nlmsghdr::parse(&reply).unwrap();
        assert_eq!(hdr.nlmsg_type, rtnetlink::RTM_NEWADDR);
        assert_eq!(reply[Nlmsghdr::SIZE], rtnetlink::AF_INET6);
        assert_eq!(u32::from_ne_bytes(reply[Nlmsghdr::SIZE + 4..Nlmsghdr::SIZE + 8].try_into().unwrap()), ifindex);
        let _ = net::global_stack().ifaces.unregister(iface);
    }

    #[test]
    fn newneigh_writes_the_canonical_arp_cache_no_split_table() {
        let (namespace, ns, iface, ifindex) = seed_neigh_iface();
        let stack = net::global_stack();
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let body = neigh_body(rtnetlink::AF_INET, ifindex, &NEIGH_IP, Some(NEIGH_MAC),
            rtnetlink::nud::NUD_PERMANENT);
        sock.write(&request(rtnetlink::RTM_NEWNEIGH, &body)).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), 0);

        // Read back through the SAME canonical per-iface ArpCache SIOCSARP uses.
        let cache = stack.ifaces.arp_cache_in_ns(iface, ns).unwrap();
        let ip = net::Ipv4Addr::new(NEIGH_IP[0], NEIGH_IP[1], NEIGH_IP[2], NEIGH_IP[3]);
        let entry = cache.snapshot_states().into_iter().find(|(a, _, _)| *a == ip)
            .expect("RTM_NEWNEIGH wrote the canonical cache");
        assert_eq!(entry.1, Some(net::MacAddr(NEIGH_MAC)));
        assert_eq!(entry.2, net::arp::NudState::Permanent);
        let _ = stack.ifaces.unregister(iface);
    }

    #[test]
    fn delneigh_removes_from_the_canonical_arp_cache() {
        let (namespace, ns, iface, ifindex) = seed_neigh_iface();
        let stack = net::global_stack();
        let ip = net::Ipv4Addr::new(NEIGH_IP[0], NEIGH_IP[1], NEIGH_IP[2], NEIGH_IP[3]);
        stack.neigh_add_v4(ns, ifindex, ip, net::MacAddr(NEIGH_MAC), true).unwrap();
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
        let body = neigh_body(rtnetlink::AF_INET, ifindex, &NEIGH_IP, None, 0);
        sock.write(&request(rtnetlink::RTM_DELNEIGH, &body)).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), 0);
        let cache = stack.ifaces.arp_cache_in_ns(iface, ns).unwrap();
        assert!(cache.snapshot_states().into_iter().all(|(a, _, _)| a != ip));
        let _ = stack.ifaces.unregister(iface);
    }

    #[test]
    fn newneigh_for_iface_absent_in_socket_namespace_is_rejected() {
        let (_owner, owner_ns, iface, ifindex) = seed_neigh_iface();
        let stack = net::global_stack();
        // A socket in a DIFFERENT namespace cannot resolve the owner ifindex.
        let other = test_namespace();
        assert_ne!(other.id().as_u64(), owner_ns);
        let sock = NetlinkSocket::new(proto::NETLINK_ROUTE, &other);
        let body = neigh_body(rtnetlink::AF_INET, ifindex, &NEIGH_IP, Some(NEIGH_MAC),
            rtnetlink::nud::NUD_PERMANENT);
        sock.write(&request(rtnetlink::RTM_NEWNEIGH, &body)).unwrap();
        let (reply, _) = sock.dequeue().unwrap();
        assert_eq!(ack_errno(&reply), -19, "ENODEV: ifindex not in socket namespace");
        let _ = stack.ifaces.unregister(iface);
    }
}
