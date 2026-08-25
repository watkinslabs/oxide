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
mod dump;

use dump::DumpState;

pub const NETLINK_SNDBUF_DEFAULT: usize = 212_992;
/// Linux default NETLINK receive budget; one owner keeps loss, `sk_err`, and poll coherent.
pub const NETLINK_RCVBUF_DEFAULT: usize = NETLINK_SNDBUF_DEFAULT;
pub const NETLINK_SEND_OVERHEAD: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendError {
    Emsgsize,
    /// The destination's receive budget refused the message and the sender
    /// could not wait for it: a non-blocking send, or a send timeout that
    /// expired first.
    Again,
    /// A signal reached a sender blocked on that budget.
    Interrupted,
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
    /// The one socket base every family embeds. Both timeouts, the buffer
    /// budgets, the credential and label switches, SO_PRIORITY, SO_MARK, the
    /// timestamp word, the device binding and the generic flag/scalar area all
    /// live there, so a SOL_SOCKET write on a netlink fd is stored in the same
    /// word the SOL_SOCKET read answers from — and in the same word the
    /// internet and virtual-socket families use.
    pub base: net::SockBase,
    pub protocol: u16,
    pub security_sid: AtomicU32,
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
    /// The one socket-owned multipart dump continuation, if any.
    pub(crate) dump: Spinlock<DumpState, SockLockClass>,
    pub poll_subs: Arc<vfs::PollSubscribers>,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
    /// Senders blocked on THIS socket's receive budget, woken when its queue
    /// drains — the wait a refused unicast serves.
    #[cfg(target_os = "oxide-kernel")]
    pub space_waiters: sched::live::WaitList,
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

    /// Whether the caller may administer this socket's own network namespace.
    /// # C: O(namespace depth)
    pub(crate) fn may_admin_net(&self) -> bool {
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
            base: net::SockBase::with_buffers(NETLINK_SNDBUF_DEFAULT as i32,
                NETLINK_RCVBUF_DEFAULT as i32),
            protocol,
            security_sid: AtomicU32::new(security::network::new_netlink_socket_label(protocol)),
            net_ns: Arc::clone(net_ns),
            opener_user_ns,
            opener_caps,
            port_id: AtomicU32::new(alloc_port_id()),
            groups: crate::groups::GroupBitmap::new(),
            dst_port_id: AtomicU32::new(crate::NETLINK_UNCONNECTED_PORT_ID),
            dst_groups: AtomicU32::new(crate::NETLINK_UNCONNECTED_GROUPS),
            connected: AtomicBool::new(false),
            ino: core::sync::atomic::AtomicU64::new(0),
            flags: crate::sockflags::NetlinkFlags::new(),
            rx_congested: AtomicBool::new(false),
            rx_drops: AtomicUsize::new(0),
            error: net::SocketError::new(),
            bpf_filter: Arc::new(net::bpf_filter::SocketFilter::new()),
            rx_queue: Spinlock::new(ReceiveQueue::new()),
            dump: Spinlock::new(DumpState::new()),
            poll_subs: Arc::new(vfs::PollSubscribers::new()),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            space_waiters: sched::live::WaitList::new(),
        }
    }

    /// Whether one multipart dump is still generating replies for this socket.
    /// # C: O(1)
    fn dump_active(&self) -> bool { self.dump.lock().active() }

    fn start_dump(&self, reply: Vec<u8>) -> Result<Vec<u8>, ()> {
        self.dump.lock().start(reply)
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
        net::security_admission::check_socket(
            net::net_ns::namespace_id(&self.net_ns), net::socket_args::AF_NETLINK_WIRE,
            security::network::Operation::Shutdown,
            self.security_sid.load(Ordering::Acquire), self.security_class(),
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
    /// Consume the error the socket-option read reports: the fatal one first,
    /// and only when there is none the non-fatal one. # C: O(1)
    pub fn take_reported_error(&self) -> i32 { self.error.take_reported() }

    /// Observe whether a socket error is pending without consuming it. # C: O(1)
    pub fn has_pending_recv_error(&self) -> bool { self.error.has() }

    /// Admit one userspace datagram before payload pages are copied. # C: O(1)
    pub fn preflight_send(&self, len: usize) -> Result<(), SendError> {
        let limit = self.base.sndbuf_bytes().saturating_sub(NETLINK_SEND_OVERHEAD);
        if len > limit { Err(SendError::Emsgsize) } else { Ok(()) }
    }

    /// Commit one admitted userspace datagram through canonical protocol routing.
    /// Taking the decoded destination whole keeps the port and the group from
    /// ever being supplied in the wrong order. # C: O(len + listeners)
    pub fn send_to(&self, buf: &[u8], dest: crate::NlDest, nonblock: bool)
        -> Result<usize, SendError>
    {
        self.preflight_send(buf.len())?;
        // Linux broadcasts before attempting the unicast half of a combined
        // port/group destination. The named port and sender are excluded from
        // that broadcast, so neither receives a duplicate.
        if dest.group != 0 && self.protocol != proto::NETLINK_KOBJECT_UEVENT {
            crate::multicast_from_user(self, dest.port_id, dest.group, buf);
        }
        if dest.port_id != 0 {
            match crate::unicast_port(self, dest.port_id, buf, nonblock) {
                crate::admission::Unicast::NoPort =>
                    return Err(SendError::Backend(vfs::VfsError::Econnrefused)),
                crate::admission::Unicast::Again => return Err(SendError::Again),
                crate::admission::Unicast::Interrupted => return Err(SendError::Interrupted),
                // A message the destination's filter dropped still reports the
                // length the caller handed over, as a delivered one does.
                crate::admission::Unicast::Dropped | crate::admission::Unicast::Queued => {}
            }
            return Ok(buf.len());
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
        if rtnetlink::is_dump(hdr) && self.dump_active() {
            self.enqueue(rtnetlink::nlmsg_ack_pub(hdr, -(vfs::VfsError::Ebusy as i32)));
            return;
        }
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
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETLINK) => rtnetlink::handle_getlink_with_access(net_ns, hdr, msg, strict, |target| self.may_admin_net_for(target)),
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
            | (proto::NETLINK_ROUTE, rtnetlink::RTM_DELLINK)
            | (proto::NETLINK_ROUTE, rtnetlink::RTM_SETLINK) => rtnetlink::handle_link_in(net_ns, hdr, msg),
            (proto::NETLINK_GENERIC, _) => genetlink::handle(msg, net_ns, self.genl_cred()),
            (proto::NETLINK_AUDIT, _) => crate::audit::handle(self, hdr, msg),
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
        if rtnetlink::is_dump(hdr)
            && Nlmsghdr::parse(&reply).is_some_and(|first| first.nlmsg_flags & flags::NLM_F_MULTI != 0) {
            match self.start_dump(reply) {
                Ok(first) => self.enqueue(first),
                Err(()) => self.enqueue(rtnetlink::nlmsg_ack_pub(hdr, -(vfs::VfsError::Ebusy as i32))),
            }
        } else {
            self.enqueue(reply);
        }
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
        // A notification-only family's kernel socket registers no receive path.
        // Netlink's kernel-socket unicast refuses the message outright in that
        // case; falling through to the dispatch walk would instead answer a
        // request nothing handled, and the reply would land in the reader's own
        // queue where its only consumer expects notifications alone.
        if crate::protocols::notification_only(self.protocol) {
            if dest_groups == 0 { return Err(vfs::VfsError::Econnrefused); }
            return Ok(consumed);
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
            if net::security_admission::check_netlink(
                self.net_ns.id().as_u64(), self.protocol, frame.hdr.nlmsg_type,
                self.security_sid.load(Ordering::Acquire), self.security_class()).is_err() {
                return Err(vfs::VfsError::Eacces);
            }
            self.handle_one(&frame.hdr, &datagram[off..off + frame.msg_len]);
            off += frame.advance;
        }
        Ok(consumed)
    }

    pub fn security_class(&self) -> &'static str {
        match self.protocol {
            proto::NETLINK_ROUTE => "netlink_route_socket",
            proto::NETLINK_SOCK_DIAG => "netlink_tcpdiag_socket",
            proto::NETLINK_NFLOG => "netlink_nflog_socket",
            proto::NETLINK_XFRM => "netlink_xfrm_socket",
            proto::NETLINK_SELINUX => "netlink_selinux_socket",
            proto::NETLINK_AUDIT => "netlink_audit_socket",
            proto::NETLINK_NETFILTER => "netlink_netfilter_socket",
            proto::NETLINK_KOBJECT_UEVENT => "netlink_kobject_uevent_socket",
            proto::NETLINK_GENERIC => "netlink_generic_socket",
            _ => "netlink_socket",
        }
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
mod tests;
