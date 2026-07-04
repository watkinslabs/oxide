extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Socket as SockLockClass, Spinlock};

use crate::{flags, genetlink, invoke_netfilter, listeners, proto, rtnetlink, rtnetlink_rule, sock_diag, Nlmsghdr, nlmsg_align};
use crate::wire::alloc_port_id;

/// AF_NETLINK socket. Owns an in-memory RX queue of nlmsg-aligned
/// reply buffers.
pub struct NetlinkSocket {
    pub protocol: u16,
    pub port_id: AtomicU32,
    pub groups: AtomicU32,
    pub rx_queue: Spinlock<VecDeque<(Vec<u8>, u32)>, SockLockClass>,
    pub poll_subs: Arc<vfs::PollSubscribers>,
}

impl NetlinkSocket {
    /// # C: O(1)
    pub fn new(protocol: u16) -> Self {
        Self {
            protocol,
            port_id: AtomicU32::new(alloc_port_id()),
            groups: AtomicU32::new(0),
            rx_queue: Spinlock::new(VecDeque::new()),
            poll_subs: Arc::new(vfs::PollSubscribers::new()),
        }
    }

    /// `bind` nl_groups: subscribe to the given group bitmask.
    /// # C: O(1)
    pub fn set_group_mask(&self, mask: u32) { self.groups.store(mask, Ordering::Release); }

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

    /// Dispatch a single parsed request header.
    /// # C: O(reply build)
    fn handle_one(&self, hdr: &Nlmsghdr, msg: &[u8]) {
        let reply = match (self.protocol, hdr.nlmsg_type) {
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETLINK) => rtnetlink::handle_getlink(hdr),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETADDR) => rtnetlink::handle_getaddr(hdr),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWADDR) => rtnetlink::handle_newaddr(hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELADDR) => rtnetlink::handle_deladdr(hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETROUTE) => rtnetlink::handle_getroute(hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_GETRULE) => rtnetlink_rule::handle_getrule(hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWRULE) => rtnetlink_rule::handle_newrule(hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELRULE) => rtnetlink_rule::handle_delrule(hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWROUTE) => rtnetlink::handle_newroute(hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_DELROUTE) => rtnetlink::handle_delroute(hdr, msg),
            (proto::NETLINK_ROUTE, rtnetlink::RTM_NEWLINK)
            | (proto::NETLINK_ROUTE, rtnetlink::RTM_SETLINK) => rtnetlink::handle_setlink(hdr, msg),
            (proto::NETLINK_GENERIC, _) => genetlink::handle(msg),
            (proto::NETLINK_NETFILTER, _) => invoke_netfilter(msg),
            (proto::NETLINK_SOCK_DIAG, sock_diag::SOCK_DIAG_BY_FAMILY)
            | (proto::NETLINK_SOCK_DIAG, sock_diag::TCPDIAG_GETSOCK) => sock_diag::handle(hdr, msg),
            _ => {
                if (hdr.nlmsg_flags & flags::NLM_F_ACK) != 0 {
                    rtnetlink::nlmsg_ack_pub(hdr, 0)
                } else {
                    let mut done = alloc::vec![0u8; Nlmsghdr::SIZE];
                    Nlmsghdr::done(hdr.nlmsg_seq, hdr.nlmsg_pid).write_to(&mut done);
                    done
                }
            }
        };
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
        use vfs::{POLL_IN, POLL_OUT};
        let mut mask = POLL_OUT;
        if !self.rx_queue.lock().is_empty() { mask |= POLL_IN; }
        mask
    }
}
