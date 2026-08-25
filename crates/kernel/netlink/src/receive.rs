extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use net::sock_opts::SenderCreds;

use crate::NetlinkSocket;

#[path = "receive/queue.rs"]
mod queue;
pub(crate) use queue::ReceiveQueue;
#[path = "receive/errors.rs"]
mod errors;
pub(crate) use errors::vfs_error;

#[cfg(feature = "debug-netlink")]
fn trace_rx(event: &'static [u8], value: usize) {
    klog::write_raw(b"[NL-RX event=");
    klog::write_raw(event);
    klog::write_raw(b" value=");
    klog::write_dec_u64(value as u64);
    klog::write_raw(b"]\n");
}

/// One kernel-owned NETLINK datagram removed from, or observed at, the RX head.
pub struct ReceivedDatagram {
    pub bytes: Vec<u8>,
    pub src_port: u32,
    /// `NETLINK_CB(skb).dst_group`: zero for unicast, otherwise the multicast
    /// group delivered through `NETLINK_PKTINFO` when the receiver requested it.
    pub multicast_group: u32,
    /// Source namespace as the receiving namespace names it, for
    /// `NETLINK_LISTEN_ALL_NSID`; absent when no mapping exists.
    pub nsid: Option<i32>,
    /// `NETLINK_CB(skb).creds`: whoever produced this datagram. The default
    /// all-zero set names the kernel.
    pub creds: SenderCreds,
    /// Security label stamped before this datagram entered the queue.
    pub security: Option<Vec<u8>>,
}

/// Canonical result of one NETLINK queue/error observation.
pub enum ReceiveState {
    Datagram(ReceivedDatagram),
    Error(i32),
    Empty,
}

impl NetlinkSocket {
    fn advance_dump(&self) {
        let next = self.dump.lock().next_chunk();
        if let Some(reply) = next { self.enqueue(reply); }
    }

    /// Drop a fully-formatted reply buffer onto the RX queue. # C: O(1)
    pub fn enqueue(&self, msg: Vec<u8>) { self.enqueue_from(msg, 0); }

    /// Enqueue one kernel-originated datagram with its sender port. # C: O(1)
    pub fn enqueue_from(&self, msg: Vec<u8>, src_port: u32) {
        self.enqueue_from_creds(msg, src_port, SenderCreds::default());
    }

    /// Enqueue one datagram with its sender port and credentials, then publish
    /// receive readiness. # C: O(1)
    pub fn enqueue_from_creds(&self, mut msg: Vec<u8>, src_port: u32, creds: SenderCreds) {
        let verdict = self.bpf_filter.verdict(&msg);
        if verdict == 0 { return; }
        msg.truncate(msg.len().min(verdict as usize));
        #[cfg(target_os = "oxide-kernel")]
        let security = {
            let sender = sched::live::current().map(|task| alloc::sync::Arc::clone(&task.pid));
            security::network::message_security(sender.as_deref())
        };
        #[cfg(not(target_os = "oxide-kernel"))]
        let security = security::network::message_security(None);
        self.rx_queue.lock().push(msg, src_port, 0, None, creds, security);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        self.poll_subs.notify();
    }

    /// Deliver one multicast datagram under Linux NETLINK receive-buffer
    /// pressure.  A failed delivery owns `sk_err=ENOBUFS` and wakeup here.
    /// # C: O(1)
    pub(crate) fn enqueue_multicast(&self, msg: Vec<u8>, group: u32, nsid: Option<i32>) -> bool {
        self.enqueue_multicast_from(msg, 0, group, nsid, SenderCreds::default(),
            security::network::message_security(None))
    }

    /// Deliver one userspace multicast while retaining the sender metadata
    /// Linux stamps into `NETLINK_CB(skb)`. # C: O(1)
    pub(crate) fn enqueue_user_multicast(&self, msg: Vec<u8>, src_port: u32, group: u32,
        creds: SenderCreds) -> bool
    {
        #[cfg(target_os = "oxide-kernel")]
        let security = {
            let sender = sched::live::current().map(|task| alloc::sync::Arc::clone(&task.pid));
            security::network::message_security(sender.as_deref())
        };
        #[cfg(not(target_os = "oxide-kernel"))]
        let security = security::network::message_security(None);
        self.enqueue_multicast_from(msg, src_port, group, None, creds, security)
    }

    fn enqueue_multicast_from(&self, msg: Vec<u8>, src_port: u32, group: u32,
        nsid: Option<i32>, creds: SenderCreds, security: Option<Vec<u8>>) -> bool
    {
        let mut queue = self.rx_queue.lock();
        let fits = queue.bytes.checked_add(msg.len()).is_some_and(|used| {
            used <= self.base.rcvbuf_bytes()
        });
        if fits {
            queue.push(msg, src_port, group, nsid, creds, security);
            drop(queue);
            #[cfg(feature = "debug-netlink")]
            trace_rx(b"multicast-enqueue", self.rx_drops.load(Ordering::Relaxed));
            #[cfg(target_os = "oxide-kernel")]
            self.waiters.wake_all();
            self.poll_subs.notify();
            return true;
        }
        self.rx_drops.fetch_add(1, Ordering::Relaxed);
        let report = !self.flags.get(crate::sockflags::F_RECV_NO_ENOBUFS)
            && !self.rx_congested.swap(true, Ordering::AcqRel);
        if report { self.error.set(vfs::VfsError::Enobufs as i32); }
        drop(queue);
        if report {
            #[cfg(feature = "debug-netlink")]
            trace_rx(b"overrun-skerr", self.rx_drops.load(Ordering::Relaxed));
            #[cfg(target_os = "oxide-kernel")]
            self.waiters.wake_all();
            self.poll_subs.notify_mask(vfs::POLL_ERR);
        }
        #[cfg(feature = "debug-netlink")]
        if !report { trace_rx(b"overrun-suppressed", self.rx_drops.load(Ordering::Relaxed)); }
        false
    }

    /// Bytes delivered to this socket and not yet read — the reference's
    /// `sk_rmem_alloc`, and the one observable that separates a message the
    /// kernel never delivered from one the process never read. # C: O(1)
    pub fn queued_bytes(&self) -> usize { self.rx_queue.lock().bytes }

    /// Set the canonical NETLINK receive-buffer budget. # C: O(1)
    pub fn set_receive_buffer(&self, bytes: usize) {
        self.base.set_rcvbuf_bytes(bytes);
    }

    /// Enable Linux `NETLINK_NO_ENOBUFS` suppression for multicast loss. # C: O(1)
    pub fn set_no_enobufs(&self, enabled: bool) {
        self.flags.assign(crate::sockflags::F_RECV_NO_ENOBUFS, enabled);
        if enabled { self.rx_congested.store(false, Ordering::Release); }
    }

    /// Pop the head datagram if present. # C: O(1)
    pub fn dequeue(&self) -> Option<(Vec<u8>, u32)> {
        let mut queue = self.rx_queue.lock();
        let dgram = queue.pop();
        let drained = queue.is_empty();
        if drained { self.rx_congested.store(false, Ordering::Release); }
        drop(queue);
        if drained { self.wake_space_waiters(); }
        if dgram.is_some() { self.advance_dump(); }
        dgram.map(|(bytes, src_port, _, _, _, _)| (bytes, src_port))
    }

    /// Clone the head datagram without consuming it. # C: O(msg len)
    pub fn peek_front(&self) -> Option<(Vec<u8>, u32)> {
        self.rx_queue.lock().datagrams.front().map(|(bytes, src_port, _, _, _, _)| (bytes.clone(), *src_port))
    }

    /// Length of the next readable NETLINK datagram. # C: O(1)
    pub fn front_len(&self) -> u32 {
        self.rx_queue.lock().datagrams.front().map(|(msg, _, _, _, _, _)| msg.len() as u32).unwrap_or(0)
    }

    /// Observe one receive event with Linux `sk_err`-before-queue ordering. # C: O(msg len)
    pub fn receive(&self, peek: bool) -> ReceiveState {
        let mut queue = self.rx_queue.lock();
        // `__skb_try_recv_datagram()` calls `sock_error()` before it examines
        // `sk_receive_queue`; keep both observations under the publication lock.
        let error = self.error.take();
        if error != 0 { return ReceiveState::Error(error); }
        let state = if let Some((bytes, src_port, multicast_group, nsid, creds, security)) = queue.datagrams.front().cloned() {
            if !peek {
                queue.pop();
                if queue.is_empty() { self.rx_congested.store(false, Ordering::Release); }
            }
            ReceiveState::Datagram(ReceivedDatagram { bytes, src_port, multicast_group, nsid, creds, security })
        } else {
            ReceiveState::Empty
        };
        let drained = queue.is_empty();
        drop(queue);
        if drained { self.wake_space_waiters(); }
        if !peek && matches!(state, ReceiveState::Datagram(_)) { self.advance_dump(); }
        state
    }

    /// SO_RCVTIMEO as the absolute monotonic deadline used for interrupted
    /// receives. `0` remains the shared no-timeout value. One owner covers
    /// both inode reads and the recvmsg syscall path.
    /// # C: O(1)
    pub fn recv_deadline_ns(&self) -> u64 {
        net::sock_intr::deadline_from_timeo(self.base.rcvtimeo_u64())
    }

    /// SO_SNDTIMEO as the absolute monotonic deadline that bounds a sender
    /// blocked on a destination's receive budget. # C: O(1)
    pub fn send_deadline_ns(&self) -> u64 {
        net::sock_intr::deadline_from_timeo(self.base.sndtimeo_u64())
    }

    #[cfg(any(test, target_os = "oxide-kernel"))]
    fn arm_receive_wait_with(&self, arm: impl FnOnce()) -> bool {
        let queue = self.rx_queue.lock();
        if !queue.is_empty() || self.error.has() { return false; }
        arm();
        drop(queue);
        true
    }

    /// Register the current task only if queue and error remain empty. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_receive_wait(&self) -> bool {
        self.arm_receive_wait_with(|| {
            #[cfg(feature = "debug-netlink")]
            trace_rx(b"wait-arm", 0);
            // SAFETY: syscall process context owns the running task; RX lock
            // prevents queue/error publication between recheck and registration.
            unsafe { self.waiters.prepare_to_wait_interruptible(); }
        })
    }

    /// Pop one queued reply into `buf` using datagram semantics. # C: O(msg len)
    pub fn read(&self, buf: &mut [u8]) -> vfs::KResult<usize> {
        match self.receive(false) {
            ReceiveState::Datagram(dgram) => {
                let dgram = dgram.bytes;
                let n = dgram.len().min(buf.len());
                buf[..n].copy_from_slice(&dgram[..n]);
                Ok(n)
            }
            ReceiveState::Error(errno) => Err(vfs_error(errno)),
            ReceiveState::Empty => Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{ReceiveState, NetlinkSocket};
    use crate::proto;

    fn verdict_runner(_kind: net::bpf_filter::FilterKind, insns: &[u8], _packet: &[u8]) -> u32 {
        u32::from_ne_bytes(insns.try_into().unwrap())
    }

    fn socket() -> NetlinkSocket {
        NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial())
    }

    fn assert_datagram(state: ReceiveState, expected: &[u8]) {
        match state {
            ReceiveState::Datagram(dgram) => assert_eq!(dgram.bytes, expected),
            _ => panic!("expected datagram"),
        }
    }

    #[test]
    fn error_precedes_queued_datagram() {
        let socket = socket();
        let error = vfs::VfsError::Enobufs as i32;
        socket.enqueue(alloc::vec![1, 2, 3]);
        assert!(socket.set_pending_recv_error(error));
        assert!(matches!(socket.receive(false), ReceiveState::Error(got) if got == error));
        assert_datagram(socket.receive(false), &[1, 2, 3]);
    }

    #[test]
    fn read_consumes_pending_error_before_queue() {
        let socket = socket();
        let error = vfs::VfsError::Enobufs as i32;
        socket.enqueue(alloc::vec![9, 8]);
        assert!(socket.set_pending_recv_error(error));
        let mut buf = [0; 2];
        assert_eq!(socket.read(&mut buf), Err(vfs::VfsError::Enobufs));
        assert_eq!(socket.read(&mut buf), Ok(2));
        assert_eq!(buf, [9, 8]);
        assert_eq!(socket.read(&mut buf), Ok(0));
    }

    #[test]
    fn every_read_adapter_preserves_connection_refused_error() {
        let socket = socket();
        assert!(socket.set_pending_recv_error(vfs::VfsError::Econnrefused as i32));
        assert_eq!(socket.read(&mut [0; 1]), Err(vfs::VfsError::Econnrefused));
        assert_eq!(super::vfs_error(vfs::VfsError::Econnreset as i32), vfs::VfsError::Econnreset);
    }

    #[test]
    fn read_error_adapter_preserves_other_supported_errno_values() {
        for error in [vfs::VfsError::Efault, vfs::VfsError::Einval, vfs::VfsError::Eintr] {
            assert_eq!(super::vfs_error(error as i32), error);
        }
    }

    #[test]
    fn error_precedes_later_queued_datagram() {
        let socket = socket();
        let error = vfs::VfsError::Enobufs as i32;
        assert!(socket.set_pending_recv_error(error));
        socket.enqueue(alloc::vec![4, 5, 6]);
        assert!(matches!(socket.receive(false), ReceiveState::Error(got) if got == error));
        assert_datagram(socket.receive(false), &[4, 5, 6]);
    }

    #[test]
    fn multicast_overrun_sets_sk_err_once_and_preserves_queued_data() {
        let socket = socket();
        let retained = alloc::vec![7, 8, 9];
        let queue_entry_bytes = core::mem::size_of::<(alloc::vec::Vec<u8>, u32, u32,
            net::sock_opts::SenderCreds, Option<alloc::vec::Vec<u8>>) >();
        socket.set_receive_buffer(retained.len() + queue_entry_bytes);
        socket.enqueue(retained.clone());
        assert!(!socket.enqueue_multicast(alloc::vec![1], 5, None));
        assert_eq!(socket.rx_drops.load(Ordering::Acquire), 1);
        assert_eq!(socket.poll() & vfs::POLL_ERR, vfs::POLL_ERR);
        assert!(matches!(socket.receive(false), ReceiveState::Error(errno)
            if errno == vfs::VfsError::Enobufs as i32));
        assert_datagram(socket.receive(false), &retained);

        assert!(socket.enqueue_multicast(alloc::vec![2], 5, None));
        assert!(!socket.enqueue_multicast(retained, 5, None));
        assert!(matches!(socket.receive(false), ReceiveState::Error(errno)
            if errno == vfs::VfsError::Enobufs as i32));
    }

    #[test]
    fn netlink_no_enobufs_suppresses_only_the_error_notification() {
        let socket = socket();
        socket.set_receive_buffer(0);
        socket.set_no_enobufs(true);
        assert!(!socket.enqueue_multicast(alloc::vec![1], 5, None));
        assert_eq!(socket.rx_drops.load(Ordering::Acquire), 1);
        assert_eq!(socket.poll() & vfs::POLL_ERR, 0);
        assert!(matches!(socket.receive(false), ReceiveState::Empty));
    }

    #[test]
    fn multicast_delivery_retains_the_group_for_pktinfo() {
        let socket = socket();
        assert!(socket.enqueue_multicast(alloc::vec![7, 8], 5, None));
        match socket.receive(false) {
            ReceiveState::Datagram(dgram) => {
                assert_eq!(dgram.bytes, [7, 8]);
                assert_eq!(dgram.src_port, 0);
                assert_eq!(dgram.multicast_group, 5);
            }
            _ => panic!("expected multicast datagram"),
        }
    }

    #[test]
    fn peek_reports_pending_error_before_preserving_datagram() {
        let socket = socket();
        let error = vfs::VfsError::Enobufs as i32;
        socket.enqueue(alloc::vec![4, 5, 6]);
        assert!(socket.set_pending_recv_error(error));
        assert!(matches!(socket.receive(true), ReceiveState::Error(got) if got == error));
        assert_datagram(socket.receive(true), &[4, 5, 6]);
        assert_datagram(socket.receive(false), &[4, 5, 6]);
    }

    #[test]
    fn visible_queue_or_error_never_arms_wait() {
        let arms = AtomicUsize::new(0);
        let queue = socket();
        queue.enqueue(alloc::vec![7]);
        assert!(!queue.arm_receive_wait_with(|| { arms.fetch_add(1, Ordering::Relaxed); }));

        let error = socket();
        assert!(error.set_pending_recv_error(vfs::VfsError::Enobufs as i32));
        assert!(!error.arm_receive_wait_with(|| { arms.fetch_add(1, Ordering::Relaxed); }));
        assert_eq!(arms.load(Ordering::Relaxed), 0);

        let empty = socket();
        assert!(empty.arm_receive_wait_with(|| { arms.fetch_add(1, Ordering::Relaxed); }));
        assert_eq!(arms.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn pending_error_publication_waits_for_receive_arm_lock() {
        use alloc::sync::Arc;
        use std::sync::mpsc;
        use std::time::Duration;

        let socket = Arc::new(socket());
        let (armed_tx, armed_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (published_tx, published_rx) = mpsc::channel();
        let error = vfs::VfsError::Enobufs as i32;

        std::thread::scope(|scope| {
            let waiter = socket.clone();
            scope.spawn(move || {
                assert!(waiter.arm_receive_wait_with(|| {
                    armed_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                }));
            });
            armed_rx.recv_timeout(Duration::from_secs(2)).expect("receive wait armed");

            let publisher = socket.clone();
            scope.spawn(move || {
                assert!(publisher.set_pending_recv_error(error));
                published_tx.send(()).unwrap();
            });
            assert!(published_rx.recv_timeout(Duration::from_millis(20)).is_err(),
                "error publication passed the receive arm lock");
            release_tx.send(()).unwrap();
            published_rx.recv_timeout(Duration::from_secs(2)).expect("error published");
        });

        assert!(matches!(socket.receive(false), ReceiveState::Error(got) if got == error));
        assert!(socket.arm_receive_wait_with(|| {}));
        assert!(socket.set_pending_recv_error(error));
        assert!(!socket.arm_receive_wait_with(|| panic!("pending error armed")));
    }

    #[test]
    fn published_error_after_wait_arm_is_observed_without_rearming() {
        let socket = socket();
        let error = vfs::VfsError::Econnreset as i32;

        assert!(socket.arm_receive_wait_with(|| {}));
        assert!(socket.set_pending_recv_error(error));
        assert!(matches!(socket.receive(false), ReceiveState::Error(got) if got == error));
        assert!(socket.arm_receive_wait_with(|| {}));
    }

    #[test]
    fn filter_sees_raw_datagram_drops_zero_and_truncates_positive() {
        net::bpf_filter::install_bpf_filter_runner(verdict_runner);
        let socket = socket();
        socket.bpf_filter.attach(net::bpf_filter::FilterProgram {
            kind: net::bpf_filter::FilterKind::Ebpf, insns: 3u32.to_ne_bytes().to_vec(),
        }).unwrap();
        socket.enqueue_from(alloc::vec![1, 2, 3, 4, 5], 42);
        match socket.receive(false) {
            ReceiveState::Datagram(dgram) => {
                assert_eq!(dgram.bytes, [1, 2, 3]);
                assert_eq!(dgram.src_port, 42);
            }
            _ => panic!("expected truncated datagram"),
        }

        socket.bpf_filter.attach(net::bpf_filter::FilterProgram {
            kind: net::bpf_filter::FilterKind::Ebpf, insns: 0u32.to_ne_bytes().to_vec(),
        }).unwrap();
        socket.enqueue(alloc::vec![6, 7, 8]);
        assert!(matches!(socket.receive(false), ReceiveState::Empty));
    }
}
