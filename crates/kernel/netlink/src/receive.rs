extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::NetlinkSocket;

#[cfg(feature = "debug-netlink")]
fn trace_rx(event: &'static [u8], value: usize) {
    klog::write_raw(b"[NL-RX event=");
    klog::write_raw(event);
    klog::write_raw(b" value=");
    klog::write_dec_u64(value as u64);
    klog::write_raw(b"]\n");
}

/// One socket-owned NETLINK receive queue.  Byte accounting is retained with
/// the datagrams so multicast overrun and `sk_err` share one canonical owner.
pub(crate) struct ReceiveQueue {
    datagrams: alloc::collections::VecDeque<(Vec<u8>, u32)>,
    bytes: usize,
}

impl ReceiveQueue {
    pub(crate) const fn new() -> Self {
        Self { datagrams: alloc::collections::VecDeque::new(), bytes: 0 }
    }

    fn push(&mut self, bytes: Vec<u8>, src_port: u32) {
        self.bytes = self.bytes.saturating_add(bytes.len());
        self.datagrams.push_back((bytes, src_port));
    }

    fn pop(&mut self) -> Option<(Vec<u8>, u32)> {
        let dgram = self.datagrams.pop_front()?;
        self.bytes = self.bytes.saturating_sub(dgram.0.len());
        Some(dgram)
    }

    pub(crate) fn is_empty(&self) -> bool { self.datagrams.is_empty() }
}

/// One kernel-owned NETLINK datagram removed from, or observed at, the RX head.
pub struct ReceivedDatagram {
    pub bytes: Vec<u8>,
    pub src_port: u32,
}

/// Canonical result of one NETLINK queue/error observation.
pub enum ReceiveState {
    Datagram(ReceivedDatagram),
    Error(i32),
    Empty,
}

pub(crate) fn vfs_error(errno: i32) -> vfs::VfsError {
    match errno {
        x if x == vfs::VfsError::Eperm as i32 => vfs::VfsError::Eperm,
        x if x == vfs::VfsError::Enoent as i32 => vfs::VfsError::Enoent,
        x if x == vfs::VfsError::Esrch as i32 => vfs::VfsError::Esrch,
        x if x == vfs::VfsError::Eintr as i32 => vfs::VfsError::Eintr,
        x if x == vfs::VfsError::Eio as i32 => vfs::VfsError::Eio,
        x if x == vfs::VfsError::Enxio as i32 => vfs::VfsError::Enxio,
        x if x == vfs::VfsError::Ebadf as i32 => vfs::VfsError::Ebadf,
        x if x == vfs::VfsError::Enomem as i32 => vfs::VfsError::Enomem,
        x if x == vfs::VfsError::Eacces as i32 => vfs::VfsError::Eacces,
        x if x == vfs::VfsError::Efault as i32 => vfs::VfsError::Efault,
        x if x == vfs::VfsError::Eexist as i32 => vfs::VfsError::Eexist,
        x if x == vfs::VfsError::Exdev as i32 => vfs::VfsError::Exdev,
        x if x == vfs::VfsError::Enodev as i32 => vfs::VfsError::Enodev,
        x if x == vfs::VfsError::Enotdir as i32 => vfs::VfsError::Enotdir,
        x if x == vfs::VfsError::Eisdir as i32 => vfs::VfsError::Eisdir,
        x if x == vfs::VfsError::Einval as i32 => vfs::VfsError::Einval,
        x if x == vfs::VfsError::Emfile as i32 => vfs::VfsError::Emfile,
        x if x == vfs::VfsError::Enotty as i32 => vfs::VfsError::Enotty,
        x if x == vfs::VfsError::Etxtbsy as i32 => vfs::VfsError::Etxtbsy,
        x if x == vfs::VfsError::Efbig as i32 => vfs::VfsError::Efbig,
        x if x == vfs::VfsError::Espipe as i32 => vfs::VfsError::Espipe,
        x if x == vfs::VfsError::Emlink as i32 => vfs::VfsError::Emlink,
        x if x == vfs::VfsError::Eagain as i32 => vfs::VfsError::Eagain,
        x if x == vfs::VfsError::Epipe as i32 => vfs::VfsError::Epipe,
        x if x == vfs::VfsError::Erange as i32 => vfs::VfsError::Erange,
        x if x == vfs::VfsError::Erofs as i32 => vfs::VfsError::Erofs,
        x if x == vfs::VfsError::Ebusy as i32 => vfs::VfsError::Ebusy,
        x if x == vfs::VfsError::Enospc as i32 => vfs::VfsError::Enospc,
        x if x == vfs::VfsError::Enotempty as i32 => vfs::VfsError::Enotempty,
        x if x == vfs::VfsError::Enosys as i32 => vfs::VfsError::Enosys,
        x if x == vfs::VfsError::Eloop as i32 => vfs::VfsError::Eloop,
        x if x == vfs::VfsError::Ebade as i32 => vfs::VfsError::Ebade,
        x if x == vfs::VfsError::Enodata as i32 => vfs::VfsError::Enodata,
        x if x == vfs::VfsError::Emsgsize as i32 => vfs::VfsError::Emsgsize,
        x if x == vfs::VfsError::Enonet as i32 => vfs::VfsError::Enonet,
        x if x == vfs::VfsError::Enoprotoopt as i32 => vfs::VfsError::Enoprotoopt,
        x if x == vfs::VfsError::Eproto as i32 => vfs::VfsError::Eproto,
        x if x == vfs::VfsError::Ehostdown as i32 => vfs::VfsError::Ehostdown,
        x if x == vfs::VfsError::Eopnotsupp as i32 => vfs::VfsError::Eopnotsupp,
        x if x == vfs::VfsError::Edestaddrreq as i32 => vfs::VfsError::Edestaddrreq,
        x if x == vfs::VfsError::Eaddrnotavail as i32 => vfs::VfsError::Eaddrnotavail,
        x if x == vfs::VfsError::Enetunreach as i32 => vfs::VfsError::Enetunreach,
        x if x == vfs::VfsError::Ehostunreach as i32 => vfs::VfsError::Ehostunreach,
        x if x == vfs::VfsError::Enobufs as i32 => vfs::VfsError::Enobufs,
        x if x == vfs::VfsError::Enametoolong as i32 => vfs::VfsError::Enametoolong,
        x if x == vfs::VfsError::Enotconn as i32 => vfs::VfsError::Enotconn,
        x if x == vfs::VfsError::Econnreset as i32 => vfs::VfsError::Econnreset,
        x if x == vfs::VfsError::Etimedout as i32 => vfs::VfsError::Etimedout,
        x if x == vfs::VfsError::Econnrefused as i32 => vfs::VfsError::Econnrefused,
        x if x == vfs::VfsError::Euclean as i32 => vfs::VfsError::Euclean,
        x if x == vfs::VfsError::Ecanceled as i32 => vfs::VfsError::Ecanceled,
        x if x == vfs::VfsError::Edquot as i32 => vfs::VfsError::Edquot,
        _ => vfs::VfsError::Eio,
    }
}

impl NetlinkSocket {
    /// Drop a fully-formatted reply buffer onto the RX queue. # C: O(1)
    pub fn enqueue(&self, msg: Vec<u8>) { self.enqueue_from(msg, 0); }

    /// Enqueue one datagram with its sender port and publish receive readiness. # C: O(1)
    pub fn enqueue_from(&self, mut msg: Vec<u8>, src_port: u32) {
        let verdict = self.bpf_filter.verdict(&msg);
        if verdict == 0 { return; }
        msg.truncate(msg.len().min(verdict as usize));
        self.rx_queue.lock().push(msg, src_port);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        self.poll_subs.notify();
    }

    /// Deliver one multicast datagram under Linux NETLINK receive-buffer
    /// pressure.  A failed delivery owns `sk_err=ENOBUFS` and wakeup here.
    /// # C: O(1)
    pub(crate) fn enqueue_multicast(&self, msg: Vec<u8>) -> bool {
        let mut queue = self.rx_queue.lock();
        let fits = queue.bytes.checked_add(msg.len()).is_some_and(|used| {
            used <= self.rcvbuf.load(Ordering::Acquire)
        });
        if fits {
            queue.push(msg, 0);
            drop(queue);
            #[cfg(feature = "debug-netlink")]
            trace_rx(b"multicast-enqueue", self.rx_drops.load(Ordering::Relaxed));
            #[cfg(target_os = "oxide-kernel")]
            self.waiters.wake_all();
            self.poll_subs.notify();
            return true;
        }
        self.rx_drops.fetch_add(1, Ordering::Relaxed);
        let report = !self.no_enobufs.load(Ordering::Acquire)
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

    /// Set the canonical NETLINK receive-buffer budget. # C: O(1)
    pub fn set_receive_buffer(&self, bytes: usize) {
        self.rcvbuf.store(bytes, Ordering::Release);
    }

    /// Enable Linux `NETLINK_NO_ENOBUFS` suppression for multicast loss. # C: O(1)
    pub fn set_no_enobufs(&self, enabled: bool) {
        self.no_enobufs.store(enabled, Ordering::Release);
    }

    /// Pop the head datagram if present. # C: O(1)
    pub fn dequeue(&self) -> Option<(Vec<u8>, u32)> {
        let mut queue = self.rx_queue.lock();
        let dgram = queue.pop();
        if queue.is_empty() { self.rx_congested.store(false, Ordering::Release); }
        dgram
    }

    /// Clone the head datagram without consuming it. # C: O(msg len)
    pub fn peek_front(&self) -> Option<(Vec<u8>, u32)> { self.rx_queue.lock().datagrams.front().cloned() }

    /// Length of the next readable NETLINK datagram. # C: O(1)
    pub fn front_len(&self) -> u32 {
        self.rx_queue.lock().datagrams.front().map(|(msg, _)| msg.len() as u32).unwrap_or(0)
    }

    /// Observe one receive event with Linux `sk_err`-before-queue ordering. # C: O(msg len)
    pub fn receive(&self, peek: bool) -> ReceiveState {
        let mut queue = self.rx_queue.lock();
        // `__skb_try_recv_datagram()` calls `sock_error()` before it examines
        // `sk_receive_queue`; keep both observations under the publication lock.
        let error = self.error.take();
        if error != 0 { return ReceiveState::Error(error); }
        if let Some((bytes, src_port)) = queue.datagrams.front().cloned() {
            if !peek {
                queue.pop();
                if queue.is_empty() { self.rx_congested.store(false, Ordering::Release); }
            }
            return ReceiveState::Datagram(ReceivedDatagram { bytes, src_port });
        }
        ReceiveState::Empty
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
            unsafe { self.waiters.park_interruptible_with_deadline(0); }
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
        socket.set_receive_buffer(retained.len());
        socket.enqueue(retained.clone());
        assert!(!socket.enqueue_multicast(alloc::vec![1]));
        assert_eq!(socket.rx_drops.load(Ordering::Acquire), 1);
        assert_eq!(socket.poll() & vfs::POLL_ERR, vfs::POLL_ERR);
        assert!(matches!(socket.receive(false), ReceiveState::Error(errno)
            if errno == vfs::VfsError::Enobufs as i32));
        assert_datagram(socket.receive(false), &retained);

        assert!(socket.enqueue_multicast(alloc::vec![2]));
        assert!(!socket.enqueue_multicast(alloc::vec![3, 4, 5]));
        assert!(matches!(socket.receive(false), ReceiveState::Error(errno)
            if errno == vfs::VfsError::Enobufs as i32));
    }

    #[test]
    fn netlink_no_enobufs_suppresses_only_the_error_notification() {
        let socket = socket();
        socket.set_receive_buffer(0);
        socket.set_no_enobufs(true);
        assert!(!socket.enqueue_multicast(alloc::vec![1]));
        assert_eq!(socket.rx_drops.load(Ordering::Acquire), 1);
        assert_eq!(socket.poll() & vfs::POLL_ERR, 0);
        assert!(matches!(socket.receive(false), ReceiveState::Empty));
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
