extern crate alloc;

use alloc::vec::Vec;

use crate::NetlinkSocket;

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

fn vfs_error(errno: i32) -> vfs::VfsError {
    match errno {
        x if x == vfs::VfsError::Econnreset as i32 => vfs::VfsError::Econnreset,
        x if x == vfs::VfsError::Enobufs as i32 => vfs::VfsError::Enobufs,
        x if x == vfs::VfsError::Etimedout as i32 => vfs::VfsError::Etimedout,
        x if x == vfs::VfsError::Econnrefused as i32 => vfs::VfsError::Econnrefused,
        x if x == vfs::VfsError::Enetunreach as i32 => vfs::VfsError::Enetunreach,
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
        self.rx_queue.lock().push_back((msg, src_port));
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        self.poll_subs.notify();
    }

    /// Pop the head datagram if present. # C: O(1)
    pub fn dequeue(&self) -> Option<(Vec<u8>, u32)> { self.rx_queue.lock().pop_front() }

    /// Clone the head datagram without consuming it. # C: O(msg len)
    pub fn peek_front(&self) -> Option<(Vec<u8>, u32)> { self.rx_queue.lock().front().cloned() }

    /// Length of the next readable NETLINK datagram. # C: O(1)
    pub fn front_len(&self) -> u32 {
        self.rx_queue.lock().front().map(|(msg, _)| msg.len() as u32).unwrap_or(0)
    }

    /// Observe one receive event with Linux queue-before-`sk_err` ordering. # C: O(msg len)
    pub fn receive(&self, peek: bool) -> ReceiveState {
        let mut queue = self.rx_queue.lock();
        if let Some((bytes, src_port)) = queue.front().cloned() {
            if !peek { queue.pop_front(); }
            return ReceiveState::Datagram(ReceivedDatagram { bytes, src_port });
        }
        let error = self.error.take();
        if error != 0 { ReceiveState::Error(error) } else { ReceiveState::Empty }
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
    fn queue_before_error_delivers_queue_then_error() {
        let socket = socket();
        let error = vfs::VfsError::Enobufs as i32;
        socket.enqueue(alloc::vec![1, 2, 3]);
        assert!(socket.set_pending_recv_error(error));
        assert_datagram(socket.receive(false), &[1, 2, 3]);
        assert!(matches!(socket.receive(false), ReceiveState::Error(got) if got == error));
    }

    #[test]
    fn read_consumes_pending_error_after_queue() {
        let socket = socket();
        let error = vfs::VfsError::Enobufs as i32;
        socket.enqueue(alloc::vec![9, 8]);
        assert!(socket.set_pending_recv_error(error));
        let mut buf = [0; 2];
        assert_eq!(socket.read(&mut buf), Ok(2));
        assert_eq!(buf, [9, 8]);
        assert_eq!(socket.read(&mut buf), Err(vfs::VfsError::Enobufs));
        assert_eq!(socket.read(&mut buf), Ok(0));
    }

    #[test]
    fn error_before_queue_delivers_queue_then_error() {
        let socket = socket();
        let error = vfs::VfsError::Enobufs as i32;
        assert!(socket.set_pending_recv_error(error));
        socket.enqueue(alloc::vec![4, 5, 6]);
        assert_datagram(socket.receive(false), &[4, 5, 6]);
        assert!(matches!(socket.receive(false), ReceiveState::Error(got) if got == error));
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
