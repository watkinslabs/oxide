//! VSOCK connection timeout and receive-wait ownership.

use core::sync::atomic::Ordering;

use super::{VsockConn, VsockState};

impl VsockConn {
    /// Replace this connection's absolute-wait duration before or during a
    /// pending connect. # C: O(1)
    pub fn set_connect_timeout_ns(&self, timeout_ns: u64) {
        self.connect_timeout_ns.store(timeout_ns, Ordering::Release);
    }

    /// Read the socket-owned connect duration retained by this connection.
    /// # C: O(1)
    pub fn connect_timeout_ns(&self) -> u64 {
        self.connect_timeout_ns.load(Ordering::Acquire)
    }

    fn arm_recv_wait_with(&self, sock: &crate::vsock_socket::VsockSocket, offset: usize,
                          arm: impl FnOnce()) -> bool {
        let state = self.st.lock();
        let rx = self.rx.lock();
        if rx.len() > offset || matches!(*state, VsockState::RcvShutdown | VsockState::Closed)
            || sock.has_pending_recv_error() || sock.read_shut.load(Ordering::Acquire)
        { return false; }
        arm();
        drop(rx);
        drop(state);
        true
    }

    /// Atomically recheck receive state and arm one interruptible reader. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_recv_wait(&self, sock: &crate::vsock_socket::VsockSocket, offset: usize,
                         deadline_ns: u64) -> bool {
        self.arm_recv_wait_with(sock, offset, || {
            // SAFETY: state and RX locks serialize terminal/data/error publication with registration.
            unsafe { self.waiters.park_interruptible_with_deadline(deadline_ns); }
        })
    }

    /// Hosted observation of the canonical receive wait gate. # C: O(1)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub fn recv_wait_would_park(&self, sock: &crate::vsock_socket::VsockSocket,
                                offset: usize) -> bool {
        self.arm_recv_wait_with(sock, offset, || {})
    }
}
