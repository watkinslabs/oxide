use super::*;

impl TcpEntry {
    /// Publish a transport error and wake all socket observers. # C: O(1)
    pub fn set_error(&self, errno: i32) -> bool {
        // Hold the connection resource lock while publishing the error. Wait
        // registration holds this lock until the task is on rx_waiters, so a
        // publisher cannot pass the recheck and wake before the park exists.
        let conn = self.conn.lock();
        if !self.error.set(errno) { return false; }
        drop(conn);
        #[cfg(target_os = "oxide-kernel")]
        self.rx_waiters.wake_all();
        let slot = self.poll_subs.lock().clone();
        if let Some(weak) = slot {
            if let Some(s) = weak.upgrade() { s.notify_mask(vfs::POLL_ERR | vfs::POLL_OUT); }
        }
        true
    }

    /// Publish terminal connection state before waking every blocked observer. # C: O(1)
    pub fn close_and_wake(&self) {
        self.close_with(|| {
            #[cfg(target_os = "oxide-kernel")]
            self.rx_waiters.wake_all();
        });
    }

    /// Testable close publication primitive used by `close_and_wake`. # C: O(1)
    pub(crate) fn close_with(&self, wake: impl FnOnce()) {
        let mut conn = self.conn.lock();
        conn.state = crate::tcp_state::TcpState::Closed;
        drop(conn);
        wake();
        if let Some(weak) = self.poll_subs.lock().clone() {
            if let Some(subs) = weak.upgrade() { subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT | vfs::POLL_HUP); }
        }
    }

    /// Transport readiness before socket-level shutdown overlays. # C: O(1)
    pub fn poll_mask(&self) -> u32 {
        let c = self.conn.lock();
        let mut mask = if c.state == crate::tcp_state::TcpState::SynSent && !self.error.has() {
            0
        } else { vfs::POLL_OUT };
        if self.error.has() { mask |= vfs::POLL_ERR; }
        if !c.recv_buf.is_empty() || c.has_urgent() { mask |= vfs::POLL_IN; }
        if c.state == crate::tcp_state::TcpState::Closed || c.state.is_closing() { mask |= vfs::POLL_HUP; }
        mask
    }

    /// F181a: register owning InetSocket's epoll subscribers. # C: O(1)
    pub fn register_poll_subs(&self, subs: &alloc::sync::Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(alloc::sync::Arc::downgrade(subs));
    }

    /// Atomically classify or arm a blocking active-open wait. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_connect_wait(&self, deadline_ns: u64) -> TcpConnectWait {
        self.arm_connect_wait_with(|| {
            // SAFETY: the connection lock serializes state publication with wait registration.
            unsafe { self.rx_waiters.park_interruptible_with_deadline(deadline_ns); }
        })
    }

    /// Testable lock-coupled connect wait primitive. # C: O(1)
    pub(crate) fn arm_connect_wait_with(&self, arm: impl FnOnce()) -> TcpConnectWait {
        let conn = self.conn.lock();
        if conn.state.is_established() { return TcpConnectWait::Established; }
        if conn.state == crate::tcp_state::TcpState::Closed || self.error.has() {
            return TcpConnectWait::Closed;
        }
        arm(); drop(conn); TcpConnectWait::Parked
    }

    /// Atomically recheck TCP transmit capacity and arm current on the ACK wait list. # C: O(retx)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_transmit_wait(&self, write_shut: &::core::sync::atomic::AtomicBool,
        sndbuf_cap: usize, deadline_ns: u64) -> bool {
        self.arm_transmit_wait_with(write_shut, sndbuf_cap, || {
            // SAFETY: process context; connection lock serializes ACK and close publication.
            unsafe { self.rx_waiters.park_interruptible_with_deadline(deadline_ns); }
        })
    }

    /// Testable lock-coupled transmit wait primitive. # C: O(retx)
    pub(crate) fn arm_transmit_wait_with(&self,
        write_shut: &::core::sync::atomic::AtomicBool, sndbuf_cap: usize,
        arm: impl FnOnce()) -> bool {
        let conn = self.conn.lock();
        if write_shut.load(::core::sync::atomic::Ordering::Acquire) || self.error.has()
            || tcp_send_closed(conn.state) || tcp_transmit_ready(&conn, sndbuf_cap) { return false; }
        arm(); drop(conn); true
    }
}
