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

    /// Keep a non-fatal error the connection survived. No observer is woken:
    /// nothing about the connection changed. # C: O(1)
    pub fn set_soft_error(&self, errno: i32) -> bool { self.error.set_soft(errno) }

    /// Consume the error the socket-option read reports. # C: O(1)
    pub fn take_reported_error(&self) -> i32 { self.error.take_reported() }

    /// The fatal error a receive would see, without consuming it. # C: O(1)
    #[cfg(test)]
    pub fn error_snapshot(&self) -> i32 {
        let errno = self.error.take();
        if errno != 0 { self.error.set(errno); }
        errno
    }

    /// Ask for extended errors on this connection's family. # C: O(1)
    #[cfg(test)]
    pub fn set_extended_errors4(&self, on: bool) { self.error.set_recverr4(on); }

    /// Forget the non-fatal error after the peer acknowledged something. # C: O(1)
    pub fn clear_soft_error(&self) { self.error.clear_soft(); }

    /// The non-fatal error the give-up path reports instead of a bare
    /// timeout, or zero when none was recorded. # C: O(1)
    pub fn soft_error(&self) -> i32 { self.error.soft() }

    /// Whether this connection's socket asked for extended errors, per the
    /// family it runs over. # C: O(1)
    pub fn wants_extended_errors(&self, v6: bool) -> bool {
        if v6 { self.error.recverr6() } else { self.error.recverr4() }
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

    /// Wake observers parked on write readiness. # C: O(1)
    pub fn notify_writable(&self) {
        if let Some(weak) = self.poll_subs.lock().clone() {
            if let Some(subs) = weak.upgrade() { subs.notify_mask(vfs::POLL_OUT | vfs::POLL_WRNORM); }
        }
    }

    /// Transport readiness before socket-level shutdown overlays. `POLL_OUT`
    /// follows Linux `tcp_poll`: withheld while
    /// `__sk_stream_is_writeable(sk, 1)` is false, which is what makes a
    /// non-blocking writer park on a full send buffer instead of spinning
    /// `EPOLLOUT` → `send` → `EAGAIN`. `sndbuf_cap` is the same `SO_SNDBUF`
    /// the `tcp_send` path enforces.
    /// # C: O(retx)
    pub fn poll_mask(&self, sndbuf_cap: usize) -> u32 {
        let c = self.conn.lock();
        let writeable = {
            let in_flight: usize = c.retx_q.iter().map(|segment| segment.payload.len()).sum();
            crate::stack::tcp_writable::tcp_writeable_with_lowat(
                c.send_buf.len().saturating_add(in_flight), sndbuf_cap,
                c.send_buf.len(), c.notsent_lowat)
        };
        let mut mask = if c.state == crate::tcp_state::TcpState::SynSent && !self.error.has() {
            0
        } else if writeable { vfs::POLL_OUT | vfs::POLL_WRNORM } else { 0 };
        if self.error.has() { mask |= vfs::POLL_ERR; }
        if !c.recv_buf.is_empty() || c.has_urgent() { mask |= vfs::POLL_IN; }
        // `tcp_poll`: a valid urgent pointer is priority readiness, which is
        // what `select`'s exception set and `EPOLLPRI` report, and what the
        // fasync half classifies as `SIGURG` rather than `SIGIO`.
        if c.has_urgent() { mask |= vfs::POLL_PRI; }
        if c.state == crate::tcp_state::TcpState::Closed {
            mask |= vfs::POLL_IN | vfs::POLL_HUP;
        } else if c.state == crate::tcp_state::TcpState::CloseWait {
            mask |= vfs::POLL_IN | vfs::POLL_RDHUP;
        } else if c.state.is_closing() && !matches!(c.state,
            crate::tcp_state::TcpState::FinWait1 | crate::tcp_state::TcpState::FinWait2) {
            mask |= vfs::POLL_HUP;
        }
        mask
    }

    /// Push a locked `SO_RCVBUF` down to the connection's advertised receive
    /// window (Linux `__sock_set_rcvbuf` → `sk_rcvbuf` → `__tcp_select_window`).
    /// # C: O(1)
    pub fn set_rcv_buf_cap(&self, bytes: u32) { self.conn.lock().set_rcv_buf_cap(bytes); }

    /// F181a: register owning InetSocket's epoll subscribers. # C: O(1)
    pub fn register_poll_subs(&self, subs: &alloc::sync::Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(alloc::sync::Arc::downgrade(subs));
    }

    /// Register the owning open file description (Linux `sk->sk_socket->file`),
    /// so urgent arrival on the receive path can signal its `f_owner`.
    /// # C: O(1)
    pub fn register_file(&self, file: &alloc::sync::Arc<vfs::File>) {
        self.poll_subs.set_owner_file(file);
    }

    /// The owning open file description, while a descriptor is bound. # C: O(1)
    pub fn owner_file(&self) -> Option<alloc::sync::Arc<vfs::File>> {
        self.poll_subs.owner_file()
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
