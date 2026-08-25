//! AF_VSOCK file-write and message-send ownership.

use super::*;

impl VsockSocket {
    /// Read one complete seqpacket record into a file-I/O destination. Record
    /// truncation is implicit for `read(2)`; the canonical record owner still
    /// retires the entire record and its full credit. # C: O(record)
    pub(super) fn read_seqpacket(&self, buf: &mut [u8], nonblock: bool)
        -> vfs::KResult<usize>
    {
        self.check_receive().map_err(|_| vfs::VfsError::Eacces)?;
        if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
        let Some(conn) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        loop {
            #[cfg(target_os = "oxide-kernel")]
            let _ = vsock::poll_rx_for(conn.owner);
            match vsock::recv_seqpacket_with(&conn, buf.len(), false, |record| {
                buf[..record.len()].copy_from_slice(record);
                Ok::<usize, vfs::VfsError>(record.len())
            }) {
                Ok(vsock::SeqpacketRecvWith::Data(copied, _)) => return Ok(copied),
                Ok(vsock::SeqpacketRecvWith::Eof) => {
                    let errno = self.take_pending_recv_error();
                    return if errno == 0 { Ok(0) } else { Err(super::vsock_vfs_error(errno)) };
                }
                Ok(vsock::SeqpacketRecvWith::Retry) => {
                    let errno = self.take_pending_recv_error();
                    if errno != 0 { return Err(super::vsock_vfs_error(errno)); }
                }
                Err(error) => return Err(error),
            }
            // An interrupted record wait reports SO_RCVTIMEO's restart verdict.
            match crate::sock_intr::wait_verdict(false, nonblock,
                crate::sock_intr::signal_pending_self(), self.recv_deadline_ns())
            {
                crate::sock_intr::WaitVerdict::NoWait => return Err(vfs::VfsError::Eagain),
                crate::sock_intr::WaitVerdict::Interrupted(intr) => return Err(intr.vfs()),
                crate::sock_intr::WaitVerdict::Shutdown | crate::sock_intr::WaitVerdict::Park => {}
            }
            #[cfg(target_os = "oxide-kernel")]
            {
                if !vsock::arm_seqpacket_recv_wait(&conn, self, 0) { continue; }
                // SAFETY: current task is parked on this connection's wait list.
                unsafe { sched::live::schedule::schedule(); }
                conn.waiters.remove_current();
            }
            #[cfg(not(target_os = "oxide-kernel"))]
            {
                if !vsock::seqpacket_recv_wait_would_park(&conn, self) { continue; }
                return Err(vfs::VfsError::Eagain);
            }
        }
    }

    /// Write one VSOCK stream prefix or one complete seqpacket record.
    /// # C: O(buf len) + waits
    pub fn write(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        self.send_message(buf, false, false)
    }

    /// Write one immediately admitted VSOCK stream prefix or complete record.
    /// # C: O(buf len)
    pub fn write_nonblock(&self, _off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        self.send_message(buf, false, true)
    }

    /// Send one `sendmsg` payload and publish a zerocopy completion when the
    /// caller requested it and `SO_ZEROCOPY` is enabled. # C: O(buf len) + waits
    pub fn send_message_flags(&self, buf: &[u8], end_of_record: bool, nonblock: bool,
        flags: u64) -> vfs::KResult<usize>
    {
        let result = self.send_message(buf, end_of_record, nonblock);
        if let Ok(bytes) = result {
            self.complete_zerocopy_send(flags & crate::uapi::MSG_ZEROCOPY != 0, bytes);
        }
        result
    }

    /// Send one payload through the immutable VSOCK protocol personality.
    /// `end_of_record` is meaningful only for `SOCK_SEQPACKET` and originates
    /// from `sendmsg(MSG_EOR)`. # C: O(buf len) + waits
    pub fn send_message(&self, buf: &[u8], end_of_record: bool, nonblock: bool)
        -> vfs::KResult<usize>
    {
        self.check_send().map_err(|_| vfs::VfsError::Eacces)?;
        if self.is_datagram() {
            if self.dgram_write_shut.load(core::sync::atomic::Ordering::Acquire) {
                return Err(vfs::VfsError::Epipe);
            }
            return Err(vfs::VfsError::Eopnotsupp);
        }
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        let seqpacket = self.socket_type() == VsockSocketType::Seqpacket;
        let mut sent = 0usize;
        loop {
            #[cfg(target_os = "oxide-kernel")]
            let _ = vsock::poll_rx_for(c.owner);
            let result = if seqpacket {
                vsock::send_seqpacket(&c, buf, end_of_record)
            } else { vsock::send(&c, &buf[sent..]) };
            match result {
                Ok(n) if seqpacket => return Ok(n),
                Ok(0) => return Ok(sent),
                Ok(n) => sent += n,
                Err(crate::NetError::Eagain) => {
                    if sent > 0 { break; }
                    #[cfg(test)]
                    if let Some(hook) = self.write_retry_hook.lock().take() { hook(self); }
                    // Send-side shutdown outranks the wait; an interrupted wait
                    // reports SO_SNDTIMEO's restart verdict.
                    match crate::sock_intr::wait_verdict(c.tx.lock().shut(), nonblock,
                        crate::sock_intr::signal_pending_self(), self.send_deadline_ns())
                    {
                        crate::sock_intr::WaitVerdict::Shutdown => return Err(vfs::VfsError::Epipe),
                        crate::sock_intr::WaitVerdict::NoWait => return Err(vfs::VfsError::Eagain),
                        crate::sock_intr::WaitVerdict::Interrupted(intr) => return Err(intr.vfs()),
                        crate::sock_intr::WaitVerdict::Park => {}
                    }
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        let tx = c.tx.lock();
                        if tx.shut() { return Err(vfs::VfsError::Epipe); }
                        let ready = if seqpacket {
                            tx.credit.peer_credit() as usize >= buf.len()
                        } else { tx.credit.peer_credit() > 0 };
                        if ready { continue; }
                        // SAFETY: process context owns this connection's wait registration.
                        unsafe { c.waiters.prepare_to_wait(); }
                        drop(tx);
                        // SAFETY: current task was parked on this connection's wait list.
                        unsafe { sched::live::schedule::schedule(); }
                    }
                    // Hosted builds have no scheduler to park on, so a verdict
                    // of Park can only be reported as "no progress yet". Every
                    // errno-bearing verdict above is shared with the kernel
                    // build; only the sleep itself is unavailable here.
                    #[cfg(not(target_os = "oxide-kernel"))]
                    return Err(vfs::VfsError::Eagain);
                }
                // No transport, or a connection that never reached (or has left)
                // the established state: ENOTCONN. EPIPE is reserved for a shut
                // direction, which the admission check above already reported.
                Err(crate::NetError::Enotconn) => return Err(vfs::VfsError::Enotconn),
                Err(crate::NetError::Epipe) => return Err(vfs::VfsError::Epipe),
                Err(crate::NetError::Emsgsize) => return Err(vfs::VfsError::Emsgsize),
                Err(_) => return Err(vfs::VfsError::Eio),
            }
            if sent == buf.len() { return Ok(sent); }
        }
        Ok(sent)
    }
    /// Blocking stream read: drain buffered RX, park on the conn's
    /// waiters when empty + still live. EOF (Ok(0)) on peer shutdown.
    /// # C: backend-dependent
    pub fn read(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        if self.socket_type() == VsockSocketType::Seqpacket {
            return self.read_seqpacket(buf, false);
        }
        self.check_receive().map_err(|_| vfs::VfsError::Eacces)?;
        if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
        if self.is_datagram() { return Err(vfs::VfsError::Eopnotsupp); }
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        loop {
            if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
            #[cfg(target_os = "oxide-kernel")]
            let _ = vsock::poll_rx_for(c.owner);
            match vsock::recv(&c, buf) {
                Ok(n)  => return Ok(n),
                Err(crate::NetError::Eagain) => {
                    let eno = self.take_pending_recv_error();
                    if eno != 0 { return Err(vsock_vfs_error(eno)); }
                    #[cfg(test)]
                    if let Some(hook) = self.read_retry_hook.lock().take() { hook(self); }
                    if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
                    {
                        let st = c.st.lock();
                        let rx = c.rx.lock();
                        if rx.is_empty()
                            && matches!(*st, VsockState::RcvShutdown | VsockState::Closed)
                        { return Ok(0); }
                    }
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        // A signal uses `sock_intr_errno(timeout)`.
                        // NOTE: AF_VSOCK carries no SO_RCVTIMEO/SO_SNDTIMEO here (`VsockSocket` has
                        // no timeo fields), so the wait is always untimed and `sock_intr_errno`
                        // necessarily yields ERESTARTSYS. Timed waits use their socket timeouts;
                        // wiring those options is a separate gap, tracked in the plan.
                        if sched::live::interruptible_work_pending_self() {
                            // A signal uses the receive timeout's shared rule.
                            return Err(crate::sock_intr::sock_intr_vfs(
                                self.recv_deadline_ns()));
                        }
                        let st = c.st.lock();
                        let rx = c.rx.lock();
                        if !rx.is_empty() || matches!(*st,
                            VsockState::RcvShutdown | VsockState::Closed)
                            || self.has_pending_recv_error()
                            || self.read_shut.load(core::sync::atomic::Ordering::Acquire)
                        { continue; }
                        // SAFETY: process ctx (VsockSocket::read); runqueue
                        // installed; preempt-off owned by the read syscall stub;
                        // RX lock closes data/error publication before park.
                        unsafe { c.waiters.prepare_to_wait(); }
                        drop(rx);
                        drop(st);
                        // SAFETY: current is parked on this connection's wait list.
                        unsafe { sched::live::schedule::schedule(); }
                    }
                    #[cfg(not(target_os = "oxide-kernel"))]
                    return Err(vfs::VfsError::Eagain);
                }
                Err(_) => return Err(vfs::VfsError::Eio),
            }
        }
    }

    /// Read one immediately available VSOCK stream prefix. # C: O(buf len)
    pub fn read_nonblock(&self, _off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        if self.socket_type() == VsockSocketType::Seqpacket {
            return self.read_seqpacket(buf, true);
        }
        self.check_receive().map_err(|_| vfs::VfsError::Eacces)?;
        if self.read_shut.load(core::sync::atomic::Ordering::Acquire) { return Ok(0); }
        if self.is_datagram() { return Err(vfs::VfsError::Eopnotsupp); }
        let Some(c) = self.conn() else { return Err(vfs::VfsError::Enotconn) };
        match vsock::recv(&c, buf) {
            Ok(n)  => Ok(n),
            Err(crate::NetError::Eagain) => {
                let eno = self.take_pending_recv_error();
                if eno != 0 { Err(vsock_vfs_error(eno)) } else { Err(vfs::VfsError::Eagain) }
            }
            Err(_) => Err(vfs::VfsError::Eio),
        }
    }

    /// Snapshot VSOCK readiness from canonical endpoint state. # C: O(1)
    pub fn poll(&self) -> u32 {
        use core::sync::atomic::Ordering::Acquire;
        use vfs::{POLL_ERR, POLL_IN, POLL_OUT, POLL_HUP, POLL_RDHUP};
        let read_shut = self.read_shut.load(Acquire);
        self.attach_poll_source();
        if self.is_datagram() {
            let write_shut = self.dgram_write_shut.load(Acquire);
            let mut mask = if read_shut { POLL_IN | POLL_RDHUP } else { 0 };
            if !write_shut { mask |= POLL_OUT; }
            if read_shut && write_shut { mask |= POLL_HUP; }
            return if self.has_pending_recv_error() || self.has_zerocopy_completion()
                { mask | POLL_ERR } else { mask };
        }
        let kind = self.kind.lock();
        let pending = if self.has_pending_recv_error() || self.has_zerocopy_completion()
            { POLL_ERR } else { 0 };
        match &*kind {
            VsockKind::Conn(c) => {
                let mut mask = 0;
                let tx = c.tx.lock();
                let send_shut = tx.shut();
                let local_write_shut = tx.local_shut;
                let peer_credit = tx.credit.peer_credit();
                drop(tx);
                let readable = if self.socket_type() == VsockSocketType::Seqpacket {
                    c.seq_rx.lock().ready_count() != 0
                } else { !c.rx.lock().is_empty() };
                if readable || read_shut { mask |= POLL_IN; }
                match *c.st.lock() {
                    VsockState::Connected => {
                        if !send_shut && peer_credit > 0 { mask |= POLL_OUT; }
                    }
                    VsockState::RcvShutdown => {
                        mask |= POLL_IN | POLL_RDHUP;
                        if !send_shut && peer_credit > 0 { mask |= POLL_OUT; }
                        if local_write_shut { mask |= POLL_HUP; }
                    }
                    VsockState::Closed => { mask |= POLL_HUP; }
                    VsockState::Connecting => {}
                }
                if read_shut { mask |= POLL_RDHUP; }
                if read_shut && local_write_shut { mask |= POLL_HUP; }
                mask | pending
            }
            VsockKind::Listener(listener) => {
                (if !listener.backlog.lock().is_empty() { POLL_IN } else { 0 }) | pending
            }
            VsockKind::Init | VsockKind::Bound { .. } => POLL_OUT | pending,
            VsockKind::Released => POLL_HUP | pending,
        }
    }

}
