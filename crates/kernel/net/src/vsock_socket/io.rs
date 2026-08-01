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
                        unsafe { c.waiters.park(); }
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
}
