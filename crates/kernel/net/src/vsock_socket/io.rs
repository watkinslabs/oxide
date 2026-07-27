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
            if nonblock { return Err(vfs::VfsError::Eagain); }
            #[cfg(target_os = "oxide-kernel")]
            {
                // Linux `vsock_connectible_recvmsg` (`af_vsock.c:2384`):
                // `sock_intr_errno(timeout)`; untimed here (no SO_RCVTIMEO on
                // AF_VSOCK in this tree), so ERESTARTSYS.
                if sched::live::deliverable_signals_self() != 0 {
                    // UNTIMED-FAMILY DEPENDENCY: correct only while this family plumbs no
                    // SO_{RCV,SND}TIMEO. If you add those options, switch to the real deadline —
                    // see `net::sock_intr::sock_intr_untimed_family_vfs`.
                    return Err(crate::sock_intr::sock_intr_untimed_family_vfs());
                }
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
                    if c.tx.lock().shut() { return Err(vfs::VfsError::Epipe); }
                    if nonblock { return Err(vfs::VfsError::Eagain); }
                    #[cfg(target_os = "oxide-kernel")]
                    {
                        // Linux `vsock_connectible_sendmsg` (`af_vsock.c:2267`):
                        // `sock_intr_errno(timeout)`; untimed here (no
                        // SO_SNDTIMEO on AF_VSOCK in this tree).
                        if sched::live::deliverable_signals_self() != 0 {
                            // UNTIMED-FAMILY DEPENDENCY: correct only while this family plumbs no
                            // SO_{RCV,SND}TIMEO. If you add those options, switch to the real deadline —
                            // see `net::sock_intr::sock_intr_untimed_family_vfs`.
                            return Err(crate::sock_intr::sock_intr_untimed_family_vfs());
                        }
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
                    #[cfg(not(target_os = "oxide-kernel"))]
                    return Err(vfs::VfsError::Eagain);
                }
                Err(crate::NetError::Enotconn) => return Err(vfs::VfsError::Epipe),
                Err(crate::NetError::Epipe) => return Err(vfs::VfsError::Epipe),
                Err(crate::NetError::Emsgsize) => return Err(vfs::VfsError::Emsgsize),
                Err(_) => return Err(vfs::VfsError::Eio),
            }
            if sent == buf.len() { return Ok(sent); }
        }
        Ok(sent)
    }
}
