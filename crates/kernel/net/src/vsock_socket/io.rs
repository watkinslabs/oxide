//! AF_VSOCK file-write and message-send ownership.

use super::*;

impl VsockSocket {
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
                        if sched::live::deliverable_signals_self() != 0 {
                            return Err(vfs::VfsError::Eintr);
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
