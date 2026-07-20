//! AF_VSOCK protocol-owned shutdown transition.

use super::*;

impl VsockSocket {
    fn admit_shutdown(&self) -> Result<(), crate::NetError> {
        crate::security_admission::check(
            self.net_ns(), crate::socket_args::AF_VSOCK as u16,
            security::network::Operation::Shutdown,
        )
    }

    /// Parse a raw shutdown direction after canonical security admission. # C: O(1)
    pub fn shutdown_raw(&self, raw: u32) -> Result<(), crate::NetError> {
        self.admit_shutdown()?;
        let how = crate::uapi::ShutdownHow::try_from(raw).map_err(|()| crate::NetError::Einval)?;
        self.shutdown_admitted(how)
    }

    /// Apply a typed shutdown direction after canonical security admission. # C: O(1)
    pub fn shutdown(&self, how: crate::uapi::ShutdownHow) -> Result<(), crate::NetError> {
        self.admit_shutdown()?;
        self.shutdown_admitted(how)
    }

    /// Apply Linux AF_VSOCK shutdown state and notify the transport. # C: O(1)
    fn shutdown_admitted(&self, how: crate::uapi::ShutdownHow) -> Result<(), crate::NetError> {
        use core::sync::atomic::Ordering;
        let conn = self.conn().ok_or(crate::NetError::Enotconn)?;
        let _emit = vsock::lock_emission(&conn);
        let mut flags = 0;
        let mut tx = conn.tx.lock();
        let st = conn.st.lock();
        if matches!(*st, VsockState::Connecting | VsockState::Closed) {
            return Err(crate::NetError::Enotconn);
        }
        if how.read() {
            let read_gate = conn.rx.lock();
            self.read_shut.store(true, Ordering::Release);
            drop(read_gate);
            flags |= vsock::VIRTIO_VSOCK_SHUTDOWN_RCV;
        }
        if how.write() {
            tx.local_shut = true;
            flags |= vsock::VIRTIO_VSOCK_SHUTDOWN_SEND;
        }
        let hdr = conn.make_hdr_with_credit(&tx.credit,
            vsock::VIRTIO_VSOCK_OP_SHUTDOWN, 0, flags);
        drop(st);
        drop(tx);
        let _ = vsock::tx_for(conn.owner, &hdr, &[]);
        #[cfg(target_os = "oxide-kernel")]
        conn.waiters.wake_all();
        self.poll_subs.notify_mask(vfs::POLL_IN | vfs::POLL_OUT
            | vfs::POLL_HUP | vfs::POLL_RDHUP);
        Ok(())
    }
}
