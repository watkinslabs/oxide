use super::*;

/// `SO_ZEROCOPY` state. Completions and their identifiers live on the socket's
/// one extended-error queue, not beside it.
pub(super) struct State {
    enabled: bool,
}

impl State {
    pub(super) const fn new() -> Self { Self { enabled: false } }
}

impl VsockSocket {
    /// Apply connectible-VSOCK's boolean `SO_ZEROCOPY` policy. # C: O(1)
    pub fn set_zerocopy(&self, value: i32) -> Result<(), crate::NetError> {
        if self.is_datagram() { return Err(crate::NetError::Enoprotoopt); }
        if !(0..=1).contains(&value) { return Err(crate::NetError::Einval); }
        self.zerocopy.lock().enabled = value != 0;
        Ok(())
    }

    /// Read connectible-VSOCK's `SO_ZEROCOPY` flag. # C: O(1)
    pub fn zerocopy_enabled(&self) -> bool { self.zerocopy.lock().enabled }

    pub(super) fn inherit_zerocopy(&self, parent: &Self) {
        self.zerocopy.lock().enabled = parent.zerocopy_enabled();
    }

    /// Publish one completed `MSG_ZEROCOPY` send. Oxide's VSOCK importer has
    /// already copied the payload, so every completion carries Linux's
    /// `SO_EE_CODE_ZEROCOPY_COPIED` fallback bit. # C: O(1) amortized
    pub fn complete_zerocopy_send(&self, requested: bool, bytes: usize) {
        let enabled = self.zerocopy_enabled();
        if !crate::socket_error::complete_zerocopy_send(&self.error, enabled, requested, bytes,
            false)
        { return; }
        self.poll_subs.notify_mask(vfs::POLL_ERR);
    }

    /// Consume the oldest completion range. # C: O(1)
    pub fn take_zerocopy_completion(&self) -> Option<(u32, u32, bool)> {
        let entry = self.error.take_extended()?;
        Some((entry.info, entry.data,
            entry.code & crate::socket_error::SO_EE_CODE_ZEROCOPY_COPIED != 0))
    }

    /// Observe whether `MSG_ERRQUEUE` can consume a completion. # C: O(1)
    pub fn has_zerocopy_completion(&self) -> bool { self.error.has_extended() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(raw: u32) -> vsock::VsockOwner {
        vsock::VsockOwner::from_raw(raw).expect("nonzero transport owner")
    }

    fn tx_ok(_: vsock::VsockOwner, _: &[u8]) -> bool { true }
    fn rx_noop(_: vsock::VsockOwner) -> usize { 0 }

    #[test]
    fn option_is_boolean_connectible_and_inherited_without_inheriting_completions() {
        let listener = VsockSocket::new();
        assert_eq!(listener.get_socket_option(crate::uapi::SOL_SOCKET, crate::uapi::SO_ZEROCOPY),
            Ok(0));
        assert_eq!(listener.set_zerocopy(-1), Err(crate::NetError::Einval));
        assert_eq!(listener.set_zerocopy(2), Err(crate::NetError::Einval));
        assert_eq!(listener.set_zerocopy(1), Ok(()));
        assert_eq!(listener.get_socket_option(crate::uapi::SOL_SOCKET, crate::uapi::SO_ZEROCOPY),
            Ok(1));
        listener.complete_zerocopy_send(true, 1);
        let child = VsockSocket::new_accepted(&listener);
        assert!(child.zerocopy_enabled());
        assert_eq!(child.take_zerocopy_completion(), None);
        assert_eq!(VsockSocket::new_type(crate::socket_args::SOCK_DGRAM).set_zerocopy(1),
            Err(crate::NetError::Enoprotoopt));
    }

    #[test]
    fn successful_copy_fallback_sends_publish_linux_completion_ranges() {
        let _guard = vsock::tests::test_domain();
        let transport = owner(0x0e00_0001);
        let _ = vsock::driver_uninstall(transport);
        assert!(vsock::driver_install(transport, 3, tx_ok, rx_noop));
        let conn = Arc::new(vsock::VsockConn::new(transport, 3, 64_001, 2, 1024,
            vsock::VsockState::Connected));
        conn.tx.lock().credit.peer_buf_alloc = 8192;
        let socket = VsockSocket::new();
        *socket.kind.lock() = VsockKind::Conn(conn);

        assert_eq!(socket.send_message_flags(b"off", false, true, crate::uapi::MSG_ZEROCOPY),
            Ok(3));
        assert_eq!(socket.take_zerocopy_completion(), None,
            "MSG_ZEROCOPY is ignored until SO_ZEROCOPY is enabled");
        socket.set_zerocopy(1).unwrap();
        assert_eq!(socket.send_message_flags(b"a", false, true, crate::uapi::MSG_ZEROCOPY), Ok(1));
        assert_eq!(socket.send_message_flags(b"b", false, true, crate::uapi::MSG_ZEROCOPY), Ok(1));
        assert_eq!(socket.take_pending_recv_error(), 0,
            "zero-errno completions do not become SO_ERROR");
        assert_ne!(socket.poll() & vfs::POLL_ERR, 0);
        assert_eq!(socket.take_zerocopy_completion(), Some((0, 1, true)));
        assert_eq!(socket.poll() & vfs::POLL_ERR, 0);
        assert!(vsock::driver_uninstall(transport));
    }
}
