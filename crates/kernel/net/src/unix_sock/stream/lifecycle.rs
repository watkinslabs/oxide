use super::{UnixEnd, UnixPair};

impl UnixPair {
    /// Whether the opposite endpoint was destroyed rather than half-closed.
    /// # C: O(1)
    pub fn peer_gone(&self, end: UnixEnd) -> bool {
        use core::sync::atomic::Ordering::Acquire;
        match end {
            UnixEnd::A => self.peer_gone_a.load(Acquire),
            UnixEnd::B => self.peer_gone_b.load(Acquire),
        }
    }

    /// Consume the endpoint's one-shot connection-reset error.
    /// # C: O(1)
    pub fn take_reset(&self, end: UnixEnd) -> bool {
        use core::sync::atomic::Ordering::AcqRel;
        match end {
            UnixEnd::A => self.reset_pending_a.swap(false, AcqRel),
            UnixEnd::B => self.reset_pending_b.swap(false, AcqRel),
        }
    }

    /// Abort a connection that was queued but never accepted by its listener.
    /// # C: O(buffered bytes + descriptors)
    pub fn abort_unaccepted(&self) {
        use core::sync::atomic::Ordering::{AcqRel, Release};
        if self.peer_gone_b.swap(true, AcqRel) { return; }
        {
            let mut incoming = self.a_to_b.lock();
            self.reset_pending_b.store(true, Release);
            incoming.closed_writer = true;
        }
        let fds = {
            let mut outgoing = self.b_to_a.lock();
            outgoing.buf.clear();
            core::mem::take(&mut outgoing.fds)
        };
        drop(fds);
        #[cfg(target_os = "oxide-kernel")]
        {
            self.a_to_b_waiters.wake_all();
            super::wake_peer_subs(self, UnixEnd::A,
                vfs::POLL_IN | vfs::POLL_ERR | vfs::POLL_HUP | vfs::POLL_RDHUP);
        }
    }
}
