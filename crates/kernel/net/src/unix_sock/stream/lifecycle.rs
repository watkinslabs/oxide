use super::{UnixEnd, UnixPair};

#[cfg(target_os = "oxide-kernel")]
pub enum ArmStreamRead {
    Retry,
    Reset,
    Eof,
    Parked,
}

impl UnixPair {
    /// Atomically recheck a boundary-aware stream read and park its caller.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_stream_read(&self, end: UnixEnd, deadline_ns: u64) -> ArmStreamRead {
        let read_ring = match end {
            UnixEnd::A => &self.b_to_a,
            UnixEnd::B => &self.a_to_b,
        };
        let g = read_ring.lock();
        let ancillary_ready = g.ancillary.front().map(|(off, _, _)| *off <= g.consumed).unwrap_or(false);
        if !g.buf.is_empty() || ancillary_ready { return ArmStreamRead::Retry; }
        if self.take_reset(end) { return ArmStreamRead::Reset; }
        if g.closed_writer { return ArmStreamRead::Eof; }
        // SAFETY: caller is a running syscall task; registration occurs under
        // the read-ring lock also taken by writers before their wake operation.
        unsafe { self.reader_waiters(end).park_with_deadline(deadline_ns); }
        drop(g);
        ArmStreamRead::Parked
    }

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

    /// Whether this endpoint still has a connection-reset error to consume.
    /// # C: O(1)
    pub fn reset_pending(&self, end: UnixEnd) -> bool {
        use core::sync::atomic::Ordering::Acquire;
        match end {
            UnixEnd::A => self.reset_pending_a.load(Acquire),
            UnixEnd::B => self.reset_pending_b.load(Acquire),
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
            core::mem::take(&mut outgoing.ancillary)
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
