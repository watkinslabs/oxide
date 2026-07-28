use alloc::vec::Vec;
use super::UnixPair;
use super::super::{GcRights, UnixEnd};
use vfs;

const ECONNRESET: i32 = syscall::errno::Errno::Econnreset as i32;

#[cfg(target_os = "oxide-kernel")]
pub enum ArmStreamRead {
    Retry,
    Reset,
    Eof,
    Parked,
}

#[cfg(target_os = "oxide-kernel")]
pub enum ArmStreamWrite { Retry, PeerClosed, Parked }

impl UnixPair {
    /// Atomically recheck stream send capacity and park one writer. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_stream_write(&self, end: UnixEnd, cap: usize, deadline_ns: u64) -> ArmStreamWrite {
        let outgoing = match end { UnixEnd::A => &self.a_to_b, UnixEnd::B => &self.b_to_a };
        let g = outgoing.lock();
        if self.peer_gone(end) || g.closed_writer || g.reader_shutdown {
            return ArmStreamWrite::PeerClosed;
        }
        if g.buf.len() < cap { return ArmStreamWrite::Retry; }
        // SAFETY: writer registration occurs under the outgoing-ring lock also
        // held by receive-side capacity publication before waking writers.
        unsafe { self.writer_waiters(end).park_interruptible_with_deadline(deadline_ns); }
        drop(g);
        ArmStreamWrite::Parked
    }
    /// Atomically recheck a boundary-aware stream read and park its caller.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_stream_read(&self, end: UnixEnd, deadline_ns: u64) -> ArmStreamRead {
        self.arm_stream_read_after(end, 0, deadline_ns)
    }

    /// Atomically park until bytes exist beyond a non-consuming peek offset. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_stream_read_after(&self, end: UnixEnd, offset: usize, deadline_ns: u64) -> ArmStreamRead {
        let read_ring = match end {
            UnixEnd::A => &self.b_to_a,
            UnixEnd::B => &self.a_to_b,
        };
        let g = read_ring.lock();
        let logical = g.consumed.saturating_add(offset as u64);
        let ancillary_ready = if offset == 0 {
            g.ancillary.front().map(|(off, _, _)| *off <= g.consumed).unwrap_or(false)
        } else {
            g.ancillary.iter().any(|(off, _, _)| *off <= logical && *off > g.consumed)
        };
        if g.buf.len() > offset || ancillary_ready { return ArmStreamRead::Retry; }
        if self.reset_pending(end) { return ArmStreamRead::Reset; }
        if g.closed_writer || g.reader_shutdown { return ArmStreamRead::Eof; }
        // SAFETY: caller is a running syscall task; registration occurs under
        // the read-ring lock also taken by writers before their wake operation.
        unsafe { self.reader_waiters(end).park_interruptible_with_deadline(deadline_ns); }
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

    /// Consume the endpoint's reset marker and canonical connection error.
    /// # C: O(1)
    pub fn take_reset(&self, end: UnixEnd) -> bool {
        use core::sync::atomic::Ordering::AcqRel;
        let marked = match end {
            UnixEnd::A => self.reset_pending_a.swap(false, AcqRel),
            UnixEnd::B => self.reset_pending_b.swap(false, AcqRel),
        };
        marked && self.end_error(end).take() == ECONNRESET
    }

    /// Whether this endpoint still has a connection-reset error to consume.
    /// # C: O(1)
    pub fn reset_pending(&self, end: UnixEnd) -> bool {
        use core::sync::atomic::Ordering::Acquire;
        let marked = match end {
            UnixEnd::A => self.reset_pending_a.load(Acquire),
            UnixEnd::B => self.reset_pending_b.load(Acquire),
        };
        marked && self.end_error(end).has()
    }

    /// Shut down `end`'s receive half while preserving bytes already queued.
    /// # C: O(1)
    pub fn shutdown_reader(&self, end: UnixEnd) {
        let incoming = match end { UnixEnd::A => &self.b_to_a, UnixEnd::B => &self.a_to_b };
        incoming.lock().reader_shutdown = true;
        #[cfg(target_os = "oxide-kernel")]
        {
            self.reader_waiters(end).wake_all();
            self.writer_waiters(end.other()).wake_all();
            super::super::wake_peer_subs(self, end.other(), vfs::POLL_IN | vfs::POLL_RDHUP);
            super::super::wake_peer_subs(self, end, vfs::POLL_OUT);
        }
    }

    /// Shut down `end`'s send half and publish EOF after queued bytes drain.
    /// # C: O(1)
    pub fn close_writer(&self, end: UnixEnd) {
        let outgoing = match end { UnixEnd::A => &self.a_to_b, UnixEnd::B => &self.b_to_a };
        outgoing.lock().closed_writer = true;
        #[cfg(target_os = "oxide-kernel")]
        {
            self.reader_waiters(end.other()).wake_all();
            self.writer_waiters(end).wake_all();
            super::super::wake_peer_subs(self, end, vfs::POLL_IN | vfs::POLL_RDHUP);
        }
    }

    /// Destroy one endpoint at final file release.
    /// # C: O(unread bytes + descriptors + SCM collection)
    pub fn release_end(&self, end: UnixEnd) {
        use core::sync::atomic::Ordering::{AcqRel, Release};
        let released = match end { UnixEnd::A => &self.released_a, UnixEnd::B => &self.released_b };
        if released.swap(true, AcqRel) { return; }
        let incoming = match end { UnixEnd::A => &self.b_to_a, UnixEnd::B => &self.a_to_b };
        let (unread, fds): (bool, Vec<(u64, GcRights, (u32, u32, u32))>) = {
            let mut g = incoming.lock();
            let unread = !g.buf.is_empty() || !g.ancillary.is_empty();
            g.buf.clear();
            g.consumed = g.produced;
            g.reader_shutdown = true;
            (unread, g.ancillary.drain(..).collect())
        };
        let (peer_gone, reset) = match end {
            UnixEnd::A => (&self.peer_gone_b, &self.reset_pending_b),
            UnixEnd::B => (&self.peer_gone_a, &self.reset_pending_a),
        };
        peer_gone.store(true, Release);
        if unread {
            self.end_error(end.other()).set(ECONNRESET);
            reset.store(true, Release);
        }
        let outgoing = match end { UnixEnd::A => &self.a_to_b, UnixEnd::B => &self.b_to_a };
        outgoing.lock().closed_writer = true;
        drop(fds);
        super::super::collect_scm_rights();
        #[cfg(target_os = "oxide-kernel")]
        {
            self.reader_waiters(end).wake_all();
            self.reader_waiters(end.other()).wake_all();
            self.writer_waiters(end).wake_all();
            self.writer_waiters(end.other()).wake_all();
            let mut mask = vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP;
            if unread { mask |= vfs::POLL_ERR; }
            super::super::wake_peer_subs(self, end, mask);
        }
    }

    /// True when reads from `end` have drained all data before EOF.
    /// # C: O(1)
    pub fn is_eof(&self, end: UnixEnd) -> bool {
        let g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
        (g.closed_writer || g.reader_shutdown) && g.buf.is_empty() && !self.reset_pending(end)
    }

    /// Linux `unix_poll` (`net/unix/af_unix.c:3353-3396`) for a stream end:
    /// readability from both directional halves, writability from
    /// `unix_writable(sk, state)` alone — the local send queue against
    /// `sndbuf_cap`, never the peer's state. An unconditional `POLL_OUT` here
    /// told a non-blocking writer "writable" while `send_unix_once` was
    /// returning `EAGAIN` at the same cap, which is a 100 %-CPU spin rather
    /// than a sleep.
    /// # C: O(1)
    pub fn poll_mask(&self, end: UnixEnd, sndbuf_cap: usize) -> u32 {
        let (has_data, peer_send_shut, local_recv_shut) = {
            let g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
            (!g.buf.is_empty(), g.closed_writer, g.reader_shutdown)
        };
        let (local_send_shut, peer_recv_shut, queued) = {
            let g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
            (g.closed_writer, g.reader_shutdown, g.buf.len())
        };
        let gone = self.peer_gone(end);
        let reset = self.reset_pending(end);
        let mut mask = 0u32;
        // "we set writable also when the other side has shut down the
        // connection. This prevents stuck sockets." — `unix_poll`'s comment;
        // the shutdown arms below never clear POLL_OUT, matching that.
        if super::super::unix_writable(queued, sndbuf_cap) { mask |= vfs::POLL_OUT | vfs::POLL_WRNORM; }
        if has_data || peer_send_shut || local_recv_shut || gone || reset {
            mask |= vfs::POLL_IN;
        }
        if peer_send_shut || local_recv_shut || gone { mask |= vfs::POLL_RDHUP; }
        if (local_recv_shut && local_send_shut) || (peer_send_shut && peer_recv_shut) || gone {
            mask |= vfs::POLL_HUP;
        }
        if reset { mask |= vfs::POLL_ERR; }
        mask
    }

    /// Abort a connection that was queued but never accepted by its listener.
    /// # C: O(buffered bytes + descriptors + SCM collection)
    pub fn abort_unaccepted(&self) {
        use core::sync::atomic::Ordering::{AcqRel, Release};
        if self.peer_gone_b.swap(true, AcqRel) { return; }
        {
            let mut incoming = self.a_to_b.lock();
            self.end_error(UnixEnd::B).set(ECONNRESET);
            self.reset_pending_b.store(true, Release);
            incoming.closed_writer = true;
        }
        let fds = {
            let mut outgoing = self.b_to_a.lock();
            outgoing.buf.clear();
            core::mem::take(&mut outgoing.ancillary)
        };
        drop(fds);
        super::super::collect_scm_rights();
        #[cfg(target_os = "oxide-kernel")]
        {
            self.a_to_b_waiters.wake_all();
            super::super::wake_peer_subs(self, UnixEnd::A,
                vfs::POLL_IN | vfs::POLL_ERR | vfs::POLL_HUP | vfs::POLL_RDHUP);
        }
    }
}
