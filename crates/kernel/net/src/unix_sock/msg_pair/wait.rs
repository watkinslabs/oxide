use super::{message_charge, UnixEnd, UnixMsgKind, UnixMsgPair};

#[cfg(target_os = "oxide-kernel")]
pub enum ArmMsgRead { Retry, Reset, Eof, Parked { reader_shutdown: bool } }

#[cfg(target_os = "oxide-kernel")]
pub enum ArmMsgReadAfter { Retry, Reset, Eof, DatagramShutdown, Parked }

#[cfg(target_os = "oxide-kernel")]
pub enum ArmMsgWrite { Retry, PeerClosed, MessageTooLarge, Parked }

impl UnixMsgPair {
    /// Linux `unix_dgram_poll` (`net/unix/af_unix.c:3398-3456`) — the `->poll`
    /// of BOTH `unix_seqpacket_ops` and `unix_dgram_ops`. Writability is
    /// `unix_writable(sk, state)` on the local send queue; the connected-peer
    /// backlog arm is skipped here because a socketpair is symmetrically
    /// connected (`unix_peer(other) == sk`), which is exactly the case Linux
    /// excludes from `unix_recvq_full_lockless`.
    /// # C: O(1)
    pub fn poll_mask(&self, end: UnixEnd, sndbuf_cap: usize) -> u32 {
        let (has_msg, peer_send_shut, local_recv_shut) = {
            let g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
            (!g.msgs.is_empty(), g.closed_writer, g.reader_shutdown)
        };
        let (local_send_shut, peer_recv_shut, queued) = {
            let g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
            (g.closed_writer, g.reader_shutdown, g.bytes)
        };
        let gone = self.peer_gone(end);
        let reset = self.reset_pending(end);
        let mut mask = 0u32;
        if super::super::unix_writable(queued, sndbuf_cap) { mask |= vfs::POLL_OUT | vfs::POLL_WRNORM; }
        if has_msg || local_recv_shut || (self.kind == UnixMsgKind::SeqPacket && (peer_send_shut || gone || reset)) { mask |= vfs::POLL_IN; }
        if local_recv_shut || (self.kind == UnixMsgKind::SeqPacket && (peer_send_shut || gone)) { mask |= vfs::POLL_RDHUP; }
        if (local_recv_shut && local_send_shut)
            || (self.kind == UnixMsgKind::SeqPacket && ((peer_send_shut && peer_recv_shut) || gone))
        { mask |= vfs::POLL_HUP; }
        if self.kind == UnixMsgKind::SeqPacket && reset { mask |= vfs::POLL_ERR; }
        mask
    }

    /// Atomically recheck a message receive and park the caller. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_read_after_generation(&self, end: UnixEnd, shutdown_generation: u64,
        deadline_ns: u64) -> ArmMsgReadAfter {
        let g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
        if !g.msgs.is_empty() { return ArmMsgReadAfter::Retry; }
        if self.reset_pending(end) { return ArmMsgReadAfter::Reset; }
        if self.kind == UnixMsgKind::SeqPacket && (g.reader_shutdown || g.closed_writer) {
            return ArmMsgReadAfter::Eof;
        }
        if self.kind == UnixMsgKind::Datagram && g.shutdown_generation != shutdown_generation {
            return ArmMsgReadAfter::DatagramShutdown;
        }
        // SAFETY: registration occurs under the queue lock also acquired by
        // send, shutdown, and release before their wake publication.
        unsafe { self.reader_waiters(end).park_interruptible_with_deadline(deadline_ns); }
        drop(g);
        ArmMsgReadAfter::Parked
    }

    /// Arm a receive without a pre-attempt shutdown snapshot. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_read(&self, end: UnixEnd, deadline_ns: u64) -> ArmMsgRead {
        let g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
        if !g.msgs.is_empty() { return ArmMsgRead::Retry; }
        if self.reset_pending(end) { return ArmMsgRead::Reset; }
        if self.kind == UnixMsgKind::SeqPacket && (g.reader_shutdown || g.closed_writer) {
            return ArmMsgRead::Eof;
        }
        let reader_shutdown = g.reader_shutdown;
        // SAFETY: registration occurs under the queue lock also acquired by
        // send, shutdown, and release before their wake publication.
        unsafe { self.reader_waiters(end).park_interruptible_with_deadline(deadline_ns); }
        drop(g);
        ArmMsgRead::Parked { reader_shutdown }
    }

    /// Atomically recheck atomic-record capacity and park one writer. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_write(&self, end: UnixEnd, len: usize, cap: usize, deadline_ns: u64) -> ArmMsgWrite {
        let g = match end { UnixEnd::A => self.a_to_b.lock(), UnixEnd::B => self.b_to_a.lock() };
        if self.peer_gone(end) || g.closed_writer || g.reader_shutdown {
            return ArmMsgWrite::PeerClosed;
        }
        let charge = message_charge(len);
        if charge > cap { return ArmMsgWrite::MessageTooLarge; }
        if g.bytes.saturating_add(charge) <= cap { return ArmMsgWrite::Retry; }
        // SAFETY: registration occurs under the queue lock also acquired by
        // receive, shutdown, and release before writer wake publication.
        unsafe { self.writer_waiters(end).park_interruptible_with_deadline(deadline_ns); }
        drop(g);
        ArmMsgWrite::Parked
    }

    /// WaitList for writers on `end`. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn writer_waiters(&self, end: UnixEnd) -> &sched::live::WaitList {
        match end { UnixEnd::A => &self.a_to_b_writers, UnixEnd::B => &self.b_to_a_writers }
    }

    /// Publish newly available capacity to the matching writer and pollers. # C: O(N waiters)
    #[cfg(target_os = "oxide-kernel")]
    pub(super) fn wake_writer(&self, end: UnixEnd) {
        self.writer_waiters(end).wake_all();
        super::wake_msgpair_peer_subs(self, end.other(), vfs::POLL_OUT);
    }
}
