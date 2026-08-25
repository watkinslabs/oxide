use super::*;

impl UnixMsgPair {
    /// Dequeue one message from the ring `end` reads from. Returns
    /// `Some(bytes)` truncated to `max`; `None` if empty.
    /// # C: O(min(max, payload.len()))
    pub fn recv(&self, end: UnixEnd, max: usize) -> Option<Vec<u8>> {
        self.recv_msg(end, max).map(|msg| {
            let UnixMsg { payload, fds, .. } = msg;
            drop(fds);
            crate::unix_sock::collect_scm_rights();
            payload
        })
    }

    /// Inspect one record under its queue lock. Non-peek callbacks consume the
    /// record on success or failure; peek callbacks never consume it. # C: O(max + rights)
    pub fn recv_msg_with<R, E>(&self, end: UnixEnd, max: usize, peek: bool,
        copy: impl FnOnce(&[u8], usize, (u32, u32, u32), usize) -> Result<R, E>)
        -> Result<Option<(R, UnixMsg, usize)>, E>
    {
        let mut g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
        let Some(front) = g.msgs.front() else {
            if self.kind == UnixMsgKind::SeqPacket && self.reset_pending(end) { return Ok(None); }
            if self.kind == UnixMsgKind::SeqPacket && (g.closed_writer || g.reader_shutdown) {
                let copied = copy(&[], 0, (0, 0, 0), 0)?;
                return Ok(Some((copied, UnixMsg::empty(), 0)));
            }
            return Ok(None);
        };
        let full_len = front.payload.len();
        let payload = front.payload[..core::cmp::min(max, full_len)].to_vec();
        let rights_len = front.rights.as_ref().map(GcRights::len).unwrap_or(front.fds.len());
        let creds = front.creds.clone();
        // Rendered for the RECEIVER's pid namespace at this instant.
        let copied = match copy(&payload, rights_len, creds.ids_for_reader(), full_len) {
            Ok(copied) => copied,
            Err(err) => {
                let dropped = if peek { None } else { g.msgs.pop_front() };
                if let Some(msg) = dropped.as_ref() { g.bytes = g.bytes.saturating_sub(message_charge(msg.payload.len())); }
                drop(g);
                #[cfg(target_os = "oxide-kernel")]
                if dropped.is_some() { self.wake_writer(end.other()); }
                drop(dropped);
                if !peek { crate::unix_sock::collect_scm_rights(); }
                return Err(err);
            }
        };
        let mut msg = if peek {
            let fds = front.rights.as_ref().map(GcRights::clone_files).unwrap_or_else(|| front.fds.clone());
            UnixMsg { payload, fds, rights: None, creds }
        } else {
            let msg = g.msgs.pop_front().unwrap();
            g.bytes = g.bytes.saturating_sub(message_charge(msg.payload.len()));
            msg
        };
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        if !peek { self.wake_writer(end.other()); }
        if let Some(rights) = msg.rights.take() { msg.fds = rights.take_files(); }
        if msg.payload.len() > max { msg.payload.truncate(max); }
        Ok(Some((copied, msg, full_len)))
    }

    /// Dequeue or peek one message payload from the ring `end` reads
    /// from. Returns copied/truncated bytes plus the full message length.
    /// # C: O(min(max, payload.len()))
    pub fn recv_payload(&self, end: UnixEnd, max: usize, peek: bool) -> Option<(Vec<u8>, usize)> {
        let out = self.recv_msg_with(end, max, peek, |payload, _, _, full| Ok::<_, core::convert::Infallible>((payload.to_vec(), full)))
            .unwrap_or_else(|never| match never {}).map(|(out, _, _)| out);
        if !peek { crate::unix_sock::collect_scm_rights(); }
        out
    }

    /// Dequeue one message plus any SCM_RIGHTS files from ring `end` reads.
    /// # C: O(min(max, payload.len()))
    pub fn recv_msg(&self, end: UnixEnd, max: usize) -> Option<UnixMsg> {
        self.recv_msg_with(end, max, false, |_, _, _, _| Ok::<(), core::convert::Infallible>(()))
            .unwrap_or_else(|never| match never {}).map(|(_, msg, _)| msg)
    }

    /// Mark this end's writer side closed.
    /// # C: O(1)
    pub fn close_writer(&self, end: UnixEnd) {
        let mut g = match end {
            UnixEnd::A => self.a_to_b.lock(),
            UnixEnd::B => self.b_to_a.lock(),
        };
        g.closed_writer = true;
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        {
            self.writer_waiters(end).wake_all();
            if self.kind == UnixMsgKind::SeqPacket {
                let waiters = match end {
                    UnixEnd::A => &self.a_to_b_waiters,
                    UnixEnd::B => &self.b_to_a_waiters,
                };
                waiters.wake_all();
                wake_msgpair_peer_subs(self, end, vfs::POLL_IN | vfs::POLL_RDHUP);
            }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        if self.kind == UnixMsgKind::SeqPacket {
            match end {
                UnixEnd::A => self.a_to_b_waiters.wake_all(),
                UnixEnd::B => self.b_to_a_waiters.wake_all(),
            }
        }
    }

    /// Shut down `end`'s receive half while preserving queued records.
    /// # C: O(1)
    pub fn shutdown_reader(&self, end: UnixEnd) {
        let g = match end { UnixEnd::A => &self.b_to_a, UnixEnd::B => &self.a_to_b };
        let mut state = g.lock();
        if !state.reader_shutdown {
            state.reader_shutdown = true;
            state.shutdown_generation = state.shutdown_generation.wrapping_add(1);
        }
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        {
            self.reader_waiters(end).wake_all();
            self.writer_waiters(end.other()).wake_all();
            wake_msgpair_peer_subs(self, end.other(), vfs::POLL_IN | vfs::POLL_RDHUP);
            wake_msgpair_peer_subs(self, end, vfs::POLL_OUT);
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        self.reader_waiters(end).wake_all();
    }

    /// Destroy one endpoint and discard records it will never receive.
    /// # C: O(unread records + descriptors + SCM collection)
    pub fn release_end(&self, end: UnixEnd) {
        use core::sync::atomic::Ordering::{AcqRel, Release};
        let released = match end { UnixEnd::A => &self.released_a, UnixEnd::B => &self.released_b };
        if released.swap(true, AcqRel) { return; }
        let incoming = match end { UnixEnd::A => &self.b_to_a, UnixEnd::B => &self.a_to_b };
        let dropped = {
            let mut g = incoming.lock();
            let unread = !g.msgs.is_empty();
            g.reader_shutdown = true;
            g.shutdown_generation = g.shutdown_generation.wrapping_add(1);
            g.bytes = 0;
            (unread, core::mem::take(&mut g.msgs))
        };
        let (gone, reset) = match end {
            UnixEnd::A => (&self.peer_gone_b, &self.reset_pending_b),
            UnixEnd::B => (&self.peer_gone_a, &self.reset_pending_a),
        };
        gone.store(true, Release);
        if self.kind == UnixMsgKind::SeqPacket && dropped.0 {
            self.end_error(end.other()).set(ECONNRESET);
            reset.store(true, Release);
        }
        if self.kind == UnixMsgKind::SeqPacket {
            let outgoing = match end { UnixEnd::A => &self.a_to_b, UnixEnd::B => &self.b_to_a };
            outgoing.lock().closed_writer = true;
        }
        drop(dropped.1);
        crate::unix_sock::collect_scm_rights();
        #[cfg(target_os = "oxide-kernel")]
        {
            self.reader_waiters(end).wake_all();
            self.reader_waiters(end.other()).wake_all();
            self.writer_waiters(end).wake_all();
            self.writer_waiters(end.other()).wake_all();
            let mut mask = vfs::POLL_OUT;
            if self.kind == UnixMsgKind::SeqPacket {
                mask |= vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP;
                if dropped.0 { mask |= vfs::POLL_ERR; }
            }
            wake_msgpair_peer_subs(self, end, mask);
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        {
            self.reader_waiters(end).wake_all();
            self.reader_waiters(end.other()).wake_all();
        }
    }

    /// Consume one close-with-unread marker and canonical reset after records drain.
    /// # C: O(1)
    pub fn take_reset(&self, end: UnixEnd) -> bool {
        use core::sync::atomic::Ordering::AcqRel;
        let marked = match end { UnixEnd::A => self.reset_pending_a.swap(false, AcqRel), UnixEnd::B => self.reset_pending_b.swap(false, AcqRel) };
        marked && self.end_error(end).take() == ECONNRESET
    }

    /// Whether a reset remains pending for `end`. # C: O(1)
    pub fn reset_pending(&self, end: UnixEnd) -> bool {
        use core::sync::atomic::Ordering::Acquire;
        let marked = match end { UnixEnd::A => self.reset_pending_a.load(Acquire), UnixEnd::B => self.reset_pending_b.load(Acquire) };
        marked && self.end_error(end).has()
    }

    /// Whether this endpoint's receive half was shut down. # C: O(1)
    pub fn reader_shutdown(&self, end: UnixEnd) -> bool {
        let g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
        g.reader_shutdown
    }

    /// Snapshot the receive-half shutdown generation for one datagram call. # C: O(1)
    pub fn shutdown_generation(&self, end: UnixEnd) -> u64 {
        let g = match end { UnixEnd::A => self.b_to_a.lock(), UnixEnd::B => self.a_to_b.lock() };
        g.shutdown_generation
    }

    /// Whether the opposite endpoint has been released. # C: O(1)
    pub fn peer_gone(&self, end: UnixEnd) -> bool {
        use core::sync::atomic::Ordering::Acquire;
        match end { UnixEnd::A => self.peer_gone_a.load(Acquire), UnixEnd::B => self.peer_gone_b.load(Acquire) }
    }

    /// True when recv from `end` would observe EOF.
    /// # C: O(1)
    pub fn is_eof(&self, end: UnixEnd) -> bool {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        self.kind == UnixMsgKind::SeqPacket
            && (g.closed_writer || g.reader_shutdown) && g.msgs.is_empty() && !self.reset_pending(end)
    }

    /// True iff there is a pending message for `end` to receive.
    /// # C: O(1)
    pub fn has_msg(&self, end: UnixEnd) -> bool {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        !g.msgs.is_empty()
    }
}
