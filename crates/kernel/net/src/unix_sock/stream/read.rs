use alloc::{sync::Arc, vec::Vec};

use vfs;

use super::UnixPair;
use super::super::{GcRights, UnixEnd};

/// Outcome of [`UnixPair::read_or_park`]: data drained, peer-closed EOF, or the
/// caller was registered on the reader wait list and must now `schedule()`.
#[cfg(target_os = "oxide-kernel")]
pub enum ReadOutcome {
    Data(Vec<u8>),
    Reset,
    Eof,
    Parked,
}

impl UnixPair {
    /// Drain up to `max` bytes from the ring `end` reads from, as a
    /// plain `read(2)`/`recvfrom(2)` with no control buffer and no
    /// credential passing.
    /// # C: O(min(max, queue))
    pub fn read(&self, end: UnixEnd, max: usize) -> Vec<u8> {
        self.read_passcred(end, max, false, false)
    }

    /// `read` for a receiver whose socket may pass credentials.
    ///
    /// This path has NO ancillary buffer, so any SCM_RIGHTS descriptors
    /// riding the drained bytes are DISCARDED — the receiver is told
    /// nothing about them beyond the truncation it cannot observe here.
    /// The boundaries they create are still honoured: the receive stops
    /// after a descriptor-bearing segment, and, when `passcred`, before a
    /// segment stamped by a different writer. Discarded descriptors are
    /// released AFTER the ring lock is dropped (closing a file may take
    /// other locks — never under the ring spinlock).
    /// # C: O(min(max, queue) + segments)
    pub fn read_passcred(&self, end: UnixEnd, max: usize, passcred: bool, inline: bool) -> Vec<u8> {
        let mut rights_later: Vec<GcRights> = Vec::new();
        let out = {
            let mut g = match end {
                UnixEnd::A => self.b_to_a.lock(),
                UnixEnd::B => self.a_to_b.lock(),
            };
            // The out-of-band records in front of this read are retired first;
            // `consumed` moves with them, so every bound below comes after.
            let head = g.consumed;
            let window = g.oob_window(head, false, inline);
            let stop = super::coalesce::coalesce_stop(
                g.ancillary.iter().map(|(off, rights, cred)| super::coalesce::Segment {
                    off: *off, has_rights: !rights.is_empty(), cred,
                }), g.consumed, g.produced, passcred);
            let allowed = core::cmp::min(stop, window.stop).saturating_sub(g.consumed) as usize;
            let take = core::cmp::min(core::cmp::min(max, allowed), g.buf.len());
            let mut out = Vec::with_capacity(take);
            for _ in 0..take {
                out.push(g.buf.pop_front().unwrap());
            }
            g.consumed += take as u64;
            // A segment gives up its descriptors as soon as ANY of its bytes
            // has been handed over without a cmsg, and is retired once its
            // last byte is gone. A partly-drained segment stays so the bytes
            // still queued keep naming their sender.
            loop {
                let Some((off, _, _)) = g.ancillary.front() else { break };
                if *off >= g.consumed { break; }
                let segment_end = g.ancillary.get(1).map(|(next, _, _)| *next).unwrap_or(g.produced);
                if segment_end <= g.consumed {
                    let (_, f, _) = g.ancillary.pop_front().unwrap();
                    rights_later.push(f);
                    continue;
                }
                let Some((_, rights, _)) = g.ancillary.front_mut() else { break };
                if !rights.is_empty() {
                    rights_later.push(core::mem::replace(rights, GcRights::from_files(Vec::new())));
                }
                break;
            }
            out
        };
        let mut drop_later: Vec<Arc<vfs::File>> = Vec::new();
        for rights in rights_later { drop_later.extend(rights.take_files()); }
        drop(drop_later);
        super::super::collect_scm_rights();
        #[cfg(target_os = "oxide-kernel")]
        if !out.is_empty() {
            self.writer_waiters(end.other()).wake_all();
            super::super::wake_peer_subs(self, end, vfs::POLL_OUT);
        }
        out
    }

    /// Linux `prepare_to_wait` for a blocking stream read: atomically, under
    /// the read-ring lock, either hand back available data / EOF, or register
    /// the caller on the reader wait list and report `Parked`. `write_inner`
    /// takes this SAME ring lock to push bytes and only wakes AFTER dropping
    /// it, so a writer is serialized behind us - it cannot slip a write+wake
    /// between our emptiness check and our park and lose the wakeup. This
    /// closes the check-then-park race in `read_unix_stream_blocking` that
    /// stalled the D-Bus private-connection stream read (gdm greeter). Caller
    /// MUST `schedule()` after a `Parked` return (the ring lock is released
    /// here). # C: O(min(max, queue))
    #[cfg(target_os = "oxide-kernel")]
    pub fn read_or_park(&self, end: UnixEnd, max: usize, deadline_ns: u64, passcred: bool,
        inline: bool) -> ReadOutcome {
        let read_ring = match end {
            UnixEnd::A => &self.b_to_a,
            UnixEnd::B => &self.a_to_b,
        };
        let g = read_ring.lock();
        if !g.buf.is_empty() {
            drop(g);
            return ReadOutcome::Data(self.read_passcred(end, max, passcred, inline));
        }
        if self.take_reset(end) {
            drop(g);
            return ReadOutcome::Reset;
        }
        if g.closed_writer || g.reader_shutdown {
            drop(g);
            return ReadOutcome::Eof;
        }
        // Register on the wait list while STILL holding the read-ring lock:
        // the writer must take this lock to push, so it can only wake us
        // after we are already on the list.
        // SAFETY: running task on this CPU; preempt-off owned by the syscall
        // stub; park_with_deadline marks Sleeping + enqueues on the WaitList;
        // the ring lock is dropped below and the caller owns the schedule().
        unsafe { self.reader_waiters(end).park_interruptible_with_deadline(deadline_ns); }
        drop(g);
        ReadOutcome::Parked
    }

    /// MSG_PEEK variant of `read`: copy without draining.
    /// # C: O(min(max, queued))
    pub fn peek(&self, end: UnixEnd, max: usize, inline: bool) -> Vec<u8> {
        let mut g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        // A peek steps over the out-of-band records in front of it without
        // retiring them, so the next receive still meets them.
        let head = g.consumed;
        let window = g.oob_window(head, true, inline);
        let start = window.head.saturating_sub(g.consumed) as usize;
        let end_index = core::cmp::min(window.stop.saturating_sub(g.consumed) as usize, g.buf.len());
        let take = core::cmp::min(max, end_index.saturating_sub(start));
        g.buf.iter().skip(start).take(take).copied().collect()
    }
}
