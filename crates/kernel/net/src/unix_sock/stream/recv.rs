use alloc::{sync::Arc, vec::Vec};
use core::ops::Deref;

use vfs;

use super::UnixPair;
use super::coalesce::{coalesce_run, report_window, Segment, StopCause};
use super::super::{GcRights, MsgCred, UnixEnd};

/// Received descriptors plus a stream-control stop marker. `is_empty()` is
/// false at either an SCM_RIGHTS or sender-credential boundary so MSG_WAITALL
/// terminates without syscall-layer knowledge of queue records.
pub struct StreamFiles {
    files: Vec<Arc<vfs::File>>,
    cred_stop: bool,
    oob_stop: bool,
    sender: Option<MsgCred>,
}

impl StreamFiles {
    fn new(files: Vec<Arc<vfs::File>>, cred_stop: bool) -> Self {
        Self { files, cred_stop, oob_stop: false, sender: None }
    }

    fn with_sender(files: Vec<Arc<vfs::File>>, cred_stop: bool, oob_stop: bool,
        sender: Option<MsgCred>) -> Self
    { Self { files, cred_stop, oob_stop, sender } }

    /// Whether receive may continue across this control result. An out-of-band
    /// record ends the receive whatever the receiver asked for: in-band data is
    /// never glued across the mark. # C: O(1)
    pub fn stops_waitall(&self, passcred: bool) -> bool {
        !self.files.is_empty() || (passcred && self.cred_stop) || self.oob_stop
    }

    /// The writer this run glued bytes from, for a MSG_WAITALL receive to latch
    /// and carry across a sleep so a later writer cannot be glued on. # C: O(1)
    pub fn committed_sender(&self) -> Option<&MsgCred> { self.sender.as_ref() }
}

/// Whether a stream receive that just glued a run must go back for more bytes.
/// MSG_WAITALL keeps gluing until the buffer fills or a control boundary ends
/// the run; a MSG_PEEK receive that already copied something never does, since
/// it walks off the end of the queue and returns what it has rather than
/// sleeping for a writer. # C: O(1)
pub fn stream_recv_continues(waitall: bool, peek: bool, total: usize, capacity: usize, stopped: bool) -> bool {
    if !waitall || stopped || total >= capacity { return false; }
    !(peek && total != 0)
}

impl Deref for StreamFiles {
    type Target = [Arc<vfs::File>];
    fn deref(&self) -> &Self::Target { &self.files }
}

impl IntoIterator for StreamFiles {
    type Item = Arc<vfs::File>;
    type IntoIter = alloc::vec::IntoIter<Self::Item>;
    fn into_iter(self) -> Self::IntoIter { self.files.into_iter() }
}

/// The queued ancillary records as the coalescing rule sees them. # C: O(1)
fn segments(ancillary: &alloc::collections::VecDeque<(u64, GcRights, super::super::MsgCred)>)
    -> impl Iterator<Item = Segment<'_>>
{
    ancillary.iter().map(|(off, rights, cred)| Segment { off: *off, has_rights: !rights.is_empty(), cred })
}

impl UnixPair {
    /// Inspect one boundary-limited stream run and commit it only when
    /// `copy` succeeds. Callback runs under the receive-ring lock. # C: O(max + rights)
    pub fn read_stream_with<R, E>(&self, end: UnixEnd, max: usize, copy: impl FnOnce(&[u8], usize, Option<(u32, u32, u32)>) -> Result<(R, usize), E>)
        -> Result<Option<(R, StreamFiles, Option<(u32, u32, u32)>)>, E>
    { self.read_stream_with_opts(end, max, false, copy) }

    /// Transactional stream receive with optional non-consuming peek. # C: O(max + rights)
    pub fn read_stream_with_opts<R, E>(&self, end: UnixEnd, max: usize, peek: bool, copy: impl FnOnce(&[u8], usize, Option<(u32, u32, u32)>) -> Result<(R, usize), E>)
        -> Result<Option<(R, StreamFiles, Option<(u32, u32, u32)>)>, E>
    { self.read_stream_with_offset(end, max, peek, 0, false, None, false, copy) }

    /// Transactional stream receive after a non-consuming logical offset.
    ///
    /// `passcred` is whether the RECEIVING socket may pass credentials. Segments
    /// keep being glued into ONE receive until the run rule ends the run; the
    /// receive reports the credential of the first glued segment and the
    /// descriptors of every glued one.
    ///
    /// `committed` carries a MSG_WAITALL receive's already-glued writer across
    /// the sleep it does when the queue runs dry. A different writer at the
    /// cursor then yields a run of NO bytes whose `stops_waitall` is set — a
    /// boundary, distinct from the `Ok(None)` that means nothing is queued.
    /// # C: O(offset + max + rights)
    /// `inline` is the receiving socket's `SO_OOBINLINE`: with it set the
    /// out-of-band byte is delivered here as ordinary data instead of being
    /// stepped over.
    pub fn read_stream_with_offset<R, E>(&self, end: UnixEnd, max: usize, peek: bool, offset: usize, passcred: bool,
        committed: Option<&MsgCred>, inline: bool,
        copy: impl FnOnce(&[u8], usize, Option<(u32, u32, u32)>) -> Result<(R, usize), E>)
        -> Result<Option<(R, StreamFiles, Option<(u32, u32, u32)>)>, E>
    {
        let mut g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        // Step over the out-of-band records standing in front of this receive
        // BEFORE any of the in-band boundary work: a consuming step retires
        // them, which moves `consumed`, and every index below is taken from it.
        let head = g.consumed.saturating_add(offset as u64);
        let window = g.oob_window(head, peek, inline);
        let ring_off = window.head.saturating_sub(g.consumed) as usize;
        let run = coalesce_run(segments(&g.ancillary), window.head, g.produced, passcred, committed);
        let stop = core::cmp::min(run.stop, window.stop);
        let cap = core::cmp::min(ring_off.saturating_add(max),
            stop.saturating_sub(g.consumed) as usize);
        let data_end = core::cmp::min(cap, g.buf.len());
        let take = core::cmp::min(max, data_end.saturating_sub(ring_off));
        // Ancillary data belongs to the segments the copied bytes reach; a peek
        // continuation must not report what its earlier step already did.
        let reached = g.consumed.saturating_add((ring_off + take) as u64);
        let reported_through = if peek && ring_off != 0 { Some(g.consumed) } else { None };
        let (report_start, report_count) = report_window(segments(&g.ancillary), reached, reported_through);
        let mut rights_len = 0usize;
        for (_, rights, _) in g.ancillary.iter().skip(report_start).take(report_count) {
            rights_len += rights.len();
        }
        // Rendered for the READER's pid namespace.
        let head = if report_count == 0 { None } else { g.ancillary.get(report_start) };
        let cred_out = head.map(|(_, _, cred)| cred.ids_for_reader());
        let sender = head.map(|(_, _, cred)| cred.clone());
        // A run the committed writer ended at the cursor carries no bytes and no
        // ancillary data, yet is NOT an empty queue: report it so a MSG_WAITALL
        // caller ends its receive instead of sleeping on data it may not glue.
        let ended_at_cursor = run.cause == StopCause::Sender && run.stop <= window.head;
        if ring_off >= data_end && report_count == 0 && !ended_at_cursor { return Ok(None); }
        let out: Vec<u8> = g.buf.iter().skip(ring_off).take(take).copied().collect();
        let (copied, commit) = copy(&out, rights_len, cred_out)?;
        let commit = core::cmp::min(commit, take);
        let reached_stop = commit == take && ring_off.saturating_add(take) == cap;
        let cred_stop = run.cause == StopCause::Sender && reached_stop;
        // The window's boundary only ends the receive when it is the one the
        // copy actually reached; the in-band rule may have stopped it sooner.
        let oob_stop = window.oob_stop && window.stop <= run.stop && reached_stop;
        if peek {
            let mut files = Vec::with_capacity(rights_len);
            for (_, rights, _) in g.ancillary.iter().skip(report_start).take(report_count) {
                files.extend(rights.clone_files());
            }
            return Ok(Some((copied, StreamFiles::with_sender(files, cred_stop, oob_stop, sender), cred_out)));
        }
        for _ in 0..commit { g.buf.pop_front(); }
        g.consumed += commit as u64;
        // A segment is retired once its last byte is gone; a segment only
        // partly drained keeps its record so the bytes still queued name their
        // sender, but gives up its descriptors with its first delivered byte.
        let mut rights_out: Vec<GcRights> = Vec::new();
        loop {
            let Some((off, _, _)) = g.ancillary.front() else { break };
            if *off >= g.consumed { break; }
            let segment_end = g.ancillary.get(1).map(|(next, _, _)| *next).unwrap_or(g.produced);
            if segment_end <= g.consumed {
                let (_, rights, _) = g.ancillary.pop_front().unwrap();
                rights_out.push(rights);
                continue;
            }
            let Some((_, rights, _)) = g.ancillary.front_mut() else { break };
            if !rights.is_empty() {
                rights_out.push(core::mem::replace(rights, GcRights::from_files(Vec::new())));
            }
            break;
        }
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        if commit != 0 {
            self.writer_waiters(end.other()).wake_all();
            super::super::wake_peer_subs(self, end, vfs::POLL_OUT);
        }
        let mut files = Vec::new();
        for rights in rights_out { files.extend(rights.take_files()); }
        Ok(Some((copied, StreamFiles::with_sender(files, cred_stop, oob_stop, sender), cred_out)))
    }

    /// Boundary-aware infallible stream drain used by legacy receive paths. # C: O(max + rights)
    pub fn read_stream(&self, end: UnixEnd, max: usize) -> (Vec<u8>, StreamFiles, Option<(u32, u32, u32)>) {
        self.read_stream_passcred(end, max, false)
    }

    /// `read_stream` for a receiver whose socket may pass credentials. # C: O(max + rights)
    pub fn read_stream_passcred(&self, end: UnixEnd, max: usize, passcred: bool)
        -> (Vec<u8>, StreamFiles, Option<(u32, u32, u32)>)
    {
        self.read_stream_with_offset(end, max, false, 0, passcred, None, false,
            |data, _, _| Ok::<_, core::convert::Infallible>((data.to_vec(), data.len())))
            .unwrap_or_else(|never| match never {})
            .map(|(data, files, cred)| (data, files, cred))
            .unwrap_or_else(|| (Vec::new(), StreamFiles::new(Vec::new(), false), None))
    }
}
