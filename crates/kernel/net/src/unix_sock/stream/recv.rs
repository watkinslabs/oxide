use alloc::{sync::Arc, vec::Vec};
use core::ops::Deref;

use vfs;

use super::UnixPair;
use super::coalesce::{coalesce_run, report_window, Segment, StopCause};
use super::super::{GcRights, UnixEnd};

/// Received descriptors plus a stream-control stop marker. `is_empty()` is
/// false at either an SCM_RIGHTS or sender-credential boundary so MSG_WAITALL
/// terminates without syscall-layer knowledge of queue records.
pub struct StreamFiles {
    files: Vec<Arc<vfs::File>>,
    cred_stop: bool,
}

impl StreamFiles {
    fn new(files: Vec<Arc<vfs::File>>, cred_stop: bool) -> Self { Self { files, cred_stop } }

    /// Whether receive may continue across this control result. # C: O(1)
    pub fn stops_waitall(&self, passcred: bool) -> bool { !self.files.is_empty() || (passcred && self.cred_stop) }
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
    { self.read_stream_with_offset(end, max, peek, 0, false, copy) }

    /// Transactional stream receive after a non-consuming logical offset.
    ///
    /// `passcred` is whether the RECEIVING socket may pass credentials. Segments
    /// keep being glued into ONE receive until the run rule ends the run; the
    /// receive reports the credential of the first glued segment and the
    /// descriptors of every glued one.
    /// # C: O(offset + max + rights)
    pub fn read_stream_with_offset<R, E>(&self, end: UnixEnd, max: usize, peek: bool, offset: usize, passcred: bool,
        copy: impl FnOnce(&[u8], usize, Option<(u32, u32, u32)>) -> Result<(R, usize), E>)
        -> Result<Option<(R, StreamFiles, Option<(u32, u32, u32)>)>, E>
    {
        let mut g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        let logical = g.consumed.saturating_add(offset as u64);
        let run = coalesce_run(segments(&g.ancillary), logical, g.produced, passcred);
        let cap = core::cmp::min(offset.saturating_add(max),
            run.stop.saturating_sub(g.consumed) as usize);
        let data_end = core::cmp::min(cap, g.buf.len());
        let take = core::cmp::min(max, data_end.saturating_sub(offset));
        // Ancillary data belongs to the segments the copied bytes reach; a peek
        // continuation must not report what its earlier step already did.
        let reached = g.consumed.saturating_add((offset + take) as u64);
        let reported_through = if peek && offset != 0 { Some(g.consumed) } else { None };
        let (report_start, report_count) = report_window(segments(&g.ancillary), reached, reported_through);
        let mut rights_len = 0usize;
        for (_, rights, _) in g.ancillary.iter().skip(report_start).take(report_count) {
            rights_len += rights.len();
        }
        // Rendered for the READER's pid namespace.
        let cred_out = if report_count == 0 { None } else {
            g.ancillary.get(report_start).map(|(_, _, cred)| cred.ids_for_reader())
        };
        if offset >= data_end && report_count == 0 { return Ok(None); }
        let out: Vec<u8> = g.buf.iter().skip(offset).take(take).copied().collect();
        let (copied, commit) = copy(&out, rights_len, cred_out)?;
        let commit = core::cmp::min(commit, take);
        let cred_stop = run.cause == StopCause::Sender && commit == take
            && offset.saturating_add(take) == cap;
        if peek {
            let mut files = Vec::with_capacity(rights_len);
            for (_, rights, _) in g.ancillary.iter().skip(report_start).take(report_count) {
                files.extend(rights.clone_files());
            }
            return Ok(Some((copied, StreamFiles::new(files, cred_stop), cred_out)));
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
        Ok(Some((copied, StreamFiles::new(files, cred_stop), cred_out)))
    }

    /// Boundary-aware infallible stream drain used by legacy receive paths. # C: O(max + rights)
    pub fn read_stream(&self, end: UnixEnd, max: usize) -> (Vec<u8>, StreamFiles, Option<(u32, u32, u32)>) {
        self.read_stream_passcred(end, max, false)
    }

    /// `read_stream` for a receiver whose socket may pass credentials. # C: O(max + rights)
    pub fn read_stream_passcred(&self, end: UnixEnd, max: usize, passcred: bool)
        -> (Vec<u8>, StreamFiles, Option<(u32, u32, u32)>)
    {
        self.read_stream_with_offset(end, max, false, 0, passcred,
            |data, _, _| Ok::<_, core::convert::Infallible>((data.to_vec(), data.len())))
            .unwrap_or_else(|never| match never {})
            .map(|(data, files, cred)| (data, files, cred))
            .unwrap_or_else(|| (Vec::new(), StreamFiles::new(Vec::new(), false), None))
    }
}
