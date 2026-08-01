use alloc::{sync::Arc, vec::Vec};
use core::ops::Deref;

use vfs;

use super::UnixPair;
use super::super::UnixEnd;

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

impl UnixPair {
    /// Inspect one boundary-limited stream segment and commit it only when
    /// `copy` succeeds. Callback runs under the receive-ring lock. # C: O(max + rights)
    pub fn read_stream_with<R, E>(&self, end: UnixEnd, max: usize, copy: impl FnOnce(&[u8], usize, Option<(u32, u32, u32)>) -> Result<(R, usize), E>)
        -> Result<Option<(R, StreamFiles, Option<(u32, u32, u32)>)>, E>
    { self.read_stream_with_opts(end, max, false, copy) }

    /// Transactional stream receive with optional non-consuming peek. # C: O(max + rights)
    pub fn read_stream_with_opts<R, E>(&self, end: UnixEnd, max: usize, peek: bool, copy: impl FnOnce(&[u8], usize, Option<(u32, u32, u32)>) -> Result<(R, usize), E>)
        -> Result<Option<(R, StreamFiles, Option<(u32, u32, u32)>)>, E>
    { self.read_stream_with_offset(end, max, peek, 0, copy) }

    /// Transactional stream receive after a non-consuming logical offset. # C: O(offset + max + rights)
    pub fn read_stream_with_offset<R, E>(&self, end: UnixEnd, max: usize, peek: bool, offset: usize, copy: impl FnOnce(&[u8], usize, Option<(u32, u32, u32)>) -> Result<(R, usize), E>)
        -> Result<Option<(R, StreamFiles, Option<(u32, u32, u32)>)>, E>
    {
        let mut g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        let logical = g.consumed.saturating_add(offset as u64);
        let mut consume_eligible = 0usize;
        let mut return_start = 0usize;
        let mut return_end = 0usize;
        let mut rights_len = 0usize;
        let mut cred_out = None;
        let mut next_cred = None;
        let mut cap = offset.saturating_add(max);
        for (index, (off, _, cred)) in g.ancillary.iter().enumerate() {
            if *off <= g.consumed {
                consume_eligible += 1;
                if offset != 0 { return_start = index + 1; }
                return_end = index + 1;
            } else if peek && *off <= logical {
                return_end = index + 1;
            } else {
                cap = core::cmp::min(cap, (*off - g.consumed) as usize);
                // Rendered for the READER's pid namespace, here and below.
                next_cred = Some(cred.ids_for_reader());
                break;
            }
        }
        for (_, rights, cred) in g.ancillary.iter().skip(return_start).take(return_end - return_start) {
            rights_len += rights.len();
            cred_out = Some(cred.ids_for_reader());
        }
        let data_end = core::cmp::min(cap, g.buf.len());
        if offset >= data_end && return_start == return_end { return Ok(None); }
        let take = core::cmp::min(max, data_end.saturating_sub(offset));
        let out: Vec<u8> = g.buf.iter().skip(offset).take(take).copied().collect();
        let (copied, commit) = copy(&out, rights_len, cred_out)?;
        let commit = core::cmp::min(commit, take);
        let cred_stop = commit == take && offset.saturating_add(take) == cap
            && next_cred.is_some() && cred_out.is_some() && next_cred != cred_out;
        if peek {
            let mut files = Vec::with_capacity(rights_len);
            for (_, rights, _) in g.ancillary.iter().skip(return_start).take(return_end - return_start) {
                files.extend(rights.clone_files());
            }
            return Ok(Some((copied, StreamFiles::new(files, cred_stop), cred_out)));
        }
        let mut rights_out = Vec::with_capacity(consume_eligible);
        for _ in 0..consume_eligible {
            let (_, rights, _) = g.ancillary.pop_front().unwrap();
            rights_out.push(rights);
        }
        for _ in 0..commit { g.buf.pop_front(); }
        g.consumed += commit as u64;
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
        self.read_stream_with(end, max, |data, _, _| Ok::<_, core::convert::Infallible>((data.to_vec(), data.len())))
            .unwrap_or_else(|never| match never {})
            .map(|(data, files, cred)| (data, files, cred))
            .unwrap_or_else(|| (Vec::new(), StreamFiles::new(Vec::new(), false), None))
    }
}
