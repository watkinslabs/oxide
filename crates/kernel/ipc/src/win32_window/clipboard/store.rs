//! Format store: insertion, lookup, enumeration and the existence bitmap.
use super::*;

impl ClipboardManager {
    /// Create an empty clipboard for one window station. # C: O(1)
    pub const fn new() -> Self {
        Self { open_thread: None, open_window: None, owner: None, viewer: None, lcid: 0,
            seqno: 0, open_seqno: 0, rendering: 0, formats: Vec::new(), format_map: 0, listeners: Vec::new() }
    }

    fn find(&self, id: u32) -> Option<usize> { self.formats.iter().position(|format| format.id == id) }

    pub(super) fn add(&mut self, id: u32) -> Result<usize, ClipboardError> {
        self.formats.try_reserve(1).map_err(|_| ClipboardError::NoMemory)?;
        self.formats.push(ClipFormat { id, from: 0, seqno: 0, data: None });
        if id < CF_MAX { self.format_map |= 1 << id; }
        Ok(self.formats.len() - 1)
    }

    pub(super) fn clear_formats(&mut self) { self.formats.clear(); self.format_map = 0; }

    /// Count of formats currently offered. # C: O(1)
    pub fn count(&self) -> usize { self.formats.len() }

    /// Whether one format is offered; format zero is never available. # C: O(N_formats)
    pub fn is_available(&self, id: u32) -> bool { id != 0 && self.find(id).is_some() }

    /// Every offered format identifier, in offer order. # C: O(N_formats)
    pub fn format_ids(&self) -> Vec<u32> { self.formats.iter().map(|format| format.id).collect() }

    /// First identifier in `list` that the store offers, zero when the store is
    /// empty, and -1 when none of the priorities is available. # C: O(N_list * N_formats)
    pub fn priority_format(&self, list: &[u32]) -> i32 {
        if self.formats.is_empty() { return 0; }
        for id in list { if self.is_available(*id) { return *id as i32; } }
        -1
    }

    /// Walk the offer order. Zero starts the walk; the answer is zero at its end.
    /// # C: O(N_formats)
    pub fn enum_formats(&self, thread: u64, previous: u32) -> Result<u32, ClipboardError> {
        if self.open_thread != Some(thread) { return Err(ClipboardError::NotOpen); }
        let start = match previous {
            0 => 0,
            id => match self.find(id) { Some(index) => index + 1, None => return Ok(0) },
        };
        Ok(self.formats.get(start).map_or(0, |format| format.id))
    }

    /// Store one format's bytes. A write needs an open transaction and a
    /// non-zero format identifier; unlike a read it is not restricted to the
    /// opening thread. Answers the sequence number stamped on the entry.
    /// # C: O(N_formats + N_bytes)
    pub fn set_data(&mut self, id: u32, data: Option<&[u8]>, lcid: u32) -> Result<u32, ClipboardError> {
        if id == 0 || self.open_thread.is_none() { return Err(ClipboardError::NotOpen); }
        let copied = match data {
            None => None,
            Some(bytes) => {
                let mut owned = Vec::new();
                owned.try_reserve_exact(bytes.len()).map_err(|_| ClipboardError::NoMemory)?;
                owned.extend_from_slice(bytes);
                Some(owned)
            }
        };
        let index = match self.find(id) { Some(index) => index, None => self.add(id)? };
        let seqno = self.seqno;
        let format = &mut self.formats[index];
        format.from = 0;
        format.seqno = seqno;
        format.data = copied;
        if self.rendering == 0 { self.seqno = self.seqno.wrapping_add(1); }
        if id == CF_TEXT || id == CF_OEMTEXT || id == CF_UNICODETEXT { self.lcid = lcid; }
        Ok(seqno)
    }

    /// Read one format. Only the opening thread may read. A delay-rendered
    /// entry answers its own record with no bytes so the caller can ask the
    /// owner to render it. # C: O(N_formats)
    pub fn data(&self, thread: u64, id: u32) -> Result<&ClipFormat, ClipboardError> {
        if self.open_thread != Some(thread) { return Err(ClipboardError::NotOpen); }
        let index = self.find(id).ok_or(ClipboardError::NotFound)?;
        Ok(&self.formats[index])
    }

    /// Locale stamped by the last text format written. # C: O(1)
    pub const fn lcid(&self) -> u32 { self.lcid }
}
