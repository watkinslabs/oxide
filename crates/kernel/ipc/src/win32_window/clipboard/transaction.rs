//! Open/close/empty transaction and the close-time format synthesis.
use super::*;

impl ClipboardManager {
    /// Admit one open request. A second window cannot take the clipboard while
    /// another holds it open; reopening from the same window is admitted and
    /// answers the current owner. # C: O(1)
    pub fn open(&mut self, thread: u64, window: Option<WindowId>) -> Result<Option<WindowId>, ClipboardError> {
        if self.open_thread.is_some() && self.open_window != window { return Err(ClipboardError::InvalidLockSequence); }
        if self.open_thread.is_none() { self.open_seqno = self.seqno; }
        if self.open_thread != Some(thread) { self.rendering = 0; }
        self.open_window = window;
        self.open_thread = Some(thread);
        Ok(self.owner)
    }

    /// Close from the opening thread. A transaction that changed the store
    /// synthesizes the derivable formats, bumps the sequence number and names
    /// the viewer to notify. # C: O(N_formats)
    pub fn close(&mut self, thread: u64) -> Result<ClipboardNotify, ClipboardError> {
        if self.open_thread != Some(thread) { return Err(ClipboardError::NotOpen); }
        Ok(ClipboardNotify { viewer: self.close_transaction(), owner: self.owner })
    }

    pub(super) fn close_transaction(&mut self) -> Option<WindowId> {
        self.open_window = None;
        self.open_thread = None;
        if self.seqno == self.open_seqno { return None; }
        if self.synthesize() > 0 { self.seqno = self.seqno.wrapping_add(1); }
        self.viewer
    }

    /// Add the formats derivable from what the owner offered. Answers how many
    /// delay-rendered entries were added. # C: O(N_synthesis * N_formats)
    fn synthesize(&mut self) -> usize {
        let map = self.format_map;
        let has = |id: u32| id < CF_MAX && map & (1 << id) != 0;
        if !has(CF_LOCALE) && (has(CF_TEXT) || has(CF_OEMTEXT) || has(CF_UNICODETEXT)) {
            let lcid = self.lcid;
            let seqno = self.seqno;
            if let Ok(index) = self.add(CF_LOCALE) {
                let mut bytes = Vec::new();
                if bytes.try_reserve_exact(4).is_ok() {
                    bytes.extend_from_slice(&lcid.to_le_bytes());
                    self.formats[index].seqno = seqno;
                    self.formats[index].data = Some(bytes);
                    self.seqno = self.seqno.wrapping_add(1);
                } else { self.remove_at(index); }
            }
        }
        let mut total = 0;
        for row in SYNTHESIS {
            if has(row[0]) { continue; }
            let from = if has(row[1]) { row[1] } else if row[2] != 0 && has(row[2]) { row[2] } else { continue };
            let seqno = self.seqno;
            let Ok(index) = self.add(row[0]) else { continue };
            self.formats[index].from = from;
            self.formats[index].seqno = seqno;
            total += 1;
        }
        total
    }

    fn remove_at(&mut self, index: usize) {
        let id = self.formats[index].id;
        self.formats.remove(index);
        if id < CF_MAX { self.format_map &= !(1 << id); }
    }

    /// Discard every format and take ownership for the opening window.
    /// # C: O(N_formats)
    pub fn empty(&mut self, thread: u64) -> Result<(), ClipboardError> {
        if self.open_thread != Some(thread) { return Err(ClipboardError::NotOpen); }
        self.clear_formats();
        self.owner = self.open_window;
        self.seqno = self.seqno.wrapping_add(1);
        Ok(())
    }

    /// Drop ownership, discarding the formats no longer renderable, and name
    /// the viewer to notify when anything changed. # C: O(N_formats²)
    pub fn release_owner(&mut self, owner: WindowId) -> Result<ClipboardNotify, ClipboardError> {
        if self.owner != Some(owner) { return Err(ClipboardError::InvalidOwner); }
        self.owner = None;
        let mut changed = false;
        let mut index = 0;
        while index < self.formats.len() {
            let format = &self.formats[index];
            let keep = format.data.is_some()
                || (format.from != 0 && format.from < CF_MAX && self.format_map & (1 << format.from) != 0);
            if keep { index += 1; continue; }
            self.remove_at(index);
            changed = true;
        }
        if !changed { return Ok(ClipboardNotify { viewer: None, owner: None }); }
        self.seqno = self.seqno.wrapping_add(1);
        Ok(ClipboardNotify { viewer: self.viewer, owner: self.owner })
    }

    /// Whether this state has an active open transaction. # C: O(1)
    pub const fn is_open(&self) -> bool { self.open_thread.is_some() }
    /// Window that holds the clipboard open. # C: O(1)
    pub const fn open_window(&self) -> Option<WindowId> { self.open_window }
    /// Window that owns the current contents. # C: O(1)
    pub const fn owner(&self) -> Option<WindowId> { self.owner }
    /// Change sequence number; every content change advances it. # C: O(1)
    pub const fn sequence(&self) -> u32 { self.seqno }
}
