// Resource-manager space: the model behind the second device node.
//
// A device holds only a handful of transient objects and sessions at once, so
// the resource manager gives each open file its own space and swaps that
// space's objects in and out around every command. Two properties matter and
// both are enforced here:
//
//   - a file never sees a physical handle. Commands carry VIRTUAL handles
//     that only this space can resolve, so one file cannot name — or flush —
//     another file's object by guessing a number.
//   - closing a file releases everything it loaded. A space that leaked one
//     object would eventually exhaust the device for every other user.

use alloc::vec::Vec;

use crate::limits::{SPACE_CONTEXT_SLOTS, SPACE_SESSION_SLOTS};
use crate::uapi::{TPM2_HANDLE_INDEX_MASK, TPM2_HT_HMAC_SESSION, TPM2_HT_MASK, TPM2_HT_POLICY_SESSION, TPM2_HT_TRANSIENT};

/// What a context slot holds.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Slot {
    /// Unused.
    Empty,
    /// Loaded in the device under this physical handle.
    Loaded(u32),
    /// Saved out of the device; the blob lives in the space's buffer.
    Saved,
}

/// Why a space operation was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SpaceError {
    /// Every context or session slot is in use.
    NoSlots,
    /// The handle names no object in this space.
    UnknownHandle(u32),
    /// The saved-context buffer cannot hold another blob.
    NoStorage,
}

/// One file's view of the device.
pub struct Space {
    context_tbl: [Slot; SPACE_CONTEXT_SLOTS],
    session_tbl: [u32; SPACE_SESSION_SLOTS],
    context_buf: Vec<u8>,
    session_buf: Vec<u8>,
    buf_size: usize,
}

impl Space {
    /// A space with `buf_size` bytes of backing store for saved contexts and
    /// the same again for saved sessions. # C: O(1)
    pub fn new(buf_size: usize) -> Self {
        Space {
            context_tbl: [Slot::Empty; SPACE_CONTEXT_SLOTS],
            session_tbl: [0u32; SPACE_SESSION_SLOTS],
            context_buf: Vec::new(),
            session_buf: Vec::new(),
            buf_size,
        }
    }

    /// Virtual handle naming context slot `i`. Slots are numbered downwards
    /// from the top of the transient range so a virtual handle can never
    /// collide with a physical one the device would assign. # C: O(1)
    pub fn vhandle_of_slot(i: usize) -> u32 { TPM2_HT_TRANSIENT | (TPM2_HANDLE_INDEX_MASK - i as u32) }

    /// Context slot a virtual handle names, if it names one at all.
    /// # C: O(1)
    pub fn slot_of_vhandle(v: u32) -> Option<usize> {
        if v & TPM2_HT_MASK != TPM2_HT_TRANSIENT { return None; }
        let i = TPM2_HANDLE_INDEX_MASK - (v & TPM2_HANDLE_INDEX_MASK);
        if i as usize >= SPACE_CONTEXT_SLOTS { return None; }
        Some(i as usize)
    }

    /// Whether a handle is a transient object handle. # C: O(1)
    pub fn is_transient(h: u32) -> bool { h & TPM2_HT_MASK == TPM2_HT_TRANSIENT }

    /// Whether a handle names a session. # C: O(1)
    pub fn is_session(h: u32) -> bool {
        matches!(h & TPM2_HT_MASK, TPM2_HT_HMAC_SESSION | TPM2_HT_POLICY_SESSION)
    }

    /// Physical handle a virtual handle resolves to. A virtual handle whose
    /// slot is empty resolves to nothing — that is how a file is prevented
    /// from naming an object it never loaded. # C: O(1)
    pub fn resolve(&self, vhandle: u32) -> Result<u32, SpaceError> {
        let i = Self::slot_of_vhandle(vhandle).ok_or(SpaceError::UnknownHandle(vhandle))?;
        match self.context_tbl[i] {
            Slot::Loaded(p) => Ok(p),
            _ => Err(SpaceError::UnknownHandle(vhandle)),
        }
    }

    /// Give a newly created physical handle a virtual name in this space.
    /// # C: O(slots)
    pub fn bind(&mut self, phandle: u32) -> Result<u32, SpaceError> {
        for i in 0..SPACE_CONTEXT_SLOTS {
            if self.context_tbl[i] == Slot::Empty {
                self.context_tbl[i] = Slot::Loaded(phandle);
                return Ok(Self::vhandle_of_slot(i));
            }
        }
        Err(SpaceError::NoSlots)
    }

    /// Virtual name an already-bound physical handle carries. # C: O(slots)
    pub fn vhandle_of(&self, phandle: u32) -> Option<u32> {
        (0..SPACE_CONTEXT_SLOTS)
            .find(|&i| self.context_tbl[i] == Slot::Loaded(phandle))
            .map(Self::vhandle_of_slot)
    }

    /// Record a session the device created for this space. # C: O(slots)
    pub fn add_session(&mut self, handle: u32) -> Result<(), SpaceError> {
        for s in self.session_tbl.iter_mut() {
            if *s == 0 { *s = handle; return Ok(()); }
        }
        Err(SpaceError::NoSlots)
    }

    /// Sessions currently owned by this space. # C: O(slots)
    pub fn sessions(&self) -> Vec<u32> { self.session_tbl.iter().copied().filter(|h| *h != 0).collect() }

    /// Objects currently loaded in the device on this space's behalf.
    /// # C: O(slots)
    pub fn loaded(&self) -> Vec<u32> {
        self.context_tbl.iter().filter_map(|s| match s { Slot::Loaded(p) => Some(*p), _ => None }).collect()
    }

    /// Note that slot `i`'s object has been saved out of the device, storing
    /// its blob. The slot keeps its virtual handle so the file's next command
    /// can still name it. # C: O(blob length)
    pub fn save(&mut self, i: usize, blob: &[u8]) -> Result<(), SpaceError> {
        if i >= SPACE_CONTEXT_SLOTS { return Err(SpaceError::NoSlots); }
        if self.context_buf.len() + blob.len() > self.buf_size { return Err(SpaceError::NoStorage); }
        self.context_buf.extend_from_slice(blob);
        self.context_tbl[i] = Slot::Saved;
        Ok(())
    }

    /// Note that slot `i`'s object has been loaded back under `phandle`.
    /// # C: O(1)
    pub fn reload(&mut self, i: usize, phandle: u32) -> Result<(), SpaceError> {
        if i >= SPACE_CONTEXT_SLOTS { return Err(SpaceError::NoSlots); }
        self.context_tbl[i] = Slot::Loaded(phandle);
        Ok(())
    }

    /// Store a saved session blob. # C: O(blob length)
    pub fn save_session(&mut self, blob: &[u8]) -> Result<(), SpaceError> {
        if self.session_buf.len() + blob.len() > self.buf_size { return Err(SpaceError::NoStorage); }
        self.session_buf.extend_from_slice(blob);
        Ok(())
    }

    /// Forget a session the device says no longer exists. # C: O(slots)
    pub fn forget_session(&mut self, handle: u32) {
        for s in self.session_tbl.iter_mut() { if *s == handle { *s = 0; } }
    }

    /// Saved context bytes. # C: O(1)
    pub fn context_buf(&self) -> &[u8] { &self.context_buf }

    /// Saved session bytes. # C: O(1)
    pub fn session_buf(&self) -> &[u8] { &self.session_buf }

    /// Every physical handle the device must be told to flush, and empty the
    /// space. Called when the file closes: whatever this space loaded is its
    /// to release. # C: O(slots)
    pub fn close(&mut self) -> Vec<u32> {
        let mut out = self.loaded();
        out.extend(self.sessions());
        self.context_tbl = [Slot::Empty; SPACE_CONTEXT_SLOTS];
        self.session_tbl = [0u32; SPACE_SESSION_SLOTS];
        self.context_buf.clear();
        self.session_buf.clear();
        out
    }
}
