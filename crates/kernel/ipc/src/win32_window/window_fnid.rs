//! Window function identity: the builtin control a window's procedure belongs
//! to, recorded on the window itself.
//!
//! An identity names one entry of the client procedure array, marked by its
//! high bit; a window keeps the first identity it is given, so a second call
//! naming a different one is refused while a call repeating the same one is
//! accepted without change.

use super::{WindowError, WindowId, WindowManager};

/// Bit every valid identity carries; an identity without it names no entry.
pub const FNID_VALID: u16 = 0x8000;
/// The client procedure index an identity names.
pub const FNID_INDEX: u16 = 0x7fff;
/// Entries the client procedure arrays hold.
pub const CLIENT_PROC_COUNT: u16 = 17;
/// Client procedure indices whose windows keep no private extra region: a
/// dialog and an MDI client publish their whole extra area to the application.
pub const PROC_DIALOG: u16 = 10;
pub const PROC_MDICLIENT: u16 = 13;

/// Bytes an identity reserves at the front of a window's extra area. A builtin
/// control keeps its entire extra area to itself; a window with no identity,
/// and the two identities whose extra area is the application's, reserve none.
/// # C: O(1)
pub const fn private_size(fnid: u16, extra_size: usize) -> usize {
    match fnid_proc_index(fnid) {
        None => 0,
        Some(index) if index as u16 == PROC_DIALOG || index as u16 == PROC_MDICLIENT => 0,
        Some(_) => extra_size,
    }
}

/// Build the identity of one client procedure index. # C: O(1)
pub const fn make_fnid(index: u16) -> u16 { FNID_VALID | index }

/// The client procedure index one identity names, absent when the identity
/// carries no valid bit or names an index past the arrays. # C: O(1)
pub const fn fnid_proc_index(fnid: u16) -> Option<usize> {
    if fnid & FNID_VALID == 0 { return None; }
    let index = fnid & FNID_INDEX;
    if index >= CLIENT_PROC_COUNT { return None; }
    Some(index as usize)
}

impl WindowManager {
    /// The identity one window carries; a window that was never given one
    /// carries zero. # C: O(N_windows)
    pub fn window_fnid(&self, id: WindowId) -> Option<u16> { self.get(id).map(|record| record.fnid) }

    /// Give one window its identity. A window keeps the first identity it is
    /// given: naming the same one again changes nothing, and naming a
    /// different one is refused. # C: O(N_windows)
    pub fn set_window_fnid(&mut self, id: WindowId, fnid: u16) -> Result<(), WindowError> {
        let (_, record) = self.windows.iter_mut().find(|(window, _)| *window == id).ok_or(WindowError::NoSuchWindow)?;
        if record.fnid != 0 && record.fnid != fnid { return Err(WindowError::InvalidParent); }
        record.fnid = fnid;
        let reserved = private_size(fnid, record.extra.len());
        record.extra.set_private_size(reserved);
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/window_fnid.rs"]
mod tests;
