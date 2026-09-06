//! Class-long get/set over the canonical class record: the negative WNDCLASSEX
//! offsets name one field each, non-negative offsets index the class extra
//! bytes. Ordering and the values a caller may not change mirror Win32.
use super::{LongPtrError, WindowId, WindowManager};

pub const GCL_MENUNAME: i32 = -8;
pub const GCLP_HBRBACKGROUND: i32 = -10;
pub const GCLP_HCURSOR: i32 = -12;
pub const GCLP_HICON: i32 = -14;
pub const GCLP_HMODULE: i32 = -16;
pub const GCL_CBWNDEXTRA: i32 = -18;
pub const GCL_CBCLSEXTRA: i32 = -20;
pub const GCLP_WNDPROC: i32 = -24;
pub const GCL_STYLE: i32 = -26;
pub const GCW_ATOM: i32 = -32;
pub const GCLP_HICONSM: i32 = -34;

/// Widths a class long accepts; anything else is a caller defect. # C: O(1)
pub const fn valid_width(width: usize) -> bool { matches!(width, 2 | 4 | 8) }

impl WindowManager {
    /// Read one class long of the class a window carries. # C: O(N_windows + N_classes)
    pub fn class_long(&self, window: WindowId, offset: i32, width: usize) -> Result<u64, LongPtrError> {
        if !valid_width(width) { return Err(LongPtrError::InvalidSize); }
        let atom = self.get(window).ok_or(LongPtrError::InvalidWindow)?.class_atom.ok_or(LongPtrError::InvalidWindow)?;
        let class = self.classes.iter().find(|class| class.atom == atom).ok_or(LongPtrError::InvalidWindow)?;
        let value = match offset {
            GCW_ATOM => class.atom as u64,
            GCL_STYLE => class.style as u64,
            GCL_CBWNDEXTRA => class.cb_wnd_extra as u64,
            GCL_CBCLSEXTRA => class.extra.len() as u64,
            GCLP_HMODULE => class.module,
            GCLP_HBRBACKGROUND => class.background,
            GCLP_HCURSOR => class.cursor,
            GCLP_HICON => class.icon,
            GCLP_HICONSM => class.icon_sm,
            GCLP_WNDPROC => class.wndproc,
            GCL_MENUNAME => 0,
            _ => return class.extra.read(offset, width),
        };
        Ok(truncate(value, width))
    }
    /// Replace one class long and answer its previous value. # C: O(N_windows + N_classes)
    pub fn set_class_long(&mut self, window: WindowId, offset: i32, value: u64, width: usize) -> Result<u64, LongPtrError> {
        if !valid_width(width) { return Err(LongPtrError::InvalidSize); }
        let atom = self.get(window).ok_or(LongPtrError::InvalidWindow)?.class_atom.ok_or(LongPtrError::InvalidWindow)?;
        let class = self.classes.iter_mut().find(|class| class.atom == atom).ok_or(LongPtrError::InvalidWindow)?;
        let previous = match offset {
            GCLP_HBRBACKGROUND => core::mem::replace(&mut class.background, value),
            GCLP_HCURSOR => core::mem::replace(&mut class.cursor, value),
            GCLP_HICON => core::mem::replace(&mut class.icon, value),
            GCLP_HICONSM => core::mem::replace(&mut class.icon_sm, value),
            GCLP_WNDPROC => core::mem::replace(&mut class.wndproc, value),
            GCLP_HMODULE => core::mem::replace(&mut class.module, value),
            GCL_STYLE => core::mem::replace(&mut class.style, value as u32) as u64,
            GCL_CBWNDEXTRA => core::mem::replace(&mut class.cb_wnd_extra, value as u32) as u64,
            // The class extra size is fixed at registration; Win32 rejects the
            // change rather than reallocating storage other windows share.
            GCL_CBCLSEXTRA => return Err(LongPtrError::InvalidSize),
            // A menu name is exchanged through a client-owned descriptor, so
            // the previous value is meaningless to the caller.
            GCL_MENUNAME => 0,
            _ => return class.extra.write(offset, width, value),
        };
        Ok(truncate(previous, width))
    }
    /// Class cursor of the class a window carries; zero when none. # C: O(N_windows + N_classes)
    pub fn class_cursor(&self, window: WindowId) -> Option<u64> {
        let atom = self.get(window)?.class_atom?;
        self.classes.iter().find(|class| class.atom == atom).map(|class| class.cursor)
    }
}

const fn truncate(value: u64, width: usize) -> u64 {
    match width { 2 => value & 0xffff, 4 => value & 0xffff_ffff, _ => value }
}

#[cfg(test)]
#[path = "tests/class_long.rs"]
mod tests;
