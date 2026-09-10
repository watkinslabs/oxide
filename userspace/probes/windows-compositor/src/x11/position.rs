//! Canonical stacking projection and desktop-manager requests.
use super::{Backend, BackendError, Xid};
use crate::ffi;

impl Backend {
    /// Apply Curie's canonical insertion value: None=no reorder, 0=Top,
    /// 1=Bottom, MAX=Topmost, MAX-1=NotTopmost, otherwise an HWND sibling.
    /// Activation is an EWMH request; success means X accepted the request,
    /// not that a window manager has already granted focus.
    pub fn position(&mut self, hwnd: u32, insertion: Option<u64>, activate: bool) -> Result<(), BackendError> {
        let (xid, parent) = { let window = self.windows.get(&hwnd).ok_or(BackendError::InvalidCommand)?; (window.xid, window.parent) };
        if let Some(order) = insertion {
            match order {
                0 => self.restack(xid, parent == self.root, None, ffi::STACK_ABOVE)?,
                1 => self.restack(xid, parent == self.root, None, ffi::STACK_BELOW)?,
                u64::MAX => { self.set_topmost(xid, parent == self.root, true)?; self.restack(xid, parent == self.root, None, ffi::STACK_ABOVE)?; },
                value if value == u64::MAX - 1 => { self.set_topmost(xid, parent == self.root, false)?; self.restack(xid, parent == self.root, None, ffi::STACK_ABOVE)?; },
                sibling_hwnd => {
                    let sibling = u32::try_from(sibling_hwnd).map_err(|_| BackendError::InvalidCommand)?;
                    let sibling_xid = self.windows.get(&sibling).ok_or(BackendError::InvalidCommand)?.xid;
                    if self.windows.get(&sibling).map(|window| window.parent) != Some(parent) { return Err(BackendError::InvalidCommand); }
                    self.restack(xid, parent == self.root, Some(sibling_xid), ffi::STACK_BELOW)?;
                }
            }
        }
        if activate && parent == self.root { self.request_activation(xid)?; }
        unsafe { ffi::xcb_flush(self.conn); }
        Ok(())
    }

    fn restack(&self, xid: Xid, top_level: bool, sibling: Option<Xid>, mode: u32) -> Result<(), BackendError> {
        let mut values = [0u32; 2]; let mask = if let Some(sibling) = sibling { values[0] = sibling; values[1] = mode; ffi::CONFIGURE_SIBLING | ffi::CONFIGURE_STACK_MODE } else { values[0] = mode; ffi::CONFIGURE_STACK_MODE };
        let error = unsafe { ffi::xcb_request_check(self.conn, ffi::xcb_configure_window_checked(self.conn, xid, mask, values.as_ptr())) };
        if error.is_null() { return Ok(()); }
        let code = unsafe { (*error).error_code };
        eprintln!("windows-compositor: restack xid={xid:#x} sibling={sibling:?} mode={mode} top_level={top_level} error={code}");
        unsafe { libc::free(error.cast()); }
        if !top_level || code != ffi::BAD_MATCH { return Err(BackendError::X11); }
        // Decoration can put logical top-level siblings beneath different X parents.
        // The desktop manager owns that reconfiguration; retain the original XIDs.
        let mut event = [0u8; 32];
        event[0] = ffi::CONFIGURE_REQUEST; event[1] = mode as u8;
        event[4..8].copy_from_slice(&self.root.to_ne_bytes());
        event[8..12].copy_from_slice(&xid.to_ne_bytes());
        event[12..16].copy_from_slice(&sibling.unwrap_or(0).to_ne_bytes());
        event[26..28].copy_from_slice(&mask.to_ne_bytes());
        let error = unsafe { ffi::xcb_request_check(self.conn, ffi::xcb_send_event_checked(self.conn, 0,
            self.root, ffi::SUBSTRUCTURE_REDIRECT | ffi::SUBSTRUCTURE_NOTIFY, event.as_ptr().cast())) };
        if error.is_null() { Ok(()) } else { unsafe { libc::free(error.cast()); } Err(BackendError::X11) }
    }

    fn set_topmost(&self, xid: Xid, top_level: bool, enabled: bool) -> Result<(), BackendError> {
        if !top_level { return Ok(()); }
        let mut event = [0u8; 32]; event[0] = ffi::CLIENT_MESSAGE; event[1] = 32; event[4..8].copy_from_slice(&xid.to_ne_bytes()); event[8..12].copy_from_slice(&self.atoms.net_wm_state.to_ne_bytes()); event[12..16].copy_from_slice(&(if enabled { 1u32 } else { 0u32 }).to_ne_bytes()); event[16..20].copy_from_slice(&self.atoms.net_wm_state_above.to_ne_bytes());
        let error = unsafe { ffi::xcb_request_check(self.conn, ffi::xcb_send_event(self.conn, 0, self.root, ffi::SUBSTRUCTURE_REDIRECT | ffi::SUBSTRUCTURE_NOTIFY, event.as_ptr() as *const libc::c_char)) };
        if error.is_null() { Ok(()) } else { unsafe { libc::free(error as *mut _); } Err(BackendError::X11) }
    }

    fn request_activation(&self, xid: Xid) -> Result<(), BackendError> {
        let mut event = [0u8; 32]; event[0] = ffi::CLIENT_MESSAGE; event[1] = 32; event[4..8].copy_from_slice(&xid.to_ne_bytes()); event[8..12].copy_from_slice(&self.atoms.net_active_window.to_ne_bytes()); event[12..16].copy_from_slice(&2u32.to_ne_bytes());
        let error = unsafe { ffi::xcb_request_check(self.conn, ffi::xcb_send_event(self.conn, 0, self.root, ffi::SUBSTRUCTURE_REDIRECT | ffi::SUBSTRUCTURE_NOTIFY, event.as_ptr() as *const libc::c_char)) };
        if error.is_null() { Ok(()) } else { unsafe { libc::free(error as *mut _); } Err(BackendError::X11) }
    }

}
