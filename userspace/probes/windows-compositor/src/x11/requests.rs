//! Completion of one submitted batch; checked errors never become successful frame ACKs.
use super::BackendError;
use crate::ffi;

/// # C: O(requests) plus batch synchronization; every checked error is consumed.
pub(crate) fn finish(conn: *mut ffi::Connection, hwnd: u32, cookies: Vec<ffi::VoidCookie>) -> Result<(), BackendError> {
    let mut failed = false;
    // Checking the last request first synchronizes the batch once. Earlier
    // results are then available without waiting after each image tile.
    for cookie in cookies.into_iter().rev() {
        let sequence = cookie.sequence;
        // SAFETY: caller retains its live connection and supplies only cookies
        // returned by checked requests issued on that connection in this batch.
        let error = unsafe { ffi::xcb_request_check(conn, cookie) };
        if error.is_null() { continue; }
        // SAFETY: request_check returned an allocated generic error, whose
        // fields remain live until the matching free below this diagnostic.
        unsafe {
            eprintln!("windows-compositor: draw-refused hwnd={hwnd:#x} sequence={sequence} resource={:#x} error={} major={} minor={}",
                (*error).resource_id, (*error).error_code, (*error).major_code, (*error).minor_code);
            libc::free(error.cast());
        }
        failed = true;
    }
    // SAFETY: the same caller-owned connection remains live through completion.
    if failed || unsafe { ffi::xcb_connection_has_error(conn) } != 0 { Err(BackendError::X11) } else { Ok(()) }
}
