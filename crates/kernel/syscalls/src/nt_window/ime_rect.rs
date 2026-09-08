//! The IME composition rectangle a client publishes for its input window.
//!
//! The rectangle is stated in the window's client space and belongs to the
//! display driver, which positions the composition and candidate windows over
//! it. The compositor protocol carries no composition-rectangle opcode, so the
//! rectangle reaches no driver and the call answers FALSE — the same answer the
//! reference gives when the display driver has no entry point for it. The
//! window check still runs first: a word that names no window is refused before
//! any coordinate is looked at.
use super::*;

/// # C: O(N_processes + N_windows)
pub(crate) fn set_ime_composition_rect_for_current(hwnd: u64, left: i32, top: i32, right: i32, bottom: i32) -> bool {
    let _ = (left, top, right, bottom);
    if valid_window(hwnd).is_none() { return false; }
    false
}
