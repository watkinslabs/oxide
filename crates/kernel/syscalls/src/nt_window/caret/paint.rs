// Balanced caret visibility around the canonical BeginPaint/EndPaint owner.

use super::{live, publish};

/// Hide the current queue caret before paint work begins.
/// # C: O(GUI entries + caret publication)
pub(crate) fn begin_for_current(hwnd: u64) -> bool {
    let mut sink = publish::Current;
    live::hide_caret_for_current(hwnd, &mut sink) != 0
}

/// Restore the current queue caret after the matching paint session ends.
/// # C: O(GUI entries + caret publication)
pub(crate) fn end_for_current(hwnd: u64) -> bool {
    let mut sink = publish::Current;
    live::show_caret_for_current(hwnd, &mut sink) != 0
}
