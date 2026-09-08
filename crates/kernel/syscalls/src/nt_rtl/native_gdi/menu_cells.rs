//! The advances of the menu face, fetched once from the font backend and kept
//! in kernel state.
//!
//! Menu measurement runs inside the message that needs the number - a
//! nonclient calculation, or the plan a nonclient paint walks - and the
//! backend is only reachable through a callback that returns after that
//! message has answered. The face is therefore measured once here, on the
//! first bar paint, and every later measurement sums the stored advances
//! without leaving the kernel. Until the answer lands the layout measures on
//! the face's published average advance.
use sync::{Spinlock, TaskList};
use syscall::nt_native_gdi as abi;

/// The window whose bar asked for the measurement. Its bar was laid out on
/// the estimate, so it is redrawn once the real advances land. One window,
/// because one face is measured once.
static ASKED: Spinlock<Option<u64>, TaskList> = Spinlock::new(None);

/// Name the window whose bar is waiting on this measurement. # C: O(1)
pub(crate) fn note_asked(hwnd: u64) { *ASKED.lock() = Some(hwnd); }

/// Ask the font backend for the advances of one face. The answer is written
/// into kernel state by the query completion, not into any caller buffer.
/// `None` means no redirect was installed, so nothing will answer.
/// # C: O(1), fixed answer
pub(crate) fn begin_menu_cells(font: ipc::win32_gdi::Font) -> Option<u64> {
    let request = abi::QueryRequest { version: abi::VERSION, size: core::mem::size_of::<abi::QueryRequest>() as u32,
        dc: 0, kind: abi::QUERY_MENU_CELLS, flags: 0, height: font.height, width: font.width,
        weight: font.weight, italic: font.italic as u32, first: 0, count: 0, input: 0, output: 0,
        table: 0, offset: 0, capacity: abi::MENU_CELL_BYTES, reserved: 0, aux: 0, value: 0, aux_bytes: 0, reserved2: 0 };
    super::query::begin_query_checked(request)
}

/// Take one answer into the layout's own table. The face is the one the
/// request named, so an answer for a face nothing measures any more is kept
/// against that face and not against the live one. # C: O(N_cells)
pub(crate) fn publish(request: &abi::QueryRequest, bytes: &[u8]) -> bool {
    let font = ipc::win32_gdi::Font { height: request.height, width: request.width,
        weight: request.weight, italic: request.italic != 0 };
    let Some(cells) = ipc::win32_gdi::cells_from_answer(bytes) else { return false; };
    ipc::win32_gdi::publish_measured_cells(font, cells);
    // The bar that asked was drawn on the estimate; a frame redraw lays it
    // out again on the advances that just landed.
    if let Some(hwnd) = ASKED.lock().take() { let _ = crate::nt_window::draw_menu_bar_for_current(hwnd); }
    true
}
