//! Canonical caret snapshots use the existing bounded compositor connection.
use syscall::nt_compositor::{caret::Snapshot,Opcode};
/// Submit one caret snapshot to the desktop. A caret move is a drawing
/// operation, not a transaction: the reference draws the caret into the
/// window's own device context and returns, leaving presentation to the frames
/// that follow. Waiting here for the desktop to acknowledge each snapshot put
/// a desktop round trip between the application and its next message - the
/// edit control moves the caret once per typed character, which cost the pump
/// over a hundred milliseconds per keystroke.
/// # C: O(mask pixels); # Sleeps: no; no GUI/GDI locks may be held
pub(crate) fn publish_current(hwnd:u64,snapshot:&Snapshot)->bool{
    let Ok(payload)=snapshot.encode()else{return false;};
    super::submit_current(Opcode::Caret,hwnd,payload).is_ok()
}
