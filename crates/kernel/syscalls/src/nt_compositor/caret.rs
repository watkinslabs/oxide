//! Canonical caret snapshots use the existing bounded compositor connection.
use syscall::nt_compositor::{caret::Snapshot,Opcode};
const ACK_TIMEOUT_NS:u64=5_000_000_000;
/// Caller resolves canonical owner, frame coordinates and real XOR mask before unlocking GUI/GDI.
/// # C: O(mask pixels); # Sleeps: yes; no GUI/GDI locks may be held
pub(crate) fn publish_current(hwnd:u64,snapshot:&Snapshot)->bool{
    let Ok(payload)=snapshot.encode()else{return false;};
    let Ok(sequence)=super::enqueue_current(Opcode::Caret,hwnd,payload)else{return false;};
    matches!(super::wait_completion_current(sequence,ACK_TIMEOUT_NS),Ok(super::Completion::Presented))
}
