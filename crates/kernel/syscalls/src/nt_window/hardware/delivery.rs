// Deliver a translated hardware view without extending the general dispatcher frame.
use super::super::{GUI, STATUS_SUCCESS, STATUS_INVALID_PARAMETER, copy_message};
use alloc::sync::Arc;
use ipc::win32_window::WinMessage;
use syscall::nt::{NtCall, NtWindowCall};
use super::Stage;

/// Usercopy runs outside GUI ownership; retirement names only the selected ID.
/// # C: O(N_process_gui_states + N_queued)
#[inline(never)]
pub(crate) fn deliver_for_current(operation: NtWindowCall, id: u64, view: WinMessage) -> Option<u64> {
    let (pointer, remove, get) = match operation {
        NtWindowCall::Peek { message, remove, .. } => (message, remove != 0, false),
        NtWindowCall::Get { message, .. } => (message, true, true),
        _ => return Some(STATUS_INVALID_PARAMETER),
    };
    let current = sched::live::current()?;
    {
        let mut entries = GUI.lock();
        let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))?;
        entry.state.note_queue_access(current.tid as u64, timekeeper::monotonic_ns());
        entry.state.read_selected_for_thread(current.tid as u64, id, get)?;
    }
    if get { note_get(view); }
    if copy_message(pointer, view).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    if remove && !get {
        let mut entries = GUI.lock();
        if let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group))) {
            let _ = entry.state.read_selected_for_thread(current.tid as u64, id, true);
        }
    }
    Some(STATUS_SUCCESS)
}

/// # C: O(1)
pub(crate) fn note_get(found: WinMessage) {
super::super::pump_profile::note_retrieval();
klog::write_raw(b"[WINDOWS-GETMESSAGE] hwnd=");
klog::write_hex_u64(found.hwnd.map(|w| w.raw() as u64).unwrap_or(0));
klog::write_raw(b" msg=");
klog::write_hex_u64(found.message as u64);
klog::write_raw(b"\n");
}

/// The general dispatcher carries no raw or translated message payload.
pub(crate) enum DispatchStage { Ready, Again, Complete(u64) }

/// Keep retrieval scratch below the general dispatcher's lifetime.
/// # C: O(N_process_gui_states + N_windows + N_queued)
#[inline(never)]
pub(crate) fn dispatch_for_current(call: NtCall, raw: bool, operation: NtWindowCall) -> DispatchStage {
    match super::process_for_current(call, raw, operation) {
        Stage::Ready => DispatchStage::Ready,
        Stage::Again => DispatchStage::Again,
        Stage::Pending(status) => DispatchStage::Complete(status),
        Stage::Prepared { id, message } => match deliver_for_current(operation, id, message) {
            Some(status) => DispatchStage::Complete(status),
            None => DispatchStage::Again,
        },
    }
}
