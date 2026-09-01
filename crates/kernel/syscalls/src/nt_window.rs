//! NT GUI adapter: process-scoped windows and thread message queues.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as GuiLockClass};
use syscall::nt::{self, NtCall, NtWindowCall, NtWindowMessage};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_001a;
const STATUS_QUOTA_EXCEEDED: u64 = 0xc000_0044;
const STATUS_ALERTED: u64 = 0x0000_0101;

struct GuiEntry { group: Weak<sched::thread_group::ThreadGroup>, state: ipc::win32_window::WindowManager, wait: Arc<sched::live::WaitList> }
static GUI: Spinlock<Vec<GuiEntry>, GuiLockClass> = Spinlock::new(Vec::new());

/// Dispatch one GUI call against the current NT process. `None` means this is
/// not a window service and lets the main NT dispatcher continue its ladder.
/// # C: O(N_process_gui_states + N_windows + N_wakeups)
pub fn dispatch(call: NtCall) -> Option<u64> {
    let operation = nt::decode_window(call).ok()?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    let group = Arc::clone(&cur.thread_group);
    loop {
        let (result, wake, sleep) = {
            let mut entries = GUI.lock();
            entries.retain(|entry| entry.group.upgrade().is_some());
            let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)));
            let index = index.unwrap_or_else(|| {
                entries.push(GuiEntry { group: Arc::downgrade(&group), state: ipc::win32_window::WindowManager::new(), wait: Arc::new(sched::live::WaitList::new()) });
                entries.len() - 1
            });
            let wait = Arc::clone(&entries[index].wait);
            let state = &mut entries[index].state;
            match operation {
                NtWindowCall::DefaultProc { hwnd, message, wparam: _, lparam: _ } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let result = match ipc::win32_window::default_window_proc(message) {
                        ipc::win32_window::DefaultWindowResult::Return(value) => value as u64,
                        ipc::win32_window::DefaultWindowResult::RequestDestroy => {
                            if hwnd != 0 {
                                let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                                if state.destroy(window).is_err() { return Some(STATUS_INVALID_HANDLE); }
                            }
                            STATUS_SUCCESS
                        }
                    };
                    (Some(result), None, None)
                }
                NtWindowCall::Create { parent, wndproc } => {
                    if parent > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let parent = if parent == 0 { None } else { match ipc::win32_window::WindowId::from_raw(parent as u32) { Some(parent) => Some(parent), None => return Some(STATUS_INVALID_HANDLE) } };
                    let result = match state.create(cur.tid as u64, parent, wndproc) { Ok(window) => window.raw() as u64, Err(_) => STATUS_INVALID_PARAMETER };
                    (Some(result), None, None)
                }
                NtWindowCall::Destroy { hwnd } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                    (Some(match state.destroy(window) { Ok(_) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }), None, None)
                }
                NtWindowCall::Post { hwnd, message, wparam, lparam } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                    let result = match state.post_to_window(window, ipc::win32_window::WinMessage { hwnd: Some(window), message, wparam, lparam }) { Ok(()) => STATUS_SUCCESS, Err(ipc::win32_window::WindowError::QueueFull) => STATUS_QUOTA_EXCEEDED, Err(_) => STATUS_INVALID_HANDLE };
                    (Some(result), Some(wait), None)
                }
                NtWindowCall::Peek { message, hwnd, first, last, remove } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let filter = ipc::win32_window::MessageFilter { hwnd: ipc::win32_window::WindowId::from_raw(hwnd as u32), first, last };
                    let Some(found) = state.peek_for_thread(cur.tid as u64, filter, false) else { return Some(STATUS_NO_MORE_ENTRIES); };
                    if copy_message(message, found).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                    if remove != 0 { let _ = state.peek_for_thread(cur.tid as u64, filter, true); }
                    (Some(STATUS_SUCCESS), None, None)
                }
                NtWindowCall::Get { message, hwnd, first, last } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let filter = ipc::win32_window::MessageFilter { hwnd: ipc::win32_window::WindowId::from_raw(hwnd as u32), first, last };
                    match state.peek_for_thread(cur.tid as u64, filter, false) {
                        Some(found) => {
                            if copy_message(message, found).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                            let _ = state.peek_for_thread(cur.tid as u64, filter, true);
                            (Some(STATUS_SUCCESS), None, None)
                        }
                        None => (None, None, Some((wait, filter))),
                    }
                }
                NtWindowCall::GetRect { hwnd, rect } => {
                    let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                    let Some(value) = state.rect(window) else { return Some(STATUS_INVALID_HANDLE); };
                    let native = [value.left.to_le_bytes(), value.top.to_le_bytes(), value.right.to_le_bytes(), value.bottom.to_le_bytes()];
                    let mut bytes = [0u8; 16];
                    for (index, field) in native.iter().enumerate() { bytes[index * 4..index * 4 + 4].copy_from_slice(field); }
                    if uaccess::copy_to_user(rect.as_u64(), &bytes).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                    (Some(STATUS_SUCCESS), None, None)
                }
                NtWindowCall::SetRect { hwnd, rect } => {
                    let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                    let mut bytes = [0u8; 16];
                    if uaccess::copy_from_user(&mut bytes, rect.as_u64()).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                    let field = |index: usize| i32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
                    let value = ipc::win32_window::WindowRect { left: field(0), top: field(1), right: field(2), bottom: field(3) };
                    (Some(match state.set_rect(window, value) { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }), None, None)
                }
            }
        };
        if let Some(wait) = wake { wait.wake_all(); }
        if let Some(result) = result { return Some(result); }
        let Some((wait, filter)) = sleep else { return Some(STATUS_NO_MORE_ENTRIES); };
        let outcome = unsafe { sched::live::wait_event_interruptible(&wait, || {
            let mut entries = GUI.lock();
            entries.retain(|entry| entry.group.upgrade().is_some());
            entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
                .and_then(|entry| entry.state.peek_for_thread(cur.tid as u64, filter, false)).is_some()
        }) };
        if outcome != sched::task::WaitOutcome::Ready { return Some(STATUS_ALERTED); }
    }
}

fn copy_message(destination: syscall::UserPtr<NtWindowMessage>, message: ipc::win32_window::WinMessage) -> Result<(), syscall::Errno> {
    let mut bytes = [0u8; core::mem::size_of::<NtWindowMessage>()];
    bytes[0..8].copy_from_slice(&(message.hwnd.map(|hwnd| hwnd.raw() as u64).unwrap_or(0)).to_le_bytes());
    bytes[8..12].copy_from_slice(&message.message.to_le_bytes());
    bytes[16..24].copy_from_slice(&message.wparam.to_le_bytes());
    bytes[24..32].copy_from_slice(&(message.lparam as u64).to_le_bytes());
    uaccess::copy_to_user(destination.as_u64(), &bytes)
}
