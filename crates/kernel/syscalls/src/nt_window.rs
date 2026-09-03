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
const STATUS_PENDING: u64 = 0x0000_0103;
const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
const WM_DESTROY: u64 = 0x0002;
const WM_NCDESTROY: u64 = 0x0082;

pub(crate) const CALLBACK_DESTROY: u64 = 1;
pub(crate) const CALLBACK_NCDESTROY: u64 = 2;

struct GuiEntry { group: Weak<sched::thread_group::ThreadGroup>, state: ipc::win32_window::WindowManager, wait: Arc<sched::live::WaitList>, foreground: bool }
static GUI: Spinlock<Vec<GuiEntry>, GuiLockClass> = Spinlock::new(Vec::new());

/// Resolve a visible window rectangle from the current NT process's canonical HWND state. # C: O(N_process_gui_states + N_windows)
pub fn window_rect_for_current(hwnd: u32) -> Option<(ipc::win32_window::WindowRect, bool)> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let window = ipc::win32_window::WindowId::from_raw(hwnd)?;
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    let state = &entries[index].state;
    let record = state.get(window)?;
    Some((state.rect(window)?, record.visible))
}

/// Route one accepted physical key transition to the desktop foreground NT window. # C: O(N_nt_processes + N_windows)
pub fn route_hardware_key(key: u16, pressed: bool, repeat: bool) -> bool {
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(entry) = entries.iter_mut().find(|entry| entry.foreground) else { return false; };
    match entry.state.post_focused_key(key, pressed, repeat) {
        Ok(()) => { entry.wait.wake_all(); true }
        Err(ipc::win32_window::WindowError::QueueFull) => {
            klog::kwarn!("nt input: foreground window queue full");
            true
        }
        Err(_) => false,
    }
}

/// Dispatch one GUI call against the current NT process. `None` means this is
/// not a window service and lets the main NT dispatcher continue its ladder.
/// # C: O(N_process_gui_states + N_windows + N_wakeups)
pub fn dispatch(call: NtCall) -> Option<u64> {
    let operation = nt::decode_window(call).ok()?;
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return Some(STATUS_INVALID_PARAMETER); }
    input::set_native_key_hook(Some(route_hardware_key));
    let group = Arc::clone(&cur.thread_group);
    loop {
        let (result, wake, sleep) = {
            let mut entries = GUI.lock();
            entries.retain(|entry| entry.group.upgrade().is_some());
            let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)));
            let index = index.unwrap_or_else(|| {
                entries.push(GuiEntry { group: Arc::downgrade(&group), state: ipc::win32_window::WindowManager::new(), wait: Arc::new(sched::live::WaitList::new()), foreground: false });
                entries.len() - 1
            });
            let wait = Arc::clone(&entries[index].wait);
            let state = &mut entries[index].state;
            state.expire_timers(timekeeper::monotonic_ns());
            match operation {
                NtWindowCall::DefaultProc { hwnd, message, wparam: _, lparam } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let rect = ipc::win32_window::WindowId::from_raw(hwnd as u32).and_then(|window| state.rect(window));
                    let result = match rect.map_or_else(|| ipc::win32_window::default_window_proc(message), |rect| ipc::win32_window::default_window_proc_for_rect(message, rect, lparam)) {
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
                    if let Some(record) = state.get(window) {
                        if record.wndproc != 0 {
                            let reserved = match state.begin_destroy(window) { Ok(value) => value, Err(_) => return Some(STATUS_INVALID_HANDLE) };
                            if !reserved { return Some(STATUS_SUCCESS); }
                            let callback = crate::nt_rtl::begin_wndproc_callback_with_completion(hwnd, WM_DESTROY, 0, 0, record.wndproc, sched::nt_callback::Completion { kind: CALLBACK_DESTROY, argument: hwnd });
                            if callback == STATUS_PENDING { return Some(callback); }
                            state.cancel_destroy(window);
                            if callback != STATUS_NOT_SUPPORTED { return Some(STATUS_INVALID_HANDLE); }
                        }
                    }
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
                    match state.take_for_thread(cur.tid as u64, filter) {
                        ipc::win32_window::QueueResult::Message(found) => {
                            if copy_message(message, found).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                            (Some(STATUS_SUCCESS), None, None)
                        }
                        ipc::win32_window::QueueResult::Quit(code) => {
                            if copy_message(message, ipc::win32_window::WinMessage { hwnd: None, message: ipc::win32_window::WM_QUIT, wparam: code as u64, lparam: 0 }).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                            (Some(0), None, None)
                        }
                        ipc::win32_window::QueueResult::Empty => (None, None, Some((wait, filter))),
                    }
                }
                NtWindowCall::PostQuit { code } => {
                    state.post_quit(cur.tid as u64, code);
                    (Some(STATUS_SUCCESS), Some(wait), None)
                }
                NtWindowCall::SetFocus { hwnd } => {
                    if hwnd > u32::MAX as u64 { return Some(STATUS_INVALID_HANDLE); }
                    let window = if hwnd == 0 { None } else {
                        let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return Some(STATUS_INVALID_HANDLE); };
                        Some(window)
                    };
                    let result = match state.set_focus(cur.tid as u64, window) {
                        Ok(previous) => previous.map_or(0, |value| value.raw() as u64),
                        Err(ipc::win32_window::WindowError::WrongThread) => STATUS_INVALID_PARAMETER,
                        Err(_) => STATUS_INVALID_HANDLE,
                    };
                    if result != STATUS_INVALID_HANDLE && result != STATUS_INVALID_PARAMETER {
                        for (entry_index, entry) in entries.iter_mut().enumerate() { entry.foreground = entry_index == index && window.is_some(); }
                    }
                    (Some(result), None, None)
                }
                NtWindowCall::InjectKey { key, pressed, repeat } => {
                    if pressed > 1 || repeat > 1 { return Some(STATUS_INVALID_PARAMETER); }
                    let result = match state.post_key(cur.tid as u64, key, pressed != 0, repeat != 0) {
                        Ok(()) => STATUS_SUCCESS,
                        Err(ipc::win32_window::WindowError::NoFocus) => STATUS_INVALID_HANDLE,
                        Err(ipc::win32_window::WindowError::WrongThread) => STATUS_INVALID_PARAMETER,
                        Err(ipc::win32_window::WindowError::QueueFull) => STATUS_QUOTA_EXCEEDED,
                        Err(_) => STATUS_INVALID_HANDLE,
                    };
                    (Some(result), Some(wait), None)
                }
                NtWindowCall::SetTimer { hwnd, id, timeout_ms, proc } => {
                    if hwnd > u32::MAX as u64 || id == 0 { return Some(STATUS_INVALID_PARAMETER); }
                    let window = if hwnd == 0 { None } else { Some(match ipc::win32_window::WindowId::from_raw(hwnd as u32) { Some(window) => window, None => return Some(STATUS_INVALID_HANDLE) }) };
                    let result = match state.set_timer(cur.tid as u64, window, id, timeout_ms, proc, timekeeper::monotonic_ns()) {
                        Ok(value) => value,
                        Err(_) => STATUS_INVALID_HANDLE,
                    };
                    (Some(result), None, None)
                }
                NtWindowCall::KillTimer { hwnd, id } => {
                    if hwnd > u32::MAX as u64 || id == 0 { return Some(STATUS_INVALID_PARAMETER); }
                    let window = if hwnd == 0 { None } else { Some(match ipc::win32_window::WindowId::from_raw(hwnd as u32) { Some(window) => window, None => return Some(STATUS_INVALID_HANDLE) }) };
                    (Some(state.kill_timer(window, id) as u64), None, None)
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
                NtWindowCall::SetRectValues { hwnd, left, top, right, bottom } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let value = ipc::win32_window::WindowRect { left, top, right, bottom };
                    (Some(match state.set_rect(window, value) { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }), None, None)
                }
                NtWindowCall::GetText { hwnd, text, count } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let Some(value) = state.text(window) else { return Some(STATUS_INVALID_HANDLE); };
                    let limit = count.saturating_sub(1) as usize;
                    let copied = value.len().min(limit);
                    for (index, unit) in value.iter().take(copied).enumerate() {
                        let bytes = unit.to_le_bytes();
                        let Some(address) = text.as_u64().checked_add(index as u64 * 2) else { return Some(STATUS_INVALID_PARAMETER); };
                        if uaccess::copy_to_user(address, &bytes).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                    }
                    if count != 0 {
                        let address = text.as_u64().checked_add(copied as u64 * 2).unwrap_or(0);
                        if address == 0 || uaccess::copy_to_user(address, &[0, 0]).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                    }
                    (Some(copied as u64), None, None)
                }
                NtWindowCall::SetText { hwnd, text } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let mut value = alloc::vec::Vec::new();
                    let mut terminated = false;
                    for index in 0..=u16::MAX as usize {
                        let Some(address) = text.as_u64().checked_add(index as u64 * 2) else { return Some(STATUS_INVALID_PARAMETER); };
                        let mut bytes = [0u8; 2];
                        if uaccess::copy_from_user(&mut bytes, address).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                        let unit = u16::from_le_bytes(bytes);
                        if unit == 0 { terminated = true; break; }
                        value.push(unit);
                    }
                    if !terminated || state.set_text(window, &value).is_err() { return Some(STATUS_INVALID_PARAMETER); }
                    (Some(STATUS_SUCCESS), None, None)
                }
                NtWindowCall::GetClientRect { hwnd, rect } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let Some(value) = state.client_rect(window) else { return Some(STATUS_INVALID_HANDLE); };
                    (Some(copy_rect(rect, value)), None, None)
                }
                NtWindowCall::GetParent { hwnd } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let Some(record) = state.get(window) else { return Some(STATUS_INVALID_HANDLE); };
                    (Some(record.parent.map(|parent| parent.raw() as u64).unwrap_or(0)), None, None)
                }
                NtWindowCall::Show { hwnd, command } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    (Some(match state.show(window, command != ipc::win32_window::SW_HIDE) { Ok(previous) => previous as u64, Err(_) => STATUS_INVALID_HANDLE }), None, None)
                }
                NtWindowCall::Invalidate { hwnd, rect } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let requested = rect.and_then(|pointer| read_rect(pointer));
                    if rect.is_some() && requested.is_none() { return Some(STATUS_INVALID_PARAMETER); }
                    (Some(match state.invalidate(window, requested) { Ok(()) => STATUS_SUCCESS, Err(_) => STATUS_INVALID_HANDLE }), None, None)
                }
                NtWindowCall::BeginPaint { hwnd, rect } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    let Ok(Some(value)) = state.begin_paint(window) else { return Some(STATUS_INVALID_HANDLE); };
                    (Some(copy_rect(rect, value)), None, None)
                }
                NtWindowCall::EndPaint { hwnd } => {
                    let Some(window) = valid_window(hwnd) else { return Some(STATUS_INVALID_HANDLE); };
                    (Some(if state.get(window).is_some() { STATUS_SUCCESS } else { STATUS_INVALID_HANDLE }), None, None)
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
                .and_then(|entry| {
                    entry.state.peek_for_thread(cur.tid as u64, filter, false)
                        .or_else(|| entry.state.quit_pending(cur.tid as u64).then_some(ipc::win32_window::WinMessage { hwnd: None, message: ipc::win32_window::WM_QUIT, wparam: 0, lparam: 0 }))
                }).is_some()
        }) };
        if outcome != sched::task::WaitOutcome::Ready { return Some(STATUS_ALERTED); }
    }
}

/// Complete the two-phase native destruction transaction after a Wine
/// callback returns. # C: O(N_process_gui_states + N_windows)
pub(crate) fn complete_callback(completion: sched::nt_callback::Completion) -> u64 {
    match completion.kind {
        CALLBACK_DESTROY => {
            let Some(wndproc) = window_wndproc_for_current(completion.argument) else { return STATUS_SUCCESS; };
            let result = crate::nt_rtl::begin_wndproc_callback_with_completion(completion.argument, WM_NCDESTROY, 0, 0, wndproc, sched::nt_callback::Completion { kind: CALLBACK_NCDESTROY, argument: completion.argument });
            if result == STATUS_PENDING { result } else { destroy_window_for_current(completion.argument); STATUS_SUCCESS }
        }
        CALLBACK_NCDESTROY => { destroy_window_for_current(completion.argument); STATUS_SUCCESS }
        _ => STATUS_INVALID_PARAMETER,
    }
}

#[cfg(target_os = "oxide-kernel")]
fn destroy_window_for_current(hwnd: u64) {
    let Some(cur) = sched::live::current() else { return; };
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    if let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) {
        let _ = entries[index].state.destroy(ipc::win32_window::WindowId::from_raw(hwnd as u32).unwrap());
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn destroy_window_for_current(_: u64) {}

fn copy_message(destination: syscall::UserPtr<NtWindowMessage>, message: ipc::win32_window::WinMessage) -> Result<(), syscall::Errno> {
    let mut bytes = [0u8; core::mem::size_of::<NtWindowMessage>()];
    bytes[0..8].copy_from_slice(&(message.hwnd.map(|hwnd| hwnd.raw() as u64).unwrap_or(0)).to_le_bytes());
    bytes[8..12].copy_from_slice(&message.message.to_le_bytes());
    bytes[16..24].copy_from_slice(&message.wparam.to_le_bytes());
    bytes[24..32].copy_from_slice(&(message.lparam as u64).to_le_bytes());
    uaccess::copy_to_user(destination.as_u64(), &bytes)
}

fn valid_window(hwnd: u64) -> Option<ipc::win32_window::WindowId> {
    (hwnd <= u32::MAX as u64).then(|| ipc::win32_window::WindowId::from_raw(hwnd as u32)).flatten()
}

fn copy_rect(destination: syscall::UserPtr<syscall::nt::NtWindowRect>, value: ipc::win32_window::WindowRect) -> u64 {
    let fields = [value.left.to_le_bytes(), value.top.to_le_bytes(), value.right.to_le_bytes(), value.bottom.to_le_bytes()];
    let mut bytes = [0u8; 16];
    for (index, field) in fields.iter().enumerate() { bytes[index * 4..index * 4 + 4].copy_from_slice(field); }
    if uaccess::copy_to_user(destination.as_u64(), &bytes).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn read_rect(source: syscall::UserPtr<syscall::nt::NtWindowRect>) -> Option<ipc::win32_window::WindowRect> {
    let mut bytes = [0u8; 16];
    uaccess::copy_from_user(&mut bytes, source.as_u64()).ok()?;
    let field = |index: usize| i32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap());
    Some(ipc::win32_window::WindowRect { left: field(0), top: field(1), right: field(2), bottom: field(3) })
}

/// Register one Wine class in the same process-scoped window owner used by
/// direct native window calls. # C: O(N_process_gui_states + N_classes)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn register_class_for_current(name: &[u16], wndproc: u64) -> Option<u64> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| {
            entries.push(GuiEntry { group: Arc::downgrade(&group), state: ipc::win32_window::WindowManager::new(), wait: Arc::new(sched::live::WaitList::new()), foreground: false });
            entries.len() - 1
        });
    entries[index].state.register_class(name, wndproc).ok().map(|atom| atom as u64)
}

/// Unregister one process-local Wine class through the canonical owner.
/// # C: O(N_process_gui_states + N_classes + N_windows)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn unregister_class_for_current(name: &[u16]) -> bool {
    let Some(cur) = sched::live::current() else { return false; };
    if !cur.is_nt_personality() { return false; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return false; };
    entries[index].state.unregister_class(name).is_ok()
}

/// Create a Wine window by resolving its registered class in the canonical
/// process window owner. # C: O(N_process_gui_states + N_classes + N_windows)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn create_class_window_for_current(name: &[u16], parent: u64) -> Option<u64> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() || parent > u32::MAX as u64 { return None; }
    let parent = if parent == 0 { None } else { Some(ipc::win32_window::WindowId::from_raw(parent as u32)?) };
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| {
            entries.push(GuiEntry { group: Arc::downgrade(&group), state: ipc::win32_window::WindowManager::new(), wait: Arc::new(sched::live::WaitList::new()), foreground: false });
            entries.len() - 1
        });
    entries[index].state.create_class(cur.tid as u64, parent, name).ok().map(|window| window.raw() as u64)
}

/// Create a Wine window after resolving an integer-resource class atom in the
/// canonical process window owner. # C: O(N_process_gui_states + N_classes + N_windows)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn create_class_window_by_atom_for_current(atom: u16, parent: u64) -> Option<u64> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() || parent > u32::MAX as u64 { return None; }
    let parent = if parent == 0 { None } else { Some(ipc::win32_window::WindowId::from_raw(parent as u32)?) };
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| {
            entries.push(GuiEntry { group: Arc::downgrade(&group), state: ipc::win32_window::WindowManager::new(), wait: Arc::new(sched::live::WaitList::new()), foreground: false });
            entries.len() - 1
        });
    let wndproc = entries[index].state.class_wndproc_by_atom(atom)?;
    entries[index].state.create_class_atom(cur.tid as u64, parent, atom, wndproc).ok().map(|window| window.raw() as u64)
}

/// Read the registered class name associated with one canonical HWND.
/// # C: O(N_process_gui_states + N_windows + N_classes)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn window_class_name_for_current(hwnd: u64) -> Option<Vec<u16>> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return None; }
    let window = ipc::win32_window::WindowId::from_raw(hwnd as u32)?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    entries[index].state.class_name(window).map(|name| name.to_vec())
}

/// Resolve canonical class metadata for Wine's class-information query.
/// # C: O(N_process_gui_states + N_classes)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn class_info_for_current(name: &[u16]) -> Option<(u16, u64, Vec<u16>)> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    let (atom, wndproc, class_name) = entries[index].state.class_info(name)?;
    Some((atom, wndproc, class_name.to_vec()))
}

/// Resolve canonical class metadata for an integer-resource class atom.
/// # C: O(N_process_gui_states + N_classes)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn class_info_by_atom_for_current(atom: u16) -> Option<(u16, u64, Vec<u16>)> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    let (atom, wndproc, class_name) = entries[index].state.class_info_by_atom(atom)?;
    Some((atom, wndproc, class_name.to_vec()))
}

/// Replace text while keeping the mutation inside the canonical window owner.
/// # C: O(N_process_gui_states + N_windows + N_text)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn set_window_text_for_current(hwnd: u64, text: &[u16]) -> Result<(), ()> {
    let cur = sched::live::current().ok_or(())?;
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return Err(()); }
    let window = ipc::win32_window::WindowId::from_raw(hwnd as u32).ok_or(())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))).ok_or(())?;
    entries[index].state.set_text(window, text).map_err(|_| ())
}

/// Return the canonical UTF-16 text length for one HWND. # C: O(N_process_gui_states + N_windows)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn window_text_length_for_current(hwnd: u64) -> Option<u64> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return None; }
    let window = ipc::win32_window::WindowId::from_raw(hwnd as u32)?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    Some(entries[index].state.text(window)?.len() as u64)
}

/// Resolve the WndProc stored in the current process's canonical HWND state.
/// # C: O(N_process_gui_states + N_windows)
#[cfg(target_os = "oxide-kernel")]
pub(crate) fn window_wndproc_for_current(hwnd: u64) -> Option<u64> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() || hwnd > u32::MAX as u64 { return None; }
    let group = Arc::clone(&cur.thread_group);
    let window = ipc::win32_window::WindowId::from_raw(hwnd as u32)?;
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    entries[index].state.get(window).map(|record| record.wndproc)
}
