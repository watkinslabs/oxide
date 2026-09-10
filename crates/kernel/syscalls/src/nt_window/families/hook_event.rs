//! Client WinEvent callback record; client owns module resolution and lifetime.
use alloc::vec::Vec;
use ipc::win32_hook::Hook;

/// Client callback-table ordinal for accessibility hook delivery.
const CALL_WIN_EVENT_HOOK: u32 = 3;
/// Fixed AMD64 callback record offsets; path includes a terminating UTF-16 zero.
const EVENT: usize = 0;
const HWND: usize = 8;
const OBJECT: usize = 16;
const CHILD: usize = 20;
const HANDLE: usize = 24;
const THREAD: usize = 32;
const TIME: usize = 36;
const PROC: usize = 40;
const MODULE: usize = 48;
const MAX_PATH_UNITS: usize = 260;

#[derive(Clone, Copy)]
pub(super) struct Notification {
    pub event: u32, pub hwnd: u64, pub object_id: i32, pub child_id: i32,
    pub thread: u32, pub time: u32,
}

/// Pass the relative procedure and module together; the client resolves them.
/// # C: O(module path); # Sleeps: usercopy
pub(super) fn begin(hook: &Hook, event: Notification, completion: sched::nt_callback::Completion) -> u64 {
    let length = hook.module.iter().position(|unit| *unit == 0).unwrap_or(hook.module.len()).min(MAX_PATH_UNITS - 1);
    let size = MODULE + (length + 1) * 2;
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(size).is_err() { return 0; }
    bytes.resize(size, 0);
    bytes[EVENT..EVENT + 4].copy_from_slice(&event.event.to_le_bytes());
    bytes[HWND..HWND + 8].copy_from_slice(&event.hwnd.to_le_bytes());
    bytes[OBJECT..OBJECT + 4].copy_from_slice(&event.object_id.to_le_bytes());
    bytes[CHILD..CHILD + 4].copy_from_slice(&event.child_id.to_le_bytes());
    bytes[HANDLE..HANDLE + 8].copy_from_slice(&(hook.handle as u64).to_le_bytes());
    bytes[THREAD..THREAD + 4].copy_from_slice(&event.thread.to_le_bytes());
    bytes[TIME..TIME + 4].copy_from_slice(&event.time.to_le_bytes());
    bytes[PROC..PROC + 8].copy_from_slice(&hook.proc_address.to_le_bytes());
    for (index, unit) in hook.module[..length].iter().enumerate() {
        let at = MODULE + index * 2;
        bytes[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
    crate::nt_rtl::begin_user_callback(CALL_WIN_EVENT_HOOK, crate::nt_user_callback::Input::Record(&bytes), completion)
}
