//! Raw keyboard queries join current identity to canonical GUI input state.
use alloc::sync::Arc;
const KEYBOARD_BYTES: usize = 256;

/// Raw SHORT result in low sixteen bits. # C: O(processes + queues)
pub(crate) fn get_key_state_current(key: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return 0; };
    if !cur.is_nt_personality() { return 0; }
    let entries = super::GUI.lock();
    let Some(entry) = entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return 0; };
    entry.state.key_state(cur.tid as u64, key as u32 as i32) as u16 as u64
}

/// Consumes the recent-press bit in the bound input owner. # C: O(processes)
pub(crate) fn get_async_key_state_current(key: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return 0; };
    if !cur.is_nt_personality() { return 0; }
    let mut entries = super::GUI.lock();
    let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return 0; };
    entry.state.async_key_state(key as u32 as i32) as u16 as u64
}

/// Copies an owned 256-byte snapshot after GUI unlock. # C: O(processes + queues + 256)
pub(crate) fn get_keyboard_state_current(destination: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return 0; };
    if !cur.is_nt_personality() { return 0; }
    let bytes = {
        let entries = super::GUI.lock();
        entries.iter().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
            .map_or([0; KEYBOARD_BYTES], |entry| entry.state.keyboard_state(cur.tid as u64))
    };
    uaccess::copy_to_user(destination, &bytes).is_ok() as u64
}

/// Validates user memory before mutation; thread override does not change physical state.
/// # C: O(processes + queues + 256)
pub(crate) fn set_keyboard_state_current(source: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return 0; };
    if !cur.is_nt_personality() { return 0; }
    let mut bytes = [0; KEYBOARD_BYTES];
    if uaccess::copy_from_user(&mut bytes, source).is_err() { return 0; }
    let mut entries = super::GUI.lock();
    let index = entries.iter().position(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))).unwrap_or_else(|| {
        entries.push(super::new_entry(&cur.thread_group));
        entries.len() - 1
    });
    entries[index].state.set_keyboard_state(cur.tid as u64, &bytes); 1
}
