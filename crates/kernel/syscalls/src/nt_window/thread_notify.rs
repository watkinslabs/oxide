//! The two thread-lifetime notifications the client makes as its GUI thread
//! retires, and the display-mode notification the desktop window receives.
use super::*;

/// Announce that the calling thread is exiting. From here until its teardown
/// no send is admitted for it, so a thread past its last message pump is never
/// handed work it cannot run. # C: O(N_processes)
pub(crate) fn mark_exiting_thread_for_current() {
    let Some(cur) = sched::live::current().filter(|task| task.is_nt_personality()) else { return; };
    let group = Arc::downgrade(&cur.thread_group);
    let mut entries = GUI.lock();
    let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&group)) else { return; };
    entry.sent.mark_exiting(cur.tid as u64);
}

/// Tear the calling thread's GUI state down: its windows, timers, queue,
/// pending work and input contexts, the same teardown scheduler retirement
/// performs. # C: O(windows³ + pending requests); # Sleeps: yes
pub(crate) fn thread_detach_for_current() {
    let Some(cur) = sched::live::current().filter(|task| task.is_nt_personality()) else { return; };
    teardown::cleanup_thread_at_exit(&cur);
}

/// Tell the desktop window the display mode changed. # C: O(1); # Sleeps: yes
pub(crate) fn send_display_change(desktop: u64, message: u32, wparam: u64, lparam: i64) {
    let _ = send::send_for_current(desktop, message, wparam, lparam as u64);
}
