//! Live routing for the message-queue ordinals against the canonical
//! per-process window owner.
use super::super::*;
use crate::nt_wine_window::queue_raw::{self, pointer, startup, wait};
use ipc::win32_window::queue_status;
use super::wait_live::msg_wait;

/// The audible warning the message beep produces, in hertz and milliseconds.
const BEEP_HZ: u32 = 750;
const BEEP_MS: u32 = 125;
/// A posted message that carries pointers can only be sent, never posted.
const ERROR_MESSAGE_SYNC_ONLY: u32 = 1159;
/// A live window schedules a dispatch notification of this kind.
const DISPATCH_NOTIFICATION_SCHEDULED: u64 = 2;

/// Route one message-queue ordinal. # C: O(1) plus the arm's own cost
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    let arg = |index: usize| args.get(index).copied().unwrap_or(0);
    match ordinal {
        queue_raw::POST_QUIT_MESSAGE => Some(post_quit(arg(0) as i32)),
        queue_raw::POST_THREAD_MESSAGE => Some(post_thread(arg(0) as u32, arg(1) as u32, arg(2), arg(3))),
        queue_raw::REPLY_MESSAGE => Some(reply(arg(0))),
        queue_raw::MSG_WAIT_FOR_MULTIPLE_OBJECTS_EX =>
            Some(msg_wait(arg(0) as u32, arg(1), arg(2) as u32, arg(3) as u32) as u64),
        queue_raw::WAIT_MESSAGE =>
            Some(wait::wait_message_result(msg_wait(0, 0, wait::INFINITE, queue_status::QS_ALLINPUT))),
        queue_raw::SCHEDULE_DISPATCH_NOTIFICATION => Some(schedule_dispatch_notification(arg(0))),
        queue_raw::MESSAGE_BEEP => Some(message_beep()),
        queue_raw::MODIFY_USER_STARTUP_INFO_FLAGS => Some(modify_startup_info_flags(arg(0) as u32, arg(1) as u32)),
        queue_raw::SET_ADDITIONAL_FOREGROUND_BOOST_PROCESSES => Some(foreground_boost()),
        _ => None,
    }
}

pub(super) fn with_entry<R>(f: impl FnOnce(&mut GuiEntry, u64) -> R) -> Option<R> {
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality())?;
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))
        .unwrap_or_else(|| { entries.push(new_entry(&group)); entries.len() - 1 });
    Some(f(&mut entries[index], cur.tid as u64))
}

/// Wake the process wait list, which the window queue and the process NT
/// objects share, so a thread parked on either sees the new queue work.
/// # C: O(N_waiters)
fn wake_queue_waiters(wait_list: &Arc<sched::live::WaitList>) { wait_list.wake_all(); }

/// The quit request reports success, including for a thread owning no window.
/// # C: O(N_queues)
fn post_quit(code: i32) -> u64 {
    let Some(wait_list) = with_entry(|entry, tid| { entry.state.post_quit(tid, code); Arc::clone(&entry.wait) }) else { return 0; };
    wake_queue_waiters(&wait_list);
    1
}

/// A message whose parameters carry pointers cannot be marshalled into another
/// thread's queue; a thread that owns no queue takes no message. # C: O(N_queues)
fn post_thread(thread: u32, message: u32, wparam: u64, lparam: u64) -> u64 {
    if pointer::is_pointer_message(message, wparam) {
        crate::nt_rtl::set_last_win32_error(ERROR_MESSAGE_SYNC_ONLY as u64);
        return 0;
    }
    let posted = with_entry(|entry, _| {
        let queued = entry.state.post_to_thread(thread as u64,
            ipc::win32_window::WinMessage { hwnd: None, message, wparam, lparam: lparam as i64 }).is_ok();
        (queued, Arc::clone(&entry.wait))
    });
    let Some((queued, wait_list)) = posted else { return 0; };
    if queued { wake_queue_waiters(&wait_list); }
    queued as u64
}

/// Publish the result of the message this thread is receiving, before its
/// procedure returns. A thread receiving nothing has nothing to answer.
/// # C: O(N_sent)
fn reply(result: u64) -> u64 {
    let replied = with_entry(|entry, tid| (entry.sent.active_reply(tid), Arc::clone(&entry.wait)));
    let Some((Some(reply), wait_list)) = replied else { return 0; };
    reply.complete(result);
    wake_queue_waiters(&wait_list);
    1
}

/// A live window schedules a notification; an unknown one schedules none.
/// # C: O(N_windows)
fn schedule_dispatch_notification(hwnd: u64) -> u64 {
    let Some(window) = u32::try_from(hwnd).ok().and_then(ipc::win32_window::WindowId::from_raw) else { return 0; };
    let live = with_entry(|entry, _| entry.state.get(window).is_some()).unwrap_or(false);
    if live { DISPATCH_NOTIFICATION_SCHEDULED } else { 0 }
}

/// The warning is silent while the beep setting is off; the call reports
/// success either way. # C: O(1)
fn message_beep() -> u64 {
    if USER_SETTINGS.lock().beep_enabled() { let _ = sound::beep::beep(BEEP_HZ, BEEP_MS); }
    1
}

fn modify_startup_info_flags(mask: u32, flags: u32) -> u64 {
    let _ = with_entry(|entry, _| entry.startup_info_flags = startup::modify(entry.startup_info_flags, mask, flags));
    1
}

/// The foreground-boost list is not maintained, which the call reports. # C: O(1)
fn foreground_boost() -> u64 {
    crate::nt_rtl::set_last_win32_error(startup::ERROR_CALL_NOT_IMPLEMENTED as u64);
    0
}
