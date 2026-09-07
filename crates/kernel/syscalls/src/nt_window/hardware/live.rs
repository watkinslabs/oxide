//! Drive the retrieval-time hardware ladder one step at a time.
//!
//! The ladder cannot run to completion on one kernel stack: every call it
//! makes enters a window procedure, which arms a client callback and unwinds
//! the syscall. So the position lives in the process GUI entry, the driver
//! suspends at each call, and the callback's return resumes the whole
//! retrieval, which finds the parked ladder and carries on.
use super::context;
use super::super::{GUI, STATUS_PENDING};
use super::super::send::{self, Continuation, SendOutcome};
use alloc::sync::Arc;
use ipc::win32_window::hardware::{self, ClickUpdate, Ladder, LadderStep, MouseOutcome, ProcCall};
use ipc::win32_window::{MessageFilter, WinMessage, WindowId};
use syscall::nt::{NtCall, NtWindowCall};

/// The ladder one thread has parked while a window procedure runs.
pub(crate) struct PendingHardware { pub(crate) tid: u64, ladder: Ladder, prepared: WinMessage, queued: WinMessage,
    /// The queued message was already taken off the queue, so the end of the
    /// ladder has nothing left to deliver or drop.
    dropped: bool }

/// What the retrieval does once the stage has had its turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    /// Nothing to process, or the message is ready: carry on into the queue.
    Ready,
    /// The message was consumed here; retrieve again.
    Again,
    /// The stage suspended in a window procedure; report this status.
    Pending(u64),
}

fn current_tid() -> Option<u64> { sched::live::current().filter(|task| task.is_nt_personality()).map(|task| task.tid as u64) }

fn with_entry<R>(f: impl FnOnce(&mut super::super::GuiEntry) -> R) -> Option<R> {
    let cur = sched::live::current()?;
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    Some(f(entry))
}

/// Take the calling thread's parked ladder; exactly one driver owns it.
/// # C: O(N_process_gui_states)
fn take() -> Option<PendingHardware> {
    let tid = current_tid()?;
    let parked = with_entry(|entry| entry.hardware.take()).flatten()?;
    if parked.tid == tid { return Some(parked); }
    let _ = with_entry(|entry| entry.hardware = Some(parked));
    None
}

/// # C: O(N_process_gui_states)
fn put(parked: PendingHardware) { let _ = with_entry(|entry| entry.hardware = Some(parked)); }

/// # C: O(N_process_gui_states)
fn record(result: Result<u64, ()>) {
    let Some(mut parked) = take() else { return; };
    parked.ladder.call_result(result);
    put(parked);
}

/// The removal filter naming exactly the message the stage worked on, so a
/// drop never takes a different one. # C: O(1)
fn exact(message: WinMessage) -> MessageFilter {
    MessageFilter { hwnd: message.hwnd, first: message.message, last: message.message }
}

/// Process the message at the front of this thread's queue before the
/// retrieval hands it over. # C: O(N_windows + N_sends); # Sleeps: yes
pub(crate) fn process_for_current(call: NtCall, raw: bool, operation: NtWindowCall) -> Stage {
    if take().is_some_and(|parked| { put(parked); true }) { return drive(call, raw); }
    match begin(operation) {
        Some(Stage::Ready) | None => Stage::Ready,
        Some(Stage::Again) => Stage::Again,
        Some(Stage::Pending(_)) => drive(call, raw),
    }
}

/// Prepare the front hardware message and park a ladder if it needs one.
/// `Pending` here means the ladder was parked, not that anything suspended.
/// # C: O(N_windows + N_classes)
fn begin(operation: NtWindowCall) -> Option<Stage> {
    let (hwnd, first, last, remove) = match operation {
        NtWindowCall::Peek { hwnd, first, last, remove, .. } => (hwnd, first, last, remove != 0),
        NtWindowCall::Get { hwnd, first, last, .. } => (hwnd, first, last, true),
        _ => return None,
    };
    let tid = current_tid()?;
    let time_ms = (timekeeper::monotonic_ns() / 1_000_000) as u32;
    // Read outside the GUI lock: the settings owner is a sibling lock of the
    // same class, and no path may hold one while taking the other.
    let double_click_ms = super::super::USER_SETTINGS.lock().double_click_ms();
    let (stage, parked) = with_entry(|entry| {
        let filter = super::super::message_filter(&entry.state, hwnd, first, last)?;
        let queued = entry.state.peek_for_thread(tid, filter, false)?;
        let window = queued.hwnd?;
        if !hardware::is_hardware_message(queued.message) { return None; }
        let modal = entry.menu_tracking.is_some() || entry.state.move_size_window().is_some();
        if hardware::is_keyboard_message(queued.message) {
            return Some(keyboard(entry, tid, window, queued, modal, remove, filter));
        }
        Some(pointer(entry, tid, window, queued, modal, remove, filter, time_ms, double_click_ms))
    })??;
    if let Some(parked) = parked { put(parked); }
    Some(stage)
}

/// A keyboard message makes at most one message of its own and is then handed
/// over unchanged apart from its generic virtual key. # C: O(N_windows)
fn keyboard(entry: &mut super::super::GuiEntry, tid: u64, window: WindowId, queued: WinMessage, modal: bool,
    remove: bool, filter: MessageFilter) -> (Stage, Option<PendingHardware>) {
    let ctx = context::key_context(&entry.state, window, modal, remove, filter);
    let prepared = hardware::prepare_key(queued, &ctx);
    if prepared.outcome == hardware::KeyOutcome::Filtered {
        let _ = entry.state.peek_for_thread(tid, exact(queued), true);
        return (Stage::Again, None);
    }
    if let Some(extra) = prepared.extra {
        // A posted extra joins the queue behind the key it came from; a sent
        // one has to enter the window procedure, which only the ladder can do.
        if extra.post { post(entry, extra.call); }
        else { return (Stage::Pending(0), Some(sent_extra(tid, queued, prepared.message, extra.call, false))); }
    }
    (replace(entry, tid, queued, prepared.message), None)
}

/// A pointer message runs the notify/activate/cursor ladder unless the
/// preparation already decided its fate. # C: O(N_windows + N_classes)
fn pointer(entry: &mut super::super::GuiEntry, tid: u64, window: WindowId, queued: WinMessage, modal: bool,
    remove: bool, filter: MessageFilter, time_ms: u32, double_click_ms: u32) -> (Stage, Option<PendingHardware>) {
    let ctx = context::mouse_context(&entry.state, window, queued.lparam, modal, time_ms, double_click_ms, remove, filter);
    let prepared = hardware::prepare_mouse(queued, entry.last_click, &ctx);
    match prepared.click {
        ClickUpdate::Keep => {}
        ClickUpdate::Store(record) => entry.last_click = Some(record),
        ClickUpdate::Clear => entry.last_click = None,
    }
    match prepared.outcome {
        MouseOutcome::Filtered => { let _ = entry.state.peek_for_thread(tid, exact(queued), true); (Stage::Again, None) }
        MouseOutcome::ErrorCursor => {
            let call = ProcCall { hwnd: window.raw(), message: ipc::win32_window::WM_SETCURSOR, wparam: window.raw() as u64,
                lparam: hardware::make_hit_param(prepared.hit_test, prepared.origin) };
            let _ = entry.state.peek_for_thread(tid, exact(queued), true);
            (Stage::Pending(0), Some(sent_extra(tid, queued, prepared.message, call, true)))
        }
        MouseOutcome::Deliver => (replace(entry, tid, queued, prepared.message), None),
        MouseOutcome::Ladder => {
            let Some(ladder) = context::ladder_context(&entry.state, &prepared.message, prepared.origin,
                prepared.hit_test, queued.lparam) else { return (Stage::Ready, None); };
            (Stage::Pending(0), Some(PendingHardware { tid, ladder: Ladder::new(ladder), prepared: prepared.message, queued, dropped: false }))
        }
    }
}

/// A ladder that exists only to make one call and then deliver, which is what
/// an error hit and a sent keyboard extra both are. # C: O(1)
fn sent_extra(tid: u64, queued: WinMessage, prepared: WinMessage, call: ProcCall, dropped: bool) -> PendingHardware {
    PendingHardware { tid, ladder: Ladder::single(call), prepared, queued, dropped }
}

/// Put the prepared form of the message back where the queued one was, so the
/// canonical queue is the only place a retrieval reads from. # C: O(N_queued)
fn replace(entry: &mut super::super::GuiEntry, tid: u64, queued: WinMessage, prepared: WinMessage) -> Stage {
    if prepared != queued { let _ = entry.state.replace_for_thread(tid, exact(queued), prepared); }
    Stage::Ready
}

/// # C: O(N_queued)
fn post(entry: &mut super::super::GuiEntry, call: ProcCall) {
    let Some(window) = WindowId::from_raw(call.hwnd) else { return; };
    let _ = entry.state.post_to_window(window, WinMessage { hwnd: Some(window), message: call.message,
        wparam: call.wparam, lparam: call.lparam });
}

/// Perform ladder steps until one suspends in a window procedure or the
/// ladder ends. # C: O(N_steps * (N_windows + N_sends)); # Sleeps: yes
fn drive(call: NtCall, raw: bool) -> Stage {
    loop {
        let Some(mut parked) = take() else { return Stage::Ready; };
        let step = parked.ladder.next();
        match step {
            LadderStep::Done { eat } => return finish(parked, eat),
            LadderStep::Send(proc_call) => { put(parked); if let Some(pending) = enter(proc_call, call, raw) { return Stage::Pending(pending); } }
            LadderStep::Activate(root) => {
                let activated = activate(root);
                put(parked);
                record(Ok(activated as u64));
            }
        }
    }
}

/// Make one window the foreground window, which is what an accepted
/// `WM_MOUSEACTIVATE` asks for. # C: O(N_windows + N_queued)
fn activate(root: u32) -> bool {
    let Some(window) = WindowId::from_raw(root) else { return false; };
    let Some((activated, wait)) = with_entry(|entry| {
        let activated = entry.state.compositor_focus(window, true).is_ok();
        if activated { entry.foreground = true; }
        (activated, Arc::clone(&entry.wait))
    }) else { return false; };
    wait.wake_all();
    activated
}

/// Enter one window procedure. A suspended call unwinds this syscall, and the
/// callback's return resumes the whole retrieval. # C: O(N_sends + N_windows); # Sleeps: yes
fn enter(proc_call: ProcCall, call: NtCall, raw: bool) -> Option<u64> {
    let Some(tid) = current_tid() else { record(Err(())); return None; };
    if !super::super::retrieval::save(call, raw) { record(Err(())); return None; }
    match send::send_resumable_current(proc_call.hwnd as u64, proc_call.message, proc_call.wparam,
        proc_call.lparam as u64, Continuation { token: tid, resume }) {
        SendOutcome::Pending => Some(STATUS_PENDING),
        SendOutcome::Complete(value) => { let _ = super::super::retrieval::drop_saved(); record(Ok(value)); None }
        SendOutcome::Failed => { let _ = super::super::retrieval::drop_saved(); record(Err(())); None }
    }
}

/// Resume the retrieval the ladder interrupted. The parked ladder carries the
/// position, so the queue is not consulted a second time. # C: O(N_steps); # Sleeps: yes
fn resume(token: u64, result: Result<u64, ()>) -> u64 {
    if current_tid() != Some(token) { return 0; }
    record(result);
    super::super::resume_position_message_current()
}

/// Retire the ladder and say what the retrieval does with the message.
/// # C: O(N_queued)
fn finish(parked: PendingHardware, eat: bool) -> Stage {
    let Some(tid) = current_tid() else { return Stage::Ready; };
    let PendingHardware { queued, prepared, dropped, .. } = parked;
    let _ = with_entry(|entry| entry.hardware = None);
    if dropped { return Stage::Again; }
    let stage = with_entry(|entry| {
        if eat { let _ = entry.state.peek_for_thread(tid, exact(queued), true); return Stage::Again; }
        replace(entry, tid, queued, prepared)
    });
    stage.unwrap_or(Stage::Ready)
}

/// Drop a parked ladder whose thread is gone. # C: O(1)
pub(crate) fn cancel_thread(entry: &mut super::super::GuiEntry, tid: u64) {
    if entry.hardware.as_ref().is_some_and(|parked| parked.tid == tid) { entry.hardware = None; }
}
