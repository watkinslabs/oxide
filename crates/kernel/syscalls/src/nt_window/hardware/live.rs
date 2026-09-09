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
use alloc::boxed::Box;
use alloc::vec::IntoIter;
use ipc::win32_window::hardware::{self, ClickUpdate, Ladder, LadderStep, MouseOutcome, ProcCall};
use ipc::win32_window::{MessageFilter, WinMessage, WindowId};
use syscall::nt::{NtCall, NtWindowCall};

/// The ladder one thread has parked while a window procedure runs.
pub(crate) struct PendingLadder { id: u64, ladder: Ladder, prepared: WinMessage,
    /// The queued message was already taken off the queue, so the end of the
    /// ladder has nothing left to deliver or drop.
    dropped: bool }

/// The nonclient hit test of one pointer message, parked while the window
/// procedure answers it. Nothing about the message is decided until it does:
/// the answer picks the nonclient renumbering, the client translation, the
/// double-click eligibility and the filter the message is tested against.
pub(crate) struct HitProbe { id: u64, queued: WinMessage, window: WindowId, remove: bool, filter: MessageFilter,
    modal: bool, menu_mode: bool, time_ms: u32, double_click_ms: u32, candidates: IntoIter<WindowId>, answer: Option<Result<u64, ()>> }

/// What one thread has parked in the retrieval-time hardware stage.
pub(crate) enum PendingHardware {
    /// The `WM_NCHITTEST` send that has to answer before a pointer message
    /// can be prepared.
    HitTest { tid: u64, probe: HitProbe },
    /// The notify/activate/cursor ladder of a message already prepared.
    Ladder { tid: u64, state: PendingLadder },
}

impl PendingHardware {
    /// # C: O(1)
    fn tid(&self) -> u64 { match self { Self::HitTest { tid, .. } | Self::Ladder { tid, .. } => *tid } }
}

/// The transient handoff owns its payload below the general dispatcher frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Selected { pub id: u64, pub message: WinMessage }

/// What the retrieval does once the stage has had its turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    /// Nothing to process, or the message is ready: carry on into the queue.
    Ready,
    /// A translated retrieval view; the queue retains the raw event.
    Prepared(Box<Selected>),
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
    if parked.tid() == tid { return Some(parked); }
    let _ = with_entry(|entry| entry.hardware = Some(parked));
    None
}

/// # C: O(N_process_gui_states)
fn put(parked: PendingHardware) { let _ = with_entry(|entry| entry.hardware = Some(parked)); }

/// # C: O(N_process_gui_states)
fn record(result: Result<u64, ()>) {
    let Some(mut parked) = take() else { return; };
    match &mut parked {
        PendingHardware::HitTest { probe, .. } => probe.answer = Some(result),
        PendingHardware::Ladder { state, .. } => state.ladder.call_result(result),
    }
    put(parked);
}

/// Process the message at the front of this thread's queue before the
/// retrieval hands it over. # C: O(N_windows + N_sends); # Sleeps: yes
pub(crate) fn process_for_current(call: NtCall, raw: bool, operation: NtWindowCall) -> Stage {
    if let Some(parked) = take() { put(parked); return drive(call, raw); }
    match begin(operation) {
        Some(Stage::Pending(_)) => drive(call, raw),
        Some(stage) => stage,
        None => Stage::Ready,
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
        let (id, queued, hardware_origin) = entry.state.inspect_for_thread(tid, filter)?;
        if !hardware_origin { return None; }
        let window = queued.hwnd?;
        if !hardware::is_hardware_message(queued.message) { return None; }
        let menu_mode = entry.menu_tracking.is_some();
        let modal = menu_mode || entry.state.move_size_window().is_some();
        if hardware::is_keyboard_message(queued.message) {
            return Some(keyboard(entry, tid, id, window, queued, modal, remove, filter));
        }
        Some(pointer(entry, tid, id, window, queued, modal, menu_mode, remove, filter, time_ms, double_click_ms))
    })??;
    if let Some(parked) = parked { put(parked); }
    Some(stage)
}

/// A keyboard message makes at most one message of its own and is then handed
/// over unchanged apart from its generic virtual key. # C: O(N_windows)
fn keyboard(entry: &mut super::super::GuiEntry, tid: u64, id: u64, window: WindowId, queued: WinMessage, modal: bool,
    remove: bool, filter: MessageFilter) -> (Stage, Option<PendingHardware>) {
    let ctx = context::key_context(&entry.state, window, modal, remove, filter);
    let prepared = hardware::prepare_key(queued, &ctx);
    if prepared.outcome == hardware::KeyOutcome::Filtered {
        let _ = entry.state.read_selected_for_thread(tid, id, true);
        return (Stage::Again, None);
    }
    if let Some(extra) = prepared.extra {
        // A posted extra joins the queue behind the key it came from; a sent
        // one has to enter the window procedure, which only the ladder can do.
        if extra.post { post(entry, extra.call); }
        else { return (Stage::Pending(0), Some(sent_extra(tid, id, prepared.message, extra.call, false))); }
    }
    (prepared_view(entry, tid, id, prepared.message), None)
}

/// A pointer message is hit-tested before anything else: the reference sends
/// `WM_NCHITTEST` on the screen point the queue carries and decides the rest
/// from the answer. Only a window holding the capture skips the send, taking
/// the click as a client one. # C: O(N_windows)
fn pointer(entry: &mut super::super::GuiEntry, tid: u64, id: u64, window: WindowId, queued: WinMessage, modal: bool,
    menu_mode: bool, remove: bool, filter: MessageFilter, time_ms: u32, double_click_ms: u32) -> (Stage, Option<PendingHardware>) {
    let (x, y) = hardware::split_point(queued.lparam);
    let captured = entry.state.capture_window();
    let candidates = if captured.is_some() { alloc::vec::Vec::new() } else { entry.state.windows_in_scope(window, x, y) };
    let mut probe = HitProbe { id, queued, window, remove, filter, modal, menu_mode, time_ms, double_click_ms,
        candidates: candidates.into_iter(), answer: None };
    if let Some(capture) = captured {
        probe.window = capture;
        return decide(entry, tid, probe, ipc::win32_window::HTCLIENT);
    }
    next_candidate(entry, tid, probe)
}

/// Continue the snapshot in z-order after a transparent or destroyed candidate.
/// # C: O(N_candidates * N_windows)
fn next_candidate(entry: &mut super::super::GuiEntry, tid: u64, mut probe: HitProbe) -> (Stage, Option<PendingHardware>) {
    while let Some(window) = probe.candidates.next() {
        let Some(record) = entry.state.get(window) else { continue; };
        probe.window = window;
        probe.answer = None;
        if record.owner_tid != tid { break; }
        if record.style & ipc::win32_window::styles::WS_DISABLED != 0 {
            return decide(entry, tid, probe, ipc::win32_window::HTERROR);
        }
        return (Stage::Pending(0), Some(PendingHardware::HitTest { tid, probe }));
    }
    let _ = entry.state.read_selected_for_thread(tid, probe.id, true);
    (Stage::Again, None)
}

/// Prepare one pointer message against the hit-test code its window answered.
/// # C: O(N_windows + N_classes)
fn decide(entry: &mut super::super::GuiEntry, tid: u64, probe: HitProbe, hit_test: i32) -> (Stage, Option<PendingHardware>) {
    let HitProbe { id, queued, window, remove, filter, modal, menu_mode, time_ms, double_click_ms, .. } = probe;
    if entry.state.get(window).is_none_or(|record| record.owner_tid != tid) {
        let _ = entry.state.read_selected_for_thread(tid, id, true);
        return (Stage::Again, None);
    }
    super::trace::hit(id, queued, window, hit_test, remove);
    let ctx = context::mouse_context(&entry.state, window, hit_test, menu_mode, modal, time_ms, double_click_ms, remove, filter);
    let prepared = hardware::prepare_mouse(WinMessage { hwnd: Some(window), ..queued }, entry.last_click, &ctx);
    match prepared.click {
        ClickUpdate::Keep => {}
        ClickUpdate::Store(record) => entry.last_click = Some(record),
        ClickUpdate::Clear => entry.last_click = None,
    }
    match prepared.outcome {
        MouseOutcome::Filtered => { let _ = entry.state.read_selected_for_thread(tid, id, true); (Stage::Again, None) }
        MouseOutcome::ErrorCursor => {
            let call = ProcCall { hwnd: window.raw(), message: ipc::win32_window::WM_SETCURSOR, wparam: window.raw() as u64,
                lparam: hardware::make_hit_param(prepared.hit_test, prepared.origin) };
            let _ = entry.state.read_selected_for_thread(tid, id, true);
            (Stage::Pending(0), Some(sent_extra(tid, id, prepared.message, call, true)))
        }
        MouseOutcome::Deliver => (prepared_view(entry, tid, id, prepared.message), None),
        MouseOutcome::Ladder => {
            let Some(ladder) = context::ladder_context(&entry.state, &prepared.message, prepared.origin,
                prepared.hit_test, queued.lparam) else { return (Stage::Ready, None); };
            (Stage::Pending(0), Some(PendingHardware::Ladder { tid,
                state: PendingLadder { id, ladder: Ladder::new(ladder), prepared: prepared.message, dropped: false } }))
        }
    }
}

/// A ladder that exists only to make one call and then deliver, which is what
/// an error hit and a sent keyboard extra both are. # C: O(1)
fn sent_extra(tid: u64, id: u64, prepared: WinMessage, call: ProcCall, dropped: bool) -> PendingHardware {
    PendingHardware::Ladder { tid, state: PendingLadder { id, ladder: Ladder::single(call), prepared, dropped } }
}

/// Return a translated view without overwriting the selected raw message.
/// # C: O(N_queued)
fn prepared_view(entry: &mut super::super::GuiEntry, tid: u64, id: u64, message: WinMessage) -> Stage {
    if entry.state.read_selected_for_thread(tid, id, false).is_none() { return Stage::Again; }
    super::trace::prepared(id, message);
    Stage::Prepared(Box::new(Selected { id, message }))
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
        let Some(parked) = take() else { return Stage::Ready; };
        let (tid, mut state) = match parked {
            PendingHardware::HitTest { tid, probe } => {
                match probe.answer {
                    // The window procedure has not been entered yet.
                    None => {
                        let Some(proc_call) = hardware::hit_test_call(probe.window.raw(), probe.queued.lparam, false) else { return Stage::Ready; };
                        put(PendingHardware::HitTest { tid, probe });
                        if let Some(pending) = enter(proc_call, call, raw) { return Stage::Pending(pending); }
                        continue;
                    }
                    Some(result) => {
                        let hit = context::hit_code(result);
                        if hit == ipc::win32_window::HTTRANSPARENT {
                            super::trace::hit(probe.id, probe.queued, probe.window, hit, probe.remove);
                        }
                        let Some((stage, parked)) = with_entry(|entry| {
                            if hit == ipc::win32_window::HTTRANSPARENT { next_candidate(entry, tid, probe) }
                            else { decide(entry, tid, probe, hit) }
                        }) else { return Stage::Ready; };
                        match parked { Some(parked) => put(parked), None => { let _ = with_entry(|entry| entry.hardware = None); return stage; } }
                        continue;
                    }
                }
            }
            PendingHardware::Ladder { tid, state } => (tid, state),
        };
        let step = state.ladder.next();
        match step {
            LadderStep::Done { eat } => return finish(state, eat),
            LadderStep::Send(proc_call) => { put(PendingHardware::Ladder { tid, state }); if let Some(pending) = enter(proc_call, call, raw) { return Stage::Pending(pending); } }
            LadderStep::Activate(root) => {
                let activated = activate(root);
                put(PendingHardware::Ladder { tid, state });
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
fn finish(parked: PendingLadder, eat: bool) -> Stage {
    let Some(tid) = current_tid() else { return Stage::Ready; };
    let PendingLadder { id, prepared, dropped, .. } = parked;
    let _ = with_entry(|entry| entry.hardware = None);
    if dropped { return Stage::Again; }
    let stage = with_entry(|entry| {
        if eat { let _ = entry.state.read_selected_for_thread(tid, id, true); return Stage::Again; }
        prepared_view(entry, tid, id, prepared)
    });
    stage.unwrap_or(Stage::Ready)
}

/// Drop a parked ladder whose thread is gone. # C: O(1)
pub(crate) fn cancel_thread(entry: &mut super::super::GuiEntry, tid: u64) {
    if entry.hardware.as_ref().is_some_and(|parked| parked.tid() == tid) { entry.hardware = None; }
}
