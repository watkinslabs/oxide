use super::*;

const TID: u64 = 5;
const LATER: u64 = HUNG_QUEUE_NS + 1;

fn manager() -> (WindowManager, WindowId) {
    let mut state = WindowManager::new();
    let window = state.create(TID, None, 0).unwrap();
    (state, window)
}

fn post(state: &mut WindowManager, window: WindowId) {
    state.post_to_window(window, WinMessage { hwnd: Some(window), message: WM_CLOSE, wparam: 0, lparam: 0 }).unwrap();
}

#[test]
fn an_idle_queue_is_never_hung_however_long_it_waits() {
    let (mut state, _) = manager();
    state.note_queue_access(TID, 0);
    assert!(!state.thread_hung(TID, LATER * 100));
}

#[test]
fn a_queue_with_work_is_hung_only_past_the_reference_window() {
    let (mut state, window) = manager();
    state.note_queue_access(TID, 0);
    post(&mut state, window);
    assert!(!state.thread_hung(TID, HUNG_QUEUE_NS));
    assert!(state.thread_hung(TID, LATER));
    assert!(state.window_hung(window, LATER));
}

#[test]
fn reading_the_queue_clears_the_hung_report() {
    let (mut state, window) = manager();
    post(&mut state, window);
    assert!(state.thread_hung(TID, LATER));
    state.note_queue_access(TID, LATER);
    assert!(!state.thread_hung(TID, LATER));
    assert!(state.thread_hung(TID, LATER + LATER));
}

#[test]
fn a_pending_quit_alone_counts_as_work() {
    let (mut state, _) = manager();
    state.note_queue_access(TID, 0);
    assert!(!state.thread_hung(TID, LATER));
    state.post_quit(TID, 0);
    assert!(state.thread_hung(TID, LATER));
}

#[test]
fn a_thread_with_no_queue_and_an_unknown_window_are_not_hung() {
    let (state, _) = manager();
    assert!(!state.thread_hung(TID + 1, LATER));
    assert!(!state.window_hung(WindowId::from_raw(9999).unwrap(), LATER));
}
