//! Production Get/Peek consumes the hardware driver's view and queue identity.
use super::*;
use ipc::win32_window::{WinMessage, WM_LBUTTONDOWN, hardware::make_point};
static PREPARED: Mutex<Option<(u64, WinMessage)>> = Mutex::new(None);
static EXPECTED_COPY: Mutex<Option<WinMessage>> = Mutex::new(None);
static COPIED: Mutex<Option<WinMessage>> = Mutex::new(None);
static DRAINED: Mutex<Option<u64>> = Mutex::new(None);
static COPY_FAIL: Mutex<bool> = Mutex::new(false);
pub(super) fn stage() -> nt_window::hardware::Stage {
    match PREPARED.lock().unwrap().take() {
        Some((id, message)) => nt_window::hardware::Stage::Prepared(Box::new(nt_window::hardware::Selected { id, message })),
        None => DRAINED.lock().unwrap().take().map_or(nt_window::hardware::Stage::Ready, nt_window::hardware::Stage::Drained),
    }
}
pub(super) fn copy(message: WinMessage) -> Result<(), syscall::Errno> {
    let expected = EXPECTED_COPY.lock().unwrap().take().expect("unexpected queued message copy");
    assert_eq!(message, expected);
    assert!(nt_window::GUI.unlocked(), "hardware usercopy holds GUI ownership");
    *COPIED.lock().unwrap() = Some(message);
    if *COPY_FAIL.lock().unwrap() { Err(syscall::Errno::Efault) } else { Ok(()) }
}
fn filter() -> MessageFilter { MessageFilter { hwnd: None, first: WM_LBUTTONDOWN, last: WM_LBUTTONDOWN } }
fn fixture() -> (u64, WinMessage, WinMessage) {
    setup();
    *COPY_FAIL.lock().unwrap() = false;
    *COPIED.lock().unwrap() = None;
    let mut entries = nt_window::GUI.lock();
    let state = &mut entries[0].state;
    let hwnd = state.siblings_top_first(None)[0];
    state.post_compositor_pointer(hwnd, 50, 50, 1, 0, 0).unwrap();
    let (id, raw, _) = state.inspect_for_thread(41, filter()).unwrap();
    let view = WinMessage { lparam: make_point(20, 10), ..raw };
    *PREPARED.lock().unwrap() = Some((id, view));
    *EXPECTED_COPY.lock().unwrap() = Some(view);
    (id, raw, view)
}
fn request(service: nt::NtService, remove: bool) -> NtCall {
    let mut request = call(service);
    request.args.a2 = WM_LBUTTONDOWN as u64;
    request.args.a3 = WM_LBUTTONDOWN as u64;
    request.args.a4 = u64::from(remove);
    request
}
#[test]
fn actual_peek_copies_prepared_view_and_preserves_raw_entry() {
    let _serial = SERIAL.lock().unwrap();
    let (id, raw, view) = fixture();
    assert_eq!(nt_window::production::dispatch(request(nt::NtService::PeekMessage, false)), Some(0));
    assert_eq!(*COPIED.lock().unwrap(), Some(view));
    assert_eq!(nt_window::GUI.lock()[0].state.read_selected_for_thread(41, id, false), Some(raw));
}
#[test]
fn actual_get_copies_prepared_view_and_retires_selected_entry() {
    let _serial = SERIAL.lock().unwrap();
    let (id, _, view) = fixture();
    assert_eq!(nt_window::production::dispatch(request(nt::NtService::GetMessage, true)), Some(0));
    assert_eq!(*COPIED.lock().unwrap(), Some(view));
    assert_eq!(nt_window::GUI.lock()[0].state.read_selected_for_thread(41, id, false), None);
}
#[test]
fn actual_removing_peek_keeps_raw_entry_when_usercopy_fails() {
    let _serial = SERIAL.lock().unwrap();
    let (id, raw, _) = fixture();
    *COPY_FAIL.lock().unwrap() = true;
    assert_eq!(nt_window::production::dispatch(request(nt::NtService::PeekMessage, true)), Some(nt_window::STATUS_INVALID_PARAMETER));
    assert_eq!(nt_window::GUI.lock()[0].state.read_selected_for_thread(41, id, false), Some(raw));
    *COPY_FAIL.lock().unwrap() = false;
}

fn drained_fixture() -> (u64, WinMessage) {
    let (id, raw, _) = fixture();
    *PREPARED.lock().unwrap() = None;
    *EXPECTED_COPY.lock().unwrap() = None;
    let mark = nt_window::GUI.lock()[0].state.inspect_retrieval_for_thread(41, filter(), id).unwrap_err();
    *DRAINED.lock().unwrap() = Some(mark);
    (id, raw)
}
#[test]
fn actual_peek_fallback_cannot_return_excluded_raw_hardware() {
    let _serial = SERIAL.lock().unwrap();
    let (id, raw) = drained_fixture();
    assert_eq!(nt_window::production::dispatch(request(nt::NtService::PeekMessage, false)), Some(nt_window::STATUS_NO_MORE_ENTRIES));
    assert_eq!(nt_window::GUI.lock()[0].state.read_selected_for_thread(41, id, false), Some(raw));
    assert!(COPIED.lock().unwrap().is_none());
}
#[test]
fn actual_get_wait_does_not_spin_on_excluded_raw_hardware() {
    let _serial = SERIAL.lock().unwrap();
    let (id, raw) = drained_fixture();
    assert_eq!(nt_window::production::dispatch(request(nt::NtService::GetMessage, true)), Some(nt_window::STATUS_ALERTED));
    assert!(EVENTS.lock().unwrap().contains(&"wait"));
    assert_eq!(nt_window::GUI.lock()[0].state.read_selected_for_thread(41, id, false), Some(raw));
}

#[test]
fn nonremoving_flags_preserve_selected_hardware_entry(){
    let _serial=SERIAL.lock().unwrap();
    for flags in [2u64,(ipc::win32_window::queue_status::QS_INPUT as u64)<<16]{
        let (id,raw,view)=fixture();let mut call=request(nt::NtService::PeekMessage,false);call.args.a4=flags;
        assert_eq!(nt_window::production::dispatch(call),Some(0));assert_eq!(*COPIED.lock().unwrap(),Some(view));
        assert_eq!(nt_window::GUI.lock()[0].state.read_selected_for_thread(41,id,false),Some(raw));
    }
}
