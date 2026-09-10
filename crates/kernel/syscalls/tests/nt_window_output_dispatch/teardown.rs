//! Production destruction dispatch, with explicit display/resource publication seams.
use super::*;
static PUBLISHED: Mutex<Option<Vec<u64>>> = Mutex::new(None);

pub(super) fn publish(hwnd: u64) -> Result<(), ()> {
    assert!(nt_window::GUI.unlocked());
    let mut trace = PUBLISHED.lock().unwrap();
    if let Some(trace) = trace.as_mut() {
        assert!(nt_window::GUI.lock()[0].state.get(WindowId::from_raw(hwnd as u32).unwrap()).is_none());
        trace.push(hwnd);
    }
    Ok(())
}
pub(super) fn destroy_dc(hwnd: u32) {
    assert!(nt_window::GUI.unlocked());
    assert!(PUBLISHED.lock().unwrap().is_some(), "unexpected destruction");
    nt_gdi::GDI.lock()[0].state.destroy_window_dc(hwnd);
}

#[test]
fn actual_destroy_publishes_descendants_before_parent_after_canonical_revocation() {
    check(nt::NtService::DestroyWindow, 0);
}

#[test]
fn actual_default_close_publishes_descendants_before_parent() {
    check(nt::NtService::DefaultWindowProc, ipc::win32_window::WM_CLOSE as u64);
}

fn check(service: nt::NtService, message: u64) {
    let _serial = SERIAL.lock().unwrap(); setup();
    let (root, child, grandchild, sibling) = {
        let mut entries = nt_window::GUI.lock();
        let state = &mut entries[0].state;
        let root = WindowId::from_raw(nt_gdi::GDI.lock()[0].state.pending_outputs().unwrap()[0].hwnd).unwrap();
        let child = state.create(41, Some(root), 0).unwrap();
        let grandchild = state.create(41, Some(child), 0).unwrap();
        let sibling = state.create(41, Some(root), 0).unwrap();
        assert_eq!(state.destruction_order(root).unwrap(), [root, child, grandchild, sibling]);
        (root, child, grandchild, sibling)
    };
    *PUBLISHED.lock().unwrap() = Some(Vec::new());
    let result = nt_window::production::dispatch(NtCall { service,
        args: syscall::SyscallArgs { a0: root.raw() as u64, a1: message, a2: 0, a3: 0, a4: 0, a5: 0 } });
    let published = PUBLISHED.lock().unwrap().take().unwrap();
    assert_eq!(result, Some(0));
    assert_eq!(published.len(), 4);
    let at = |id: WindowId| published.iter().position(|hwnd| *hwnd == id.raw() as u64).unwrap();
    assert!(at(grandchild) < at(child), "display parent destruction already removes its children");
    assert!(at(child) < at(root));
    assert!(at(sibling) < at(root));
    for id in [root, child, grandchild, sibling] { assert!(nt_window::GUI.lock()[0].state.get(id).is_none()); }
}
