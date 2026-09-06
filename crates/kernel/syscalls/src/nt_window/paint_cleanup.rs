//! Window teardown drains owned preparation resources outside GUI ownership.
use super::*;

/// No callbacks execute while revoking an HWND; fresh HDC/HRGN identities cannot be reused. # C: O(processes * preparations)
pub(crate) fn window_for_current(hwnd: u64) {
    let Some(current) = sched::live::current().filter(|current| current.is_nt_personality()) else { return; };
    loop {
        let completion = {
            let mut entries = GUI.lock();
            entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&current.thread_group)))
                .and_then(|entry| { entry.paint_callbacks.cancel_window(hwnd); entry.paint_callbacks.take_window(hwnd) })
        };
        let Some(completion) = completion else { return; };
        paint_callbacks::dispose_for_current(completion);
    }
}
