use super::*;
use alloc::sync::Arc;
use super::super::{GUI, STATUS_PENDING, send};
const WM_PAINT: u32 = 0x000f;

/// Mutate canonical damage then execute synchronous paint when requested.
/// # C: O(windows traversal + callbacks); # Sleeps: yes
pub(crate) fn for_current(hwnd: u64, rect: u64, region: u64, flags: u32) -> u64 {
    let Some(mode) = mode(rect, region, flags) else { return 0; };
    let Ok(input) = read_region(rect, region,
        |out, source| uaccess::copy_from_user(out, source).map_err(|_| ()),
        |handle| crate::nt_gdi::region_snapshot_for_current(handle).map_err(|_| ())) else { return 0; };
    let Some(root) = u32::try_from(hwnd).ok().and_then(WindowId::from_raw) else { return 0; };
    let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return 0; };
    let token = {
        let mut entries = GUI.lock();
        let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return 0; };
        // Stored parent/client coordinates already share canonical units. Raw DPI
        // conversion belongs at ingress, not in a second per-HWND scale registry.
        if entry.state.redraw_tree(root, input.as_ref(), flags, |_, _, region| region.try_copy()).is_err() { return 0; }
        if flags & (ipc::win32_window::RDW_UPDATENOW | ipc::win32_window::RDW_ERASENOW) == 0 { return 1; }
        let Some(token) = entry.redraw.admit(cur.tid as u64, root, mode) else { return 0; };
        if flags & ipc::win32_window::RDW_UPDATENOW == 0 { entry.redraw.set_erase(cur.tid as u64, token); }
        token
    };
    resume(token, Ok(0))
}

/// Send completion runs on the original sender thread; its LRESULT is not redraw's BOOL.
/// # C: O(windows traversal + callbacks); # Sleeps: yes
pub(crate) fn resume(token: u64, result: Result<u64, ()>) -> u64 {
    let Some(cur) = sched::live::current().filter(|cur| cur.is_nt_personality()) else { return 0; };
    {
        let mut entries = GUI.lock();
        if entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
            .is_some_and(|entry| entry.redraw.defer_if_driving(cur.tid as u64, token, result)) { return STATUS_PENDING; }
    }
    if result.is_err() {
        finish(cur.tid as u64, token);
        return 0;
    }
    loop {
        let next = {
            let mut entries = GUI.lock();
            let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return 0; };
            let Some(scan) = entry.redraw.scan(cur.tid as u64, token) else { return 0; };
            let next = if scan.erase { entry.state.next_pending_erase(scan.root, scan.after, scan.mode) }
                else { entry.state.next_pending_paint(scan.root, scan.after, scan.mode) };
            match next {
                Ok(Some(window)) => {
                    if !entry.redraw.advance(cur.tid as u64, token, window) { return 0; }
                    (window, scan.erase)
                }
                Ok(None) => { entry.redraw.finish(cur.tid as u64, token); return 1; }
                Err(_) => { entry.redraw.finish(cur.tid as u64, token); return 0; }
            }
        };
        if next.1 {
            {
                let mut entries = GUI.lock();
                if let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) { entry.redraw.drive_erase(cur.tid as u64, token); }
            }
            let result = super::erase::begin_for_current(next.0.raw(), token);
            let completed = {
                let mut entries = GUI.lock();
                entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
                    .and_then(|entry| entry.redraw.end_drive(cur.tid as u64, token))
            };
            match completed { Some(Ok(_)) => continue, Some(Err(())) => { finish(cur.tid as u64, token); return 0; }, None => return result }
        }
        match send::send_resumable_current(next.0.raw() as u64, WM_PAINT, 0, 0, send::Continuation { token, resume }) {
            send::SendOutcome::Pending => return STATUS_PENDING,
            send::SendOutcome::Complete(_) => continue,
            send::SendOutcome::Failed => { finish(cur.tid as u64, token); return 0; }
        }
    }
}

fn finish(tid: u64, token: u64) {
    let Some(cur) = sched::live::current() else { return; };
    let mut entries = GUI.lock();
    if let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) {
        entry.redraw.finish(tid, token);
    }
}
