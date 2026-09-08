//! Synchronous canonical window-create transaction.

use super::*;

#[path = "create/nccalcsize.rs"]
mod nccalcsize;

const WM_NCCREATE: u64 = 0x0081;
const WM_CREATE: u64 = 0x0001;
const WM_NCDESTROY: u64 = 0x0082;
const CALLBACK_CREATE_REJECT_NCDESTROY: u64 = 5;

/// Name a create rejection that would otherwise return NULL in silence. An
/// application whose main window is NULL exits at once, so an unnamed
/// rejection here is indistinguishable from a crash.
fn reject_create_lifecycle(reason: &'static [u8], hwnd: u64, detail: u64) {
    klog::write_raw(b"[WINDOWS-WINDOW-CREATE-FAIL] stage=lifecycle reason=");
    klog::write_raw(reason);
    klog::write_raw(b" hwnd=");
    klog::write_hex_u64(hwnd);
    klog::write_raw(b" detail=");
    klog::write_hex_u64(detail);
    klog::write_raw(b"\n");
}

pub(crate) fn begin_create_lifecycle_for_current(hwnd: u64, params: CreateStructArgs, convention: CreateReturnConvention) -> u64 {
    let Some(cur) = sched::live::current() else { return convention.failure(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || hwnd == 0 || hwnd > u32::MAX as u64 {
        reject_create_lifecycle(b"caller", hwnd, cur.is_nt_personality() as u64);
        return convention.failure(STATUS_INVALID_PARAMETER);
    }
    let group = Arc::clone(&cur.thread_group);
    let (token, wndproc) = {
        let mut entries = GUI.lock();
        entries.retain(|entry| entry.group.upgrade().is_some());
        let Some(index) = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else {
            reject_create_lifecycle(b"no-gui-entry", hwnd, entries.len() as u64);
            return convention.failure(STATUS_INVALID_PARAMETER);
        };
        let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else {
            reject_create_lifecycle(b"bad-window-id", hwnd, 0);
            return convention.failure(STATUS_INVALID_PARAMETER);
        };
        let Some(record) = entries[index].state.get(window) else {
            reject_create_lifecycle(b"no-window-record", hwnd, 0);
            return convention.failure(STATUS_INVALID_PARAMETER);
        };
        if record.owner_tid != cur.tid as u64 {
            reject_create_lifecycle(b"foreign-owner", hwnd, record.owner_tid);
            return convention.failure(STATUS_INVALID_PARAMETER);
        }
        if record.wndproc == 0 {
            // A class registered without a window procedure has nothing to run
            // the create callbacks on, so the window can never be completed.
            reject_create_lifecycle(b"no-wndproc", hwnd, 0);
            return convention.failure(STATUS_INVALID_PARAMETER);
        }
        let token = entries[index].next_create;
        entries[index].next_create = token.checked_add(1).filter(|value| *value != 0).unwrap_or(1);
        entries[index].pending_creates.push(PendingCreate { token, hwnd, wndproc: record.wndproc, params, convention, nccalc: 0, nccalc_handed: ipc::win32_window::WindowRect { left: 0, top: 0, right: 0, bottom: 0 } });
        (token, record.wndproc)
    };
    // The compositor/backend HWND must exist before WM_NCCREATE: application
    // painting can occur synchronously during either create callback.
    if let Err(error) = bridge::publish_create_current(hwnd, params.style as u32, params.ex_style) {
        // A window that cannot be published is a NULL CreateWindowEx, and an
        // application whose main window is NULL exits immediately. Naming the
        // transport reason here is the difference between that exit and a
        // silent one: the failure is otherwise visible only as the process
        // dying and every downstream owner reporting a closed peer.
        klog::write_raw(b"[WINDOWS-WINDOW-CREATE-FAIL] stage=publish hwnd=");
        klog::write_hex_u64(hwnd);
        klog::write_raw(b" transport=");
        klog::write_hex_u64(error as u64);
        klog::write_raw(b"\n");
        abort_create_for_current(token);
        return convention.failure(STATUS_INVALID_PARAMETER);
    }
    let completion = sched::nt_callback::Completion { kind: CALLBACK_CREATE_NCCREATE, argument: token };
    let status = crate::nt_rtl::begin_wndproc_create_callback(hwnd, WM_NCCREATE, wndproc, params, completion);
    if status == STATUS_PENDING { status } else {
        klog::write_raw(b"[WINDOWS-WINDOW-CREATE-FAIL] stage=nccreate-callback hwnd=");
        klog::write_hex_u64(hwnd);
        klog::write_raw(b" status=");
        klog::write_hex_u64(status);
        klog::write_raw(b"\n");
        abort_create_for_current(token); convention.failure(STATUS_INVALID_PARAMETER)
    }
}

/// Record the user address the outstanding creation-time nonclient
/// calculation is writing into. # C: O(processes + pending creates)
fn set_pending_nccalc(token: u64, pointer: u64, handed: ipc::win32_window::WindowRect) {
    let Some(cur) = sched::live::current() else { return; };
    let mut entries = GUI.lock();
    let Some(entry) = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group))) else { return; };
    if let Some(pending) = entry.pending_creates.iter_mut().find(|pending| pending.token == token) { pending.nccalc = pointer; pending.nccalc_handed = handed; }
}

/// Continue the create transaction at WM_CREATE. # C: O(processes + windows); # Sleeps: yes
fn begin_create_message(pending: PendingCreate) -> u64 {
    let next = crate::nt_rtl::begin_wndproc_create_callback(pending.hwnd, WM_CREATE, pending.wndproc, pending.params,
        sched::nt_callback::Completion { kind: CALLBACK_CREATE, argument: pending.token });
    if next == STATUS_PENDING { next } else { abort_create_for_current(pending.token); pending.convention.failure(STATUS_INVALID_PARAMETER) }
}

fn pending_create_for_current(token: u64) -> Option<PendingCreate> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    entries[index].pending_creates.iter().find(|pending| pending.token == token).copied()
}

fn take_pending_create_for_current(token: u64) -> Option<PendingCreate> {
    let cur = sched::live::current()?;
    if !cur.is_nt_personality() { return None; }
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    entries.retain(|entry| entry.group.upgrade().is_some());
    let index = entries.iter().position(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group)))?;
    let pending = entries[index].pending_creates.iter().position(|pending| pending.token == token)?;
    Some(entries[index].pending_creates.swap_remove(pending))
}

/// Post the created window's geometry to its own queue. Failure to post is not
/// a failed creation: the window exists and the message can still arrive from a
/// later reposition.
fn notify_created_geometry_for_current(hwnd: u64) {
    let Some(cur) = sched::live::current() else { return; };
    let Some(window) = ipc::win32_window::WindowId::from_raw(hwnd as u32) else { return; };
    let group = Arc::clone(&cur.thread_group);
    let mut entries = GUI.lock();
    let Some(entry) = entries.iter_mut().find(|entry| entry.group.upgrade().is_some_and(|candidate| Arc::ptr_eq(&candidate, &group))) else { return; };
    let _ = entry.state.notify_created_geometry(window);
}

fn abort_create_for_current(token: u64) {
    if let Some(pending) = take_pending_create_for_current(token) { destroy_window_for_current(pending.hwnd); }
}

fn reject_create(completion: sched::nt_callback::Completion, pending: PendingCreate) -> u64 {
    let next = crate::nt_rtl::begin_wndproc_create_callback(
        pending.hwnd,
        WM_NCDESTROY,
        pending.wndproc,
        pending.params,
        sched::nt_callback::Completion { kind: CALLBACK_CREATE_REJECT_NCDESTROY, argument: completion.argument },
    );
    if next == STATUS_PENDING { next } else { abort_create_for_current(pending.token); pending.convention.failure(STATUS_INVALID_PARAMETER) }
}

/// Complete destruction callbacks and the synchronous create transaction.
pub(crate) fn complete_callback(completion: sched::nt_callback::Completion, callback_result: u64) -> u64 {
    match completion.kind {
        CALLBACK_DESTROY => {
            let root = callback_root(completion.argument);
            let index = callback_index(completion.argument);
            let Some(order) = destruction_order_for_current(root) else { return STATUS_SUCCESS; };
            let next = index + 1;
            let (message, target_index, kind) = if next < order.len() { (WM_DESTROY, next, CALLBACK_DESTROY) } else { (WM_NCDESTROY, order.len() - 1, CALLBACK_NCDESTROY) };
            let target = order[target_index];
            let Some(wndproc) = window_wndproc_for_current(target) else { destroy_window_for_current(root); return STATUS_SUCCESS; };
            let result = crate::nt_rtl::begin_wndproc_callback_with_completion(target, message, 0, 0, wndproc, sched::nt_callback::Completion { kind, argument: callback_argument(root, target_index) });
            if result == STATUS_PENDING { result } else { destroy_window_for_current(root); STATUS_SUCCESS }
        }
        CALLBACK_NCDESTROY => {
            let root = callback_root(completion.argument);
            let index = callback_index(completion.argument);
            if index > 0 {
                let Some(order) = destruction_order_for_current(root) else { return STATUS_SUCCESS; };
                let target = order[index - 1];
                let Some(wndproc) = window_wndproc_for_current(target) else { destroy_window_for_current(root); return STATUS_SUCCESS; };
                let result = crate::nt_rtl::begin_wndproc_callback_with_completion(target, WM_NCDESTROY, 0, 0, wndproc, sched::nt_callback::Completion { kind: CALLBACK_NCDESTROY, argument: callback_argument(root, index - 1) });
                if result == STATUS_PENDING { return result; }
            }
            destroy_window_for_current(root); STATUS_SUCCESS
        }
        CALLBACK_CREATE_NCCREATE => {
            let Some(pending) = pending_create_for_current(completion.argument) else { return STATUS_INVALID_PARAMETER; };
            if create_lifecycle::after_nc_create(callback_result) == create_lifecycle::CreateTransition::Reject {
                // The application's own window procedure refused the window.
                // Everything up to here succeeded, so this is the application
                // rejecting what it was handed, and the CREATESTRUCT it was
                // handed is the thing to look at. Report what it saw.
                klog::write_raw(b"[WINDOWS-WNDPROC-NCCREATE-REJECT] hwnd=");
                klog::write_hex_u64(pending.hwnd);
                klog::write_raw(b" result=");
                klog::write_hex_u64(callback_result);
                klog::write_raw(b" style=");
                klog::write_hex_u64(pending.params.style as u64);
                klog::write_raw(b" exstyle=");
                klog::write_hex_u64(pending.params.ex_style as u64);
                klog::write_raw(b" instance=");
                klog::write_hex_u64(pending.params.instance);
                klog::write_raw(b" class=");
                klog::write_hex_u64(pending.params.class);
                klog::write_raw(b" name=");
                klog::write_hex_u64(pending.params.name);
                klog::write_raw(b" parent=");
                klog::write_hex_u64(pending.params.parent);
                klog::write_raw(b" cx=");
                klog::write_hex_u64(pending.params.cx as u64);
                klog::write_raw(b" cy=");
                klog::write_hex_u64(pending.params.cy as u64);
                klog::write_raw(b"\n");
                return reject_create(completion, pending);
            }
            // The reference computes the client area between WM_NCCREATE and
            // WM_CREATE. A window that never runs it keeps a client rectangle
            // equal to its window rectangle, so nothing the nonclient area
            // owns - a menu bar first of all - ever reserves its band.
            if let Some((status, pointer, handed)) = nccalcsize::begin(pending.hwnd, pending.wndproc, pending.token) {
                set_pending_nccalc(pending.token, pointer, handed);
                return status;
            }
            begin_create_message(pending)
        }
        CALLBACK_CREATE_NCCALCSIZE => {
            let Some(pending) = pending_create_for_current(completion.argument) else { return STATUS_INVALID_PARAMETER; };
            nccalcsize::apply_for_current(pending.hwnd, pending.nccalc, pending.nccalc_handed);
            set_pending_nccalc(pending.token, 0, pending.nccalc_handed);
            begin_create_message(pending)
        }
        CALLBACK_CREATE => {
            let Some(pending) = pending_create_for_current(completion.argument) else { return STATUS_INVALID_PARAMETER; };
            if create_lifecycle::after_create(callback_result) == create_lifecycle::CreateTransition::Reject { return reject_create(completion, pending); }
            let Some(pending) = take_pending_create_for_current(completion.argument) else { return STATUS_INVALID_PARAMETER; };
            if pending.params.style as u32 & 0x1000_0000 != 0 {
                let shown = super::dispatch(NtCall { service: nt::NtService::ShowWindow,
                    args: syscall::SyscallArgs { a0: pending.hwnd, a1: 1, a2: 0, a3: 0, a4: 0, a5: 0 } });
                if !shown.is_some_and(|result| result <= 1) {
                    destroy_window_for_current(pending.hwnd);
                    return pending.convention.failure(STATUS_INVALID_PARAMETER);
                }
            }
            // Creation itself reports the geometry the window was made with.
            // Without it the application never learns its size, and a control
            // it lays out from that size stays at zero and draws nothing.
            notify_created_geometry_for_current(pending.hwnd);
            crate::nt_milestone::window_create();
            pending.hwnd
        }
        CALLBACK_CREATE_REJECT_NCDESTROY => {
            let Some(pending) = take_pending_create_for_current(completion.argument) else { return STATUS_INVALID_PARAMETER; };
            destroy_window_for_current(pending.hwnd);
            pending.convention.failure(STATUS_INVALID_PARAMETER)
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}
