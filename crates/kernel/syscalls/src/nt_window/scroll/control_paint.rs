//! Scrollbar BeginPaint, client drawing callback and owned EndPaint continuation.
use alloc::sync::Arc;
use ipc::win32_window::WindowId;
use syscall::{nt::{NtCall, NtService}, SyscallArgs};
use crate::nt_window::{GUI, paint_callbacks, paint_prepare};
use super::proc_abi::*;
const STATUS_PENDING: u64 = 0x103;
const STATUS_INVALID_PARAMETER: u64 = 0xc000000d;
fn native(service: NtService, args: SyscallArgs) -> u64 {
    if service != NtService::EndWindowPaint { return STATUS_INVALID_PARAMETER; }
    // Paint-open failure owns an unbound reservation. Release through its owner,
    // without reentering the message dispatcher from a drawing operation.
    if u32::try_from(args.a0).ok().and_then(crate::nt_window::paintlease::remove_for_current).is_some() { 0 }
    else { crate::nt_window::STATUS_INVALID_HANDLE }
}
fn gdi(service: NtService, args: SyscallArgs) -> u64 { crate::nt_gdi::dispatch(NtCall { service, args }).unwrap_or(STATUS_INVALID_PARAMETER) }

/// A caller-provided HDC is never ended or deleted by this procedure.
/// # C: O(owner work + callback); # Sleeps: yes
pub(crate) fn for_current(hwnd: u64, dc: u64) -> u64 {
    if dc != 0 { return draw(hwnd, dc, None); }
    let Some(dc) = crate::nt_wine_window::paint::open_paint_dc(hwnd, native, gdi) else { return 0; };
    paint_prepare::prepare_control_for_current(hwnd as u32, dc as u32)
}

/// Preparation releases its nonclient region before transferring the paint DC lease.
/// # C: O(owner work + callback); # Sleeps: yes
pub(crate) fn finish_for_current(prepared: paint_prepare::Prepared, result: Result<bool, ()>) -> u64 {
    let dc = paint_prepare::finish_for_current(prepared, result);
    if dc == 0 { return 0; }
    draw(prepared.hwnd as u64, dc, Some(paint_prepare::Prepared { nc_region: 0, ..prepared }))
}


fn hold(prepared: paint_prepare::Prepared) -> Option<u64> {
    let cur = sched::live::current().filter(|cur| cur.is_nt_personality() && cur.tid as u64 == prepared.tid)?;
    let mut entries = GUI.lock();
    let entry = entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))?;
    let window = WindowId::from_raw(prepared.hwnd)?;
    if entry.state.get(window)?.owner_tid != prepared.tid { return None; }
    entry.state.validate_paint_session(window, prepared.dc).ok()?;
    let resources = paint_callbacks::Resources { hwnd: prepared.hwnd as u64, dc: prepared.dc as u64,
        nc_region: 0, erase: false, delayed: false, empty_clip: false };
    entry.paint_callbacks.hold(prepared.tid, resources, paint_callbacks::Completion::ControlPaint(prepared))
}
fn draw(hwnd: u64, dc: u64, prepared: Option<paint_prepare::Prepared>) -> u64 {
    let Some(bytes) = super::control_draw::record(hwnd, dc, true, true) else { if prepared.is_some() { present(hwnd, dc); } return 0; };
    let completion = match prepared {
        Some(prepared) => {
            let Some(token) = hold(prepared) else { paint_prepare::discard_for_current(prepared); return 0; };
            sched::nt_callback::Completion { kind: PAINT_COMPLETION, argument: token }
        }
        None => sched::nt_callback::Completion::NONE,
    };
    let status = crate::nt_rtl::begin_user_callback(DRAW_CALLBACK, crate::nt_user_callback::Input::Record(&bytes), completion);
    if status == STATUS_PENDING { return status; }
    klog::write_raw(b"[WINDOWS-SCROLL-PAINT-FAIL] hwnd="); klog::write_hex_u64(hwnd);
    klog::write_raw(b" status="); klog::write_hex_u64(status); klog::write_raw(b"\n");
    if prepared.is_some() { complete_callback(completion, status); }
    0
}
/// The callback cannot outlive its HDC lease, including cancellation by foreign destruction.
/// # C: O(processes + preparations + present); # Sleeps: yes
pub(crate) fn complete_callback(completion: sched::nt_callback::Completion, _: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return 0; };
    let held = {
        let mut entries = GUI.lock();
        entries.iter_mut().find(|entry| entry.group.ptr_eq(&Arc::downgrade(&cur.thread_group)))
            .and_then(|entry| entry.paint_callbacks.release_held(cur.tid as u64, completion.argument))
    };
    if let Some((paint_callbacks::Completion::ControlPaint(prepared), cancelled)) = held {
        if cancelled { paint_prepare::discard_for_current(prepared); }
        else { crate::nt_text_order::end_paint_for_current(prepared.hwnd as u64, prepared.dc as u64, present); }
    }
    0
}
fn present(hwnd: u64, dc: u64) { let _ = crate::nt_wine_window::paint::end_paint_with_dc(hwnd, dc, gdi); }
