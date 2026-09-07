//! Kernel binding: resolve the HWND snapshot from the calling process's GUI owner.
use super::{answer, Answer, GET_DIALOG_INFO, GET_MDI_CLIENT_INFO, ORDINAL};

/// Report what the two window-state pointers answer, bounded. A dialog reads
/// its own state back immediately after creation and stores through the
/// result without a null check, so the answer is the fact worth having; that
/// it was asked says nothing.
fn trace_state_answer(code: u32, hwnd: u64, value: u64) {
    use core::sync::atomic::{AtomicU32, Ordering};
    static BUDGET: AtomicU32 = AtomicU32::new(0);
    if !matches!(code, GET_DIALOG_INFO | GET_MDI_CLIENT_INFO) { return; }
    if BUDGET.fetch_add(1, Ordering::Relaxed) >= 64 { return; }
    klog::write_raw(b"[WINDOWS-DLGINFO] code="); klog::write_hex_u64(u64::from(code));
    klog::write_raw(b" hwnd="); klog::write_hex_u64(hwnd);
    klog::write_raw(b" value="); klog::write_hex_u64(value); klog::write_raw(b"\n");
}

/// # C: O(processes + windows * depth)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != ORDINAL { return None; }
    let [hwnd, code, ..] = args else { return Some(0); };
    let code = *code as u32;
    let window = crate::nt_window::hwnd_snapshot_for_current(*hwnd);
    Some(match answer(code, *hwnd, window) {
        Answer::Value(value) => { trace_state_answer(code, *hwnd, value); value }
        Answer::Unsupported(code) => {
            klog::write_raw(b"[WINDOWS-RAW-UNHANDLED] ordinal=1332 code=");
            klog::write_hex_u64(u64::from(code));
            klog::write_raw(b"\n");
            0
        },
    })
}
