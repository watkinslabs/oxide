//! Kernel binding: resolve the HWND snapshot from the calling process's GUI owner.
use super::{answer, Answer, ORDINAL};

/// # C: O(processes + windows * depth)
pub(crate) fn route(ordinal: u64, args: &[u64]) -> Option<u64> {
    if ordinal != ORDINAL { return None; }
    let [hwnd, code, ..] = args else { return Some(0); };
    let code = *code as u32;
    let window = crate::nt_window::hwnd_snapshot_for_current(*hwnd);
    Some(match answer(code, *hwnd, window) {
        Answer::Value(value) => value,
        Answer::Unsupported(code) => {
            klog::write_raw(b"[WINDOWS-RAW-UNHANDLED] ordinal=1332 code=");
            klog::write_hex_u64(u64::from(code));
            klog::write_raw(b"\n");
            0
        },
    })
}
