//! `NtUserCallHwnd` multiplexer: one-window queries selected by a code.
pub(crate) const ORDINAL: u64 = 0x1332;
pub(crate) const ACTIVATE_OTHER_WINDOW: u32 = 0;
pub(crate) const GET_DIALOG_INFO: u32 = 1;
pub(crate) const GET_DPI_FOR_WINDOW: u32 = 2;
pub(crate) const GET_LAST_ACTIVE_POPUP: u32 = 3;
pub(crate) const GET_MDI_CLIENT_INFO: u32 = 4;
pub(crate) const GET_PARENT: u32 = 5;
pub(crate) const GET_WINDOW_DPI_AWARENESS_CONTEXT: u32 = 6;
pub(crate) const GET_WINDOW_INPUT_CONTEXT: u32 = 7;
pub(crate) const GET_WINDOW_SYS_SUB_MENU: u32 = 8;
pub(crate) const GET_WINDOW_TEXT_LENGTH: u32 = 9;
pub(crate) const IS_WINDOW: u32 = 10;
pub(crate) const IS_WINDOW_ENABLED: u32 = 11;
pub(crate) const IS_WINDOW_UNICODE: u32 = 12;
pub(crate) const IS_WINDOW_VISIBLE: u32 = 13;
pub(crate) const SET_FOREGROUND_WINDOW_INTERNAL: u32 = 14;
pub(crate) const GET_FULL_WINDOW_HANDLE: u32 = 15;
pub(crate) const IS_CURRENT_PROCESS_WINDOW: u32 = 16;
pub(crate) const IS_CURRENT_THREAD_WINDOW: u32 = 17;
const DPI_AWARENESS_CONTEXT_UNAWARE: u64 = 0x6010;
const WS_CHILD: u32 = 0x4000_0000;
const WS_POPUP: u32 = 0x8000_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_DISABLED: u32 = 0x0800_0000;

/// Canonical facts about one HWND of the calling process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub hwnd: u32,
    pub parent: u32,
    pub owner: u32,
    pub style: u32,
    pub unicode: bool,
    /// Every ancestor up to the top-level window carries WS_VISIBLE.
    pub ancestors_visible: bool,
    pub current_thread: bool,
    pub text_length: u32,
    pub dpi: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Answer { Value(u64), Unsupported(u32) }

/// A null or unknown handle answers every predicate false and every handle
/// query zero; the reference never raises a status from this entry.
/// # C: O(1)
pub(crate) fn answer(code: u32, hwnd: u64, window: Option<Snapshot>) -> Answer {
    let Some(w) = window.filter(|_| hwnd != 0) else {
        return match code {
            IS_WINDOW | IS_WINDOW_ENABLED | IS_WINDOW_UNICODE | IS_WINDOW_VISIBLE | GET_PARENT | GET_WINDOW_TEXT_LENGTH |
            GET_LAST_ACTIVE_POPUP | GET_FULL_WINDOW_HANDLE | IS_CURRENT_PROCESS_WINDOW | IS_CURRENT_THREAD_WINDOW |
            GET_DIALOG_INFO | GET_MDI_CLIENT_INFO | GET_WINDOW_INPUT_CONTEXT | GET_WINDOW_SYS_SUB_MENU |
            ACTIVATE_OTHER_WINDOW | SET_FOREGROUND_WINDOW_INTERNAL => Answer::Value(0),
            GET_DPI_FOR_WINDOW => Answer::Value(0),
            GET_WINDOW_DPI_AWARENESS_CONTEXT => Answer::Value(0),
            other => Answer::Unsupported(other),
        };
    };
    Answer::Value(match code {
        IS_WINDOW => 1,
        IS_WINDOW_ENABLED => u64::from(w.style & WS_DISABLED == 0),
        IS_WINDOW_UNICODE => u64::from(w.unicode),
        IS_WINDOW_VISIBLE => u64::from(w.style & WS_VISIBLE != 0 && w.ancestors_visible),
        GET_PARENT => if w.style & WS_POPUP != 0 { u64::from(w.owner) } else if w.style & WS_CHILD != 0 { u64::from(w.parent) } else { 0 },
        GET_WINDOW_TEXT_LENGTH => u64::from(w.text_length),
        GET_DPI_FOR_WINDOW => u64::from(w.dpi),
        GET_WINDOW_DPI_AWARENESS_CONTEXT => DPI_AWARENESS_CONTEXT_UNAWARE,
        GET_FULL_WINDOW_HANDLE => u64::from(w.hwnd),
        IS_CURRENT_PROCESS_WINDOW => u64::from(w.hwnd),
        IS_CURRENT_THREAD_WINDOW => if w.current_thread { u64::from(w.hwnd) } else { 0 },
        GET_LAST_ACTIVE_POPUP => u64::from(w.hwnd),
        GET_DIALOG_INFO | GET_MDI_CLIENT_INFO | GET_WINDOW_INPUT_CONTEXT | GET_WINDOW_SYS_SUB_MENU => 0,
        ACTIVATE_OTHER_WINDOW | SET_FOREGROUND_WINDOW_INTERNAL => 0,
        other => return Answer::Unsupported(other),
    })
}

#[cfg(target_os = "oxide-kernel")]
#[path = "hwnd_call/kernel.rs"]
pub(crate) mod kernel;
#[cfg(test)]
#[path = "tests/hwnd_call.rs"]
mod tests;
