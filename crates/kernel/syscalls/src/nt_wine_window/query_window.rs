//! `NtUserQueryWindow`: one window-info class per call, answered from the
//! canonical window, thread and input-context owners.
pub(crate) const ORDINAL: u64 = 0x14df;

/// Window-info classes, in their reference order.
pub(crate) const WINDOW_PROCESS: u64 = 0;
pub(crate) const WINDOW_PROCESS2: u64 = 1;
pub(crate) const WINDOW_THREAD: u64 = 2;
pub(crate) const WINDOW_ACTIVE_WINDOW: u64 = 3;
pub(crate) const WINDOW_FOCUS_WINDOW: u64 = 4;
pub(crate) const WINDOW_IS_HUNG: u64 = 5;
pub(crate) const WINDOW_CLIENT_BASE: u64 = 6;
pub(crate) const WINDOW_IS_FOREGROUND_THREAD: u64 = 7;
pub(crate) const WINDOW_DEFAULT_IME_WINDOW: u64 = 8;
pub(crate) const WINDOW_DEFAULT_INPUT_CONTEXT: u64 = 9;

/// Facts about one resolved window and the thread that owns it.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Facts {
    pub pid: u64,
    pub thread_id: u64,
    /// Active and focus windows of the owning thread's input state.
    pub active: u64,
    pub focus: u64,
    pub hung: bool,
    /// The owning thread also owns the foreground window.
    pub foreground_thread: bool,
    /// Default IME window of the owning thread.
    pub default_ime_window: u64,
    /// Default input context of the CALLING thread, which this class reports
    /// without regard to the named window.
    pub default_input_context: u64,
}

/// The default-input-context class answers from the calling thread alone, so
/// it neither resolves nor requires the named window. # C: O(1)
pub(crate) const fn needs_window(cls: u64) -> bool { cls != WINDOW_DEFAULT_INPUT_CONTEXT }

/// A window the caller cannot resolve answers zero for every class that reads
/// it; a class the enumeration does not name answers zero too. # C: O(1)
pub(crate) fn answer(cls: u64, window: Option<Facts>) -> u64 {
    if cls == WINDOW_DEFAULT_INPUT_CONTEXT { return window.map_or(0, |facts| facts.default_input_context); }
    let Some(facts) = window else { return 0; };
    match cls {
        WINDOW_PROCESS | WINDOW_PROCESS2 => facts.pid,
        WINDOW_THREAD => facts.thread_id,
        WINDOW_ACTIVE_WINDOW => facts.active,
        WINDOW_FOCUS_WINDOW => facts.focus,
        WINDOW_IS_HUNG => u64::from(facts.hung),
        WINDOW_IS_FOREGROUND_THREAD => u64::from(facts.foreground_thread),
        WINDOW_DEFAULT_IME_WINDOW => facts.default_ime_window,
        WINDOW_CLIENT_BASE | _ => 0,
    }
}

#[cfg(target_os = "oxide-kernel")]
#[path = "query_window/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/query_window.rs"]
mod tests;
