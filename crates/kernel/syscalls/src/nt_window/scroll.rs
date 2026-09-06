//! Raw Win32 scroll ABI codecs and validation. Main owns dispatch wiring.

#[path = "scroll/raw.rs"]
mod raw;
#[cfg(target_os = "oxide-kernel")]
#[path = "scroll/kernel.rs"]
mod kernel;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use kernel::dispatch;
pub(crate) use raw::{decode_scroll_info, encode_scroll_info, GetScrollInfoParams, SetScrollInfoArgs,
    GET_PARAMS_BYTES, GET_SCROLL_INFO_METHOD, SBM_SETSCROLLINFO, SCROLLINFO_BYTES,
    SET_SCROLL_INFO_ORDINAL};

pub trait ScrollActionSink {
    fn show_scrollbar(&mut self, hwnd: u64, bar: i32) -> bool;
    fn hide_scrollbar(&mut self, hwnd: u64, bar: i32) -> bool;
    fn enable_scroll_arrows(&mut self, hwnd: u64, bar: i32) -> bool;
    fn disable_scroll_arrows(&mut self, hwnd: u64, bar: i32) -> bool;
    /// Complete SetWindowPos(..., SWP_FRAMECHANGED) through the resumable
    /// position owner. `Some(0)` and `Some(STATUS_PENDING)` are valid results.
    fn frame_changed(&mut self, hwnd: u64, bar: i32, token: u64) -> pending::Outcome;
    fn repaint_scrollbar(&mut self, hwnd: u64, bar: i32) -> bool;
    /// `None` is transport failure; `Some(0)` is a valid synchronous LRESULT.
    /// The live owner supplies Curie's resumable send adapter here.
    fn send_scrollbar_message(&mut self, hwnd: u64, message: u32, wparam: u64, lparam: u64) -> Option<u64>;
}

/// Consume the canonical action result. SB_CTL is a synchronous scrollbar
/// window message, never a second nonclient scrollbar state.
pub fn consume_actions<S: ScrollActionSink + ?Sized>(
    sink: &mut S, hwnd: u64, bar: i32, info_ptr: u64, redraw: bool,
    outcome: ipc::win32_window::ScrollOutcome, token: Option<u64>,
) -> pending::Outcome {
    let action = outcome.action;
    if action.control_message && sink.send_scrollbar_message(hwnd, SBM_SETSCROLLINFO, redraw as u64, info_ptr).is_none() { return pending::Outcome::Failed; }
    if bar == ipc::win32_window::SB_CTL { return pending::Outcome::Complete(0); }
    if action.hide {
        if !sink.hide_scrollbar(hwnd, bar) { return pending::Outcome::Failed; }
        let Some(token) = token else { return pending::Outcome::Failed; };
        match sink.frame_changed(hwnd, bar, token) { pending::Outcome::Complete(_) => {}, pending::Outcome::Pending => return pending::Outcome::Pending, pending::Outcome::Failed => return pending::Outcome::Failed }
    }
    if action.show {
        if !sink.show_scrollbar(hwnd, bar) { return pending::Outcome::Failed; }
        let Some(token) = token else { return pending::Outcome::Failed; };
        match sink.frame_changed(hwnd, bar, token) { pending::Outcome::Complete(_) => {}, pending::Outcome::Pending => return pending::Outcome::Pending, pending::Outcome::Failed => return pending::Outcome::Failed }
    }
    if action.disable_arrows && !sink.disable_scroll_arrows(hwnd, bar) { return pending::Outcome::Failed; }
    if action.enable_arrows && !sink.enable_scroll_arrows(hwnd, bar) { return pending::Outcome::Failed; }
    if redraw && !action.hide && action.repaint && !sink.repaint_scrollbar(hwnd, bar) { return pending::Outcome::Failed; }
    pending::Outcome::Complete(0)
}

#[cfg(test)]
#[path = "tests/scroll.rs"]
mod tests;

#[cfg(target_os = "oxide-kernel")]
#[path = "scroll/live.rs"]
pub(crate) mod live;
#[cfg(target_os = "oxide-kernel")]
#[path = "scroll/sink.rs"]
pub(crate) mod sink;
#[path = "scroll/pending.rs"]
pub(crate) mod pending;
