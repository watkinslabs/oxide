//! Raw Win32 scroll ABI codecs and validation. Main owns dispatch wiring.

#[path = "scroll/raw.rs"]
pub(crate) mod raw;
#[path = "scroll/bar_raw.rs"]
pub(crate) mod bar_raw;
#[path = "scroll/dc_raw.rs"]
pub(crate) mod dc_raw;
#[cfg(target_os = "oxide-kernel")]
#[path = "scroll/dc_live.rs"]
pub(crate) mod dc_live;
#[cfg(target_os = "oxide-kernel")]
#[path = "scroll/bar_live.rs"]
pub(crate) mod bar_live;
#[cfg(target_os = "oxide-kernel")]
#[path = "scroll/kernel.rs"]
mod kernel;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use kernel::dispatch;
pub(crate) use raw::{decode_scroll_info, encode_scroll_info, SBM_SETSCROLLINFO};
#[cfg(target_os = "oxide-kernel")]
pub(crate) use raw::SCROLLINFO_BYTES;
#[cfg(test)]
pub(crate) use raw::{GetScrollInfoParams, SetScrollInfoArgs};

#[path = "scroll/actions.rs"]
mod actions;
pub use actions::{ScrollActionSink, consume_actions};

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

#[path = "scroll/proc_abi.rs"]
pub(crate) mod proc_abi;
#[cfg(target_os = "oxide-kernel")]
#[path = "scroll/control_paint.rs"]
pub(crate) mod control_paint;
#[cfg(target_os = "oxide-kernel")]
#[path = "scroll/control_proc.rs"]
pub(crate) mod control_proc;

#[cfg(target_os = "oxide-kernel")]
#[path = "scroll/control_input.rs"]
pub(crate) mod control_input;

#[cfg(target_os = "oxide-kernel")]
#[path = "scroll/control_query.rs"]
pub(crate) mod control_query;
