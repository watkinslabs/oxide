//! `NtUserCallHwndParam`: one ordinal, one method enumeration, one decoder.
//!
//! Module manifest:
//! - `method.rs`      — the method enumeration in the client's order.
//! - `decode.rs`      — the single method-to-request mapping every route uses.
//! - `params.rs`      — the parameter records passed behind one pointer.
//! - `window_info.rs` — the `WINDOWINFO` encoding.
//! - `kernel.rs`      — executes one decoded request against the owners.

pub(crate) const ORDINAL: u64 = 0x1336;
/// The parameter word's argument index, which the unclaimed-ordinal trace
/// reads to name the method behind a multiplexer.
pub(crate) const METHOD_ARG: usize = 2;

#[path = "hwnd_param/method.rs"]
pub(crate) mod method;
#[path = "hwnd_param/params.rs"]
pub(crate) mod params;
#[path = "hwnd_param/decode.rs"]
mod decode;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use decode::{decode, RectKind, Request};
#[path = "hwnd_param/window_info.rs"]
pub(crate) mod window_info;

#[cfg(target_os = "oxide-kernel")]
#[path = "hwnd_param/kernel.rs"]
pub(crate) mod kernel;
