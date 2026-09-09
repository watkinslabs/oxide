//! Disabled retrieval trace boundary.
use ipc::win32_window::{WinMessage, WindowId};
pub(super) fn hit(_: u64, _: WinMessage, _: WindowId, _: i32, _: bool) {}
pub(super) fn prepared(_: u64, _: WinMessage) {}
