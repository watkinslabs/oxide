//! Window-station clipboard: format store, sequence number, viewer chain and
//! format listeners. One owner; the syscall shim holds no clipboard state.
//!
//! Module manifest:
//! - `formats.rs`  — clipboard format identifiers and the synthesis table.
//! - `tests/`      — admission ladder, synthesis and listener contracts.

use alloc::vec::Vec;
use super::WindowId;

#[path = "clipboard/formats.rs"]
mod formats;
pub use formats::{CF_BITMAP, CF_DIB, CF_DIBV5, CF_ENHMETAFILE, CF_LOCALE, CF_MAX, CF_METAFILEPICT,
    CF_OEMTEXT, CF_PALETTE, CF_TEXT, CF_UNICODETEXT, SYNTHESIS};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ClipboardError {
    /// A second thread holds the clipboard open on a different window.
    InvalidLockSequence,
    /// The operation requires this thread to hold the open transaction.
    NotOpen,
    InvalidParameter,
    NoMemory,
    /// No such format is present in the store.
    NotFound,
    /// The viewer chain has to be walked by the caller with WM_CHANGECBCHAIN.
    Pending,
    InvalidOwner,
}

/// One stored format. `data` absent marks a delay-rendered format; `from`
/// names the format a synthesized entry would be generated from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClipFormat { pub id: u32, pub from: u32, pub seqno: u32, pub data: Option<Vec<u8>> }

/// The windows a close or release transaction must notify.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct ClipboardNotify { pub viewer: Option<WindowId>, pub owner: Option<WindowId> }

pub struct ClipboardManager {
    open_thread: Option<u64>, open_window: Option<WindowId>,
    owner: Option<WindowId>, viewer: Option<WindowId>,
    lcid: u32, seqno: u32, open_seqno: u32, rendering: u32,
    formats: Vec<ClipFormat>, format_map: u32,
    listeners: Vec<WindowId>,
}

#[path = "clipboard/store.rs"]
mod store;
#[path = "clipboard/transaction.rs"]
mod transaction;
#[path = "clipboard/listeners.rs"]
mod listeners;

impl Default for ClipboardManager { fn default() -> Self { Self::new() } }

#[cfg(test)]
#[path = "clipboard/tests/admission.rs"]
mod admission_tests;
#[cfg(test)]
#[path = "clipboard/tests/synthesis.rs"]
mod synthesis_tests;
