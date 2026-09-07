//! Per-window style edits and the attributes only a few calls touch: help
//! context, layered appearance, window region and title-bar element state.
//!
//! Module manifest:
//! - `style.rs`    — style-bit edits, AlterWindowStyle and EnableWindow.
//! - `extras.rs`   — help context, layered attributes, window region.
//! - `titlebar.rs` — title-bar element state from the window's styles.

use alloc::vec::Vec;
use super::{WindowError, WindowId, WindowManager, WindowRect};
use super::styles::*;

/// Layered-window appearance. `flags` selects which of the colour key and the
/// alpha the compositor honours.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct LayeredAttributes { pub color_key: u32, pub alpha: u8, pub flags: u32 }

pub const LWA_COLORKEY: u32 = 0x0000_0001;
pub const LWA_ALPHA: u32 = 0x0000_0002;

pub const ULW_COLORKEY: u32 = 0x0000_0001;
pub const ULW_ALPHA: u32 = 0x0000_0002;
pub const ULW_OPAQUE: u32 = 0x0000_0004;
pub const ULW_EX_NORESIZE: u32 = 0x0000_0008;

/// Only monitor capture is ever excluded; no window here is protected.
pub const WDA_NONE: u32 = 0x0000_0000;

/// Attributes carried beside the window record. Absent entries are defaults.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowAttributes {
    pub help_context: u32,
    pub layered: Option<LayeredAttributes>,
    /// Window region as a rectangle list; empty means an empty region, absent
    /// means no region and therefore the whole window.
    pub region: Option<Vec<WindowRect>>,
    /// Whether the non-client area is currently drawn active.
    pub nc_activated: bool,
}

/// What an enable transition asks the caller to do beyond the style edit.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EnableOutcome {
    /// Whether the window was already disabled, which is what the call answers.
    pub previously_disabled: bool,
    /// Whether the state actually changed, so a state-change event and
    /// WM_ENABLE are due.
    pub changed: bool,
    /// Whether the newly disabled window held the focus and must lose it.
    pub clear_focus: bool,
}

#[path = "attributes/style.rs"]
mod style;
#[path = "attributes/extras.rs"]
mod extras;
#[path = "attributes/titlebar.rs"]
mod titlebar;
pub use titlebar::{title_bar_state, TITLE_BAR_ELEMENTS, STATE_SYSTEM_FOCUSABLE, STATE_SYSTEM_INVISIBLE,
    STATE_SYSTEM_UNAVAILABLE};

#[cfg(test)]
#[path = "attributes/tests/style.rs"]
mod style_tests;
#[cfg(test)]
#[path = "attributes/tests/extras.rs"]
mod extras_tests;
