//! Window tree queries: ancestry, relationships, hit testing and enumeration.
//!
//! Module manifest:
//! - `ancestor.rs` — GetAncestor/GetParent/GetWindow and the child test.
//! - `hit.rs`      — point-to-window search for the client and screen forms.
//! - `enumerate.rs`— handle-list building, class/title search and reparenting.

use alloc::vec::Vec;
use super::{WindowError, WindowId, WindowManager, WindowRect};
use super::styles::*;

/// GetAncestor relationships.
pub const GA_PARENT: u32 = 1;
pub const GA_ROOT: u32 = 2;
pub const GA_ROOTOWNER: u32 = 3;

/// ChildWindowFromPointEx filters.
pub const CWP_ALL: u32 = 0x0000;
pub const CWP_SKIPINVISIBLE: u32 = 0x0001;
pub const CWP_SKIPDISABLED: u32 = 0x0002;
pub const CWP_SKIPTRANSPARENT: u32 = 0x0004;

/// Whether a point lies inside a rectangle, with the right and bottom edges
/// exclusive as every Win32 rectangle test has them. # C: O(1)
pub const fn point_in_rect(rect: WindowRect, x: i32, y: i32) -> bool {
    x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom
}

#[path = "tree/ancestor.rs"]
mod ancestor;
#[path = "tree/hit.rs"]
mod hit;
pub use hit::{HTCLIENT, HTERROR, HTNOWHERE, HTTRANSPARENT};
#[path = "tree/enumerate.rs"]
mod enumerate;
pub use enumerate::HwndListFilter;

#[cfg(test)]
#[path = "tree/tests/ancestry.rs"]
mod ancestry_tests;
#[cfg(test)]
#[path = "tree/tests/hit.rs"]
mod hit_tests;
#[cfg(test)]
#[path = "tree/tests/enumerate.rs"]
mod enumerate_tests;
