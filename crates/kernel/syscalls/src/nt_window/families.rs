//! Module manifest for the window families whose ordinals the win32u entry
//! routes: each child resolves the caller and calls exactly one owner.
//!
//! - `clipboard_api.rs` — window-station clipboard transaction and formats.
//! - `hook_api.rs`      — hook registry, chain walk and procedure entry.
//! - `hook_event.rs`    — client accessibility callback record.
//! - `tree_api.rs`      — ancestry, point search, enumeration and reparenting.
//! - `state_api.rs`     — styles, attributes, foreground and position batches.
//! - `station_api.rs`   — window stations, desktops and object information.
//! - `hwnd_param_api.rs`— coordinate mapping, window info and private data.
#![cfg(target_os = "oxide-kernel")]

#[path = "families/clipboard_api.rs"]
mod clipboard_api;
pub use clipboard_api::*;
#[path = "families/hook_api.rs"]
mod hook_api;
#[path = "families/hook_event.rs"]
mod hook_event;
pub(crate) use hook_api::*;
#[path = "families/tree_api.rs"]
mod tree_api;
pub(crate) use tree_api::*;
#[path = "families/state_api.rs"]
mod state_api;
pub(crate) use state_api::*;
#[path = "families/station_api.rs"]
mod station_api;
pub(crate) use station_api::*;
#[path = "families/hwnd_param_api.rs"]
mod hwnd_param_api;
pub(crate) use hwnd_param_api::*;
