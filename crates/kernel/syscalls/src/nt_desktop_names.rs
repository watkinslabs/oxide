//! Canonical interactive station and desktop names for an NT launch.
//!
//! One place owns these names. They are the identities Windows-derived code
//! expects to find, and a launch that invented its own would be invisible to
//! every application that looks the standard ones up by name.

/// Interactive window station created for the first NT process of a launch.
pub const INTERACTIVE_STATION: &str = "\\Windows\\WindowStations\\WinSta0";
/// Default desktop within the interactive station.
pub const DEFAULT_DESKTOP: &str = "Default";

/// Rights an NT process holds on its own station.
/// `WINSTA_ALL_ACCESS` without `DELETE`/`WRITE_OWNER`: a process manages the
/// station it belongs to but cannot destroy it for every other process.
pub const STATION_ACCESS: u32 = 0x0000_037f | READ_CONTROL;
/// Rights an NT process holds on its own desktop, likewise without the
/// ownership rights that would let one application unseat the others.
pub const DESKTOP_ACCESS: u32 = 0x0000_01ff | READ_CONTROL;

const READ_CONTROL: u32 = 0x0002_0000;

#[cfg(test)]
#[path = "tests/nt_desktop_names.rs"]
mod tests;
