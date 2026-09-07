//! Process startup-info flags the window manager mirrors, and the display
//! layout the process applies to new device contexts.

/// Apply one masked update and report the value that was in force. # C: O(1)
pub(crate) const fn modify(previous: u32, mask: u32, flags: u32) -> u32 { (previous & !mask) | flags }

/// `ERROR_CALL_NOT_IMPLEMENTED`, which the foreground-boost entry reports.
pub(crate) const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
/// `ERROR_NOACCESS`, reported when the layout query names no output.
pub(crate) const ERROR_NOACCESS: u32 = 998;

#[cfg(test)]
#[path = "../tests/queue_startup.rs"]
mod tests;
