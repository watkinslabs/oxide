//! The extent a window actually has on the display.
//!
//! The display server is the authority on a mapped window's size. A window
//! manager frames, constrains or tiles what the application asked for and
//! reports the result in a configure notification; the size the client
//! requested is a request, never a fact. A client that keeps the requested
//! extent instead measures every later frame against a size the window no
//! longer has, and a frame whose surface does not describe its window cannot
//! be put on it: every one is refused and the window keeps whatever pixels it
//! already had, which on screen is an application that stopped drawing.

use syscall::nt_compositor::MAX_DIMENSION;

/// The extent to retain after a configure notification, or `None` when there
/// is nothing to adopt: an unusable size names no window, and a size already
/// held is not a change.
///
/// # C: O(1)
pub fn notified(held: (u32, u32), reported: (u32, u32)) -> Option<(u32, u32)> {
    let (width, height) = reported;
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION { return None; }
    (reported != held).then_some(reported)
}

/// Whether a surface captured for `held` still describes a window of
/// `extent`. A surface of the wrong extent is not a smaller picture of the
/// window: its rows are the wrong length, so no row of it can be read out at
/// the window's coordinates.
///
/// # C: O(1)
pub fn surface_survives(held: (u32, u32), extent: (u32, u32)) -> bool { held == extent }

#[cfg(test)]
#[path = "tests/extent.rs"]
mod tests;
