// Legacy CURSOR/CURSOR2 admission ladder, kept ungated and free of user-memory
// and global state so the errno contract is hosted-testable. `kms_ext` performs
// the work this decides on.
//
// A card that publishes no cursor entry point is the null-function-pointer case
// upstream, and the three refusals below are three DIFFERENT errnos there — a
// single EINVAL for all of them is what this module exists to prevent.

use syscall::errno::Errno;

use crate::{DRM_MODE_CURSOR_BO, DRM_MODE_CURSOR_MOVE};

/// What a legal cursor request asks the driver to do. Both may be set: one
/// request carrying both flags uploads and then moves, in that order.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CursorPlan {
    /// Publish (or, for a zero handle, withdraw) the cursor image.
    pub set_bo: bool,
    /// Reposition the published cursor.
    pub mov: bool,
}

/// Which cursor entry points the owning card actually publishes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CursorSupport {
    pub set: bool,
    pub mov: bool,
}

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Admit or refuse a legacy cursor request, in the order the refusals are
/// decided upstream: flag validity, then CRTC identity, then each requested
/// operation against the entry point that would perform it.
///
/// The three refusals are deliberately distinct. `ENOENT` names a CRTC that
/// does not exist, `ENXIO` an image request on a card with no cursor image
/// support, and `EFAULT` a move on a card with no move support. A client that
/// falls back to software compositing distinguishes them, so collapsing them
/// to `EINVAL` reads to that client as a malformed request it should not retry.
///
/// # C: O(1)
pub fn plan(flags: u32, crtc_known: bool, support: CursorSupport) -> Result<CursorPlan, i64> {
    if flags == 0 || flags & !(DRM_MODE_CURSOR_BO | DRM_MODE_CURSOR_MOVE) != 0 { return Err(err(Errno::Einval)); }
    if !crtc_known { return Err(err(Errno::Enoent)); }
    let set_bo = flags & DRM_MODE_CURSOR_BO != 0;
    let mov    = flags & DRM_MODE_CURSOR_MOVE != 0;
    if set_bo && !support.set { return Err(err(Errno::Enxio)); }
    if mov    && !support.mov { return Err(err(Errno::Efault)); }
    Ok(CursorPlan { set_bo, mov })
}

#[cfg(test)]
#[path = "cursor_plan/tests.rs"]
mod tests;
