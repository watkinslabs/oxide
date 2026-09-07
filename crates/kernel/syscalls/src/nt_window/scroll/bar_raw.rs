//! Scrollbar visibility, arrow enabling and the accessibility snapshot
//! (`NtUserShowScrollBar`, `NtUserEnableScrollBar`, `NtUserGetScrollBarInfo`).
use ipc::win32_window::{ESB_DISABLE_BOTH, SB_BOTH, SB_CTL, SB_HORZ, SB_VERT};
#[cfg(test)]
use ipc::win32_window::ESB_DISABLE_LTUP;

pub(crate) const SHOW_SCROLL_BAR: u64 = 0x15ba;
pub(crate) const ENABLE_SCROLL_BAR: u64 = 0x13b0;
pub(crate) const GET_SCROLL_BAR_INFO: u64 = 0x1445;

/// `OBJID_CLIENT`, `OBJID_HSCROLL` and `OBJID_VSCROLL` as signed object ids.
pub(crate) const OBJID_CLIENT: i32 = -4;
pub(crate) const OBJID_HSCROLL: i32 = -6;
pub(crate) const OBJID_VSCROLL: i32 = -5;
/// `SBM_GETSCROLLBARINFO`, which a scrollbar control answers for itself.
pub(crate) const SBM_GETSCROLLBARINFO: u32 = 0x00eb;

/// Which standard bars a show request affects. A request naming one bar leaves
/// the other alone, and `SB_BOTH` moves both together. # C: O(1)
pub(crate) const fn show_targets(bar: i32, show: bool) -> Option<(bool, bool)> {
    match bar {
        SB_HORZ => Some((show, false)),
        SB_VERT => Some((false, show)),
        SB_BOTH => Some((show, show)),
        _ => None,
    }
}

/// A show request also names which bars it must leave untouched. # C: O(1)
pub(crate) const fn show_touches(bar: i32) -> (bool, bool) {
    match bar { SB_HORZ => (true, false), SB_VERT => (false, true), _ => (true, true) }
}

/// The enable request keeps only the arrow-disable bits. # C: O(1)
pub(crate) const fn enable_flags(flags: u32) -> u32 { flags & ESB_DISABLE_BOTH }

/// The bar an accessibility object id names. # C: O(1)
pub(crate) const fn info_bar(id: i32) -> Option<i32> {
    match id { OBJID_CLIENT => Some(SB_CTL), OBJID_HSCROLL => Some(SB_HORZ), OBJID_VSCROLL => Some(SB_VERT), _ => None }
}

/// A client object id is answered by the scrollbar window itself. # C: O(1)
pub(crate) const fn defers_to_control(id: i32) -> bool { id == OBJID_CLIENT }

/// Whether an enable request found every bar it names already at those flags,
/// which is the one case the call reports as no change. A scrollbar control
/// always reports the change. # C: O(1)
pub(crate) const fn enable_unchanged(bar: i32, other_matched: bool, target_matched: bool) -> bool {
    match bar { SB_BOTH => other_matched && target_matched, SB_CTL => false, _ => target_matched }
}

/// The bar an enable request finally applies to; `SB_BOTH` finishes on the
/// horizontal bar after the vertical one. # C: O(1)
pub(crate) const fn enable_target(bar: i32) -> i32 { if bar == SB_BOTH { SB_HORZ } else { bar } }

/// A scrollbar control also takes its window's enabled state from the request,
/// but only when the request names both arrows together. # C: O(1)
pub(crate) const fn control_window_enabled(bar: i32, flags: u32) -> Option<bool> {
    if bar != SB_CTL { return None; }
    match flags { ESB_DISABLE_BOTH => Some(false), 0 => Some(true), _ => None }
}

#[cfg(test)]
#[path = "tests/bar_raw.rs"]
mod tests;
