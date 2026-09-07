//! One menu-tracking session: which popup window shows which menu, whether
//! cancellation has been requested, and the resumable loop state one tracking
//! thread parks in the process record while a window procedure runs.
extern crate alloc;
use alloc::vec::Vec;
use ipc::win32_menu::track_loop::TrackLoop;


/// The cancellation record the tracking thread publishes: which window owns
/// the menu, and whether `NtUserEndMenu` has asked the loop to stop. The open
/// popup windows are the loop's own; this record carries nothing they carry.
pub(crate) struct MenuCancel { pub owner: u64, pub exit: bool }

/// The popup windows one tracking session has open, innermost last.
pub(crate) struct MenuSession { pub owner: u64, open: Vec<(u32, u64)> }

impl MenuSession {
    /// # C: O(1)
    pub(crate) fn new(owner: u64) -> Self { Self { owner, open: Vec::new() } }

    /// Retain the window showing one menu. # C: O(N_open)
    pub(crate) fn opened(&mut self, menu: u32, hwnd: u64) {
        self.open.retain(|(candidate, _)| *candidate != menu);
        self.open.push((menu, hwnd));
    }

    /// Forget the window showing one menu, reporting it. # C: O(N_open)
    pub(crate) fn closed(&mut self, menu: u32) -> Option<u64> {
        let index = self.open.iter().position(|(candidate, _)| *candidate == menu)?;
        Some(self.open.remove(index).1)
    }

    /// # C: O(N_open)
    pub(crate) fn window_of(&self, menu: u32) -> Option<u64> {
        self.open.iter().find(|(candidate, _)| *candidate == menu).map(|(_, hwnd)| *hwnd)
    }

    /// Every open popup, innermost first: the order the chain is searched for
    /// the menu a point falls on and unwound when tracking ends. # C: O(N_open)
    pub(crate) fn innermost_first(&self) -> Vec<(u32, u64)> {
        let mut chain = self.open.clone();
        chain.reverse();
        chain
    }
}

/// The tracking loop of one thread, parked in the process record while the
/// window procedure a step armed runs in the client. The loop is taken out to
/// be driven and put back before every suspension, so exactly one driver owns
/// it at a time.
pub(crate) struct PendingTrack { pub tid: u64, pub state: TrackLoop, pub session: MenuSession,
    /// Where `TrackPopupMenuEx` asked for the top menu to open.
    pub origin: (i32, i32) }

#[cfg(test)]
#[path = "../tests/menu_session.rs"]
mod tests;
