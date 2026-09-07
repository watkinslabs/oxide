//! Per-window icons: the large and small icons a window presents, and the
//! small icon derived from the large one when the window sets no small icon.

use alloc::vec::Vec;
use super::{WindowId, WindowManager};

pub const ICON_SMALL: u64 = 0;
pub const ICON_BIG: u64 = 1;
/// The derived small icon, which a window never sets directly.
pub const ICON_SMALL2: u64 = 2;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WindowIcons { pub big: u64, pub small: u64, pub small2: u64 }

/// What installing one icon asks the caller to do besides storing the record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IconSideEffect {
    /// Nothing beyond the stored record.
    None,
    /// Derive the small icon from this large one.
    DeriveSmall(u64),
    /// Release the derived small icon; it is no longer reachable.
    ReleaseDerived(u64),
}

/// Apply one icon installation, answering the replaced icon, the new record
/// and the derived-icon work the caller owes. # C: O(1)
pub fn set_icon(icons: WindowIcons, kind: u64, icon: u64) -> Option<(u64, WindowIcons, IconSideEffect)> {
    let mut next = icons;
    let (previous, effect) = match kind {
        ICON_SMALL => {
            let previous = icons.small;
            let effect = if previous != 0 && icon == 0 && icons.big != 0 { IconSideEffect::DeriveSmall(icons.big) }
                else if icon != 0 && icons.small2 != 0 { IconSideEffect::ReleaseDerived(icons.small2) }
                else { IconSideEffect::None };
            if matches!(effect, IconSideEffect::ReleaseDerived(_)) { next.small2 = 0; }
            next.small = icon;
            (previous, effect)
        }
        ICON_BIG => {
            let previous = icons.big;
            let mut effect = IconSideEffect::None;
            if icons.small2 != 0 { effect = IconSideEffect::ReleaseDerived(icons.small2); next.small2 = 0; }
            else if icon != 0 && icons.small == 0 { effect = IconSideEffect::DeriveSmall(icon); }
            next.big = icon;
            (previous, effect)
        }
        _ => return None,
    };
    Some((previous, next, effect))
}

/// Icon one window reports for a request kind. # C: O(1)
pub const fn get_icon(icons: WindowIcons, kind: u64) -> u64 {
    match kind {
        ICON_SMALL => icons.small,
        ICON_BIG => icons.big,
        ICON_SMALL2 => if icons.small != 0 { icons.small } else { icons.small2 },
        _ => 0,
    }
}

/// Per-window icon records.
#[derive(Default)]
pub struct WindowIconTable { entries: Vec<(WindowId, WindowIcons)> }

impl WindowIconTable {
    /// # C: O(1)
    pub const fn new() -> Self { Self { entries: Vec::new() } }
    /// # C: O(N_entries)
    pub fn get(&self, id: WindowId) -> WindowIcons {
        self.entries.iter().find(|(window, _)| *window == id).map_or(WindowIcons::default(), |(_, icons)| *icons)
    }
    /// # C: O(N_entries)
    pub fn set(&mut self, id: WindowId, icons: WindowIcons) {
        if let Some((_, slot)) = self.entries.iter_mut().find(|(window, _)| *window == id) { *slot = icons; return; }
        if self.entries.try_reserve(1).is_err() { return; }
        self.entries.push((id, icons));
    }
    /// # C: O(N_entries)
    pub fn remove(&mut self, id: WindowId) { self.entries.retain(|(window, _)| *window != id); }
}

impl WindowManager {
    /// # C: O(N_windows + N_icon_entries)
    pub fn window_icons(&self, id: WindowId) -> WindowIcons { self.icons.get(id) }

    /// Install one window icon, answering the replaced icon and the derived
    /// work the caller owes. # C: O(N_windows + N_icon_entries)
    pub fn set_window_icon(&mut self, id: WindowId, kind: u64, icon: u64) -> Option<(u64, IconSideEffect)> {
        self.get(id)?;
        let (previous, next, effect) = set_icon(self.icons.get(id), kind, icon)?;
        self.icons.set(id, next);
        Some((previous, effect))
    }

    /// Record the derived small icon of one window. # C: O(N_icon_entries)
    pub fn set_derived_window_icon(&mut self, id: WindowId, icon: u64) {
        let mut icons = self.icons.get(id);
        icons.small2 = icon;
        self.icons.set(id, icons);
    }

    /// # C: O(N_windows + N_icon_entries)
    pub fn window_icon(&self, id: WindowId, kind: u64) -> u64 { get_icon(self.icons.get(id), kind) }
}

#[cfg(test)]
#[path = "tests/window_icon.rs"]
mod tests;
