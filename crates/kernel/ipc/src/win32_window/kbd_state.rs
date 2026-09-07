//! Per-thread active keyboard layout.
//!
//! A thread that never activated a layout reports the layout derived from the
//! default user locale, with the locale in both halves of the handle.

use alloc::vec::Vec;
use super::{WindowManager, WindowId};

/// Default user locale: the layout every thread starts on.
pub const DEFAULT_LOCALE: u32 = 0x0409;
/// Characters in a layout name, including the terminator.
pub const KL_NAMELENGTH: usize = 9;
const HKL_PREV: u64 = 0;
const HKL_NEXT: u64 = 1;
const LANG_INVARIANT: u32 = 0x7f;
const SUBLANG_DEFAULT: u32 = 0x01;
/// Language id that names no locale, which a layout handle may carry.
const INVARIANT_LANGID: u32 = (SUBLANG_DEFAULT << 10) | LANG_INVARIANT;
const WM_INPUTLANGCHANGE: u32 = 0x0051;

/// Layout handle derived from one locale. # C: O(1)
pub const fn locale_layout(locale: u32) -> u64 { ((locale << 16) | (locale & 0xffff)) as u64 }

/// Layout name: the eight hexadecimal digits of the layout id, with a handle
/// whose halves agree collapsing to its low half. # C: O(1)
pub fn layout_name(layout: u64) -> Vec<u16> {
    let id = layout as u32;
    let id = if id >> 16 == id & 0xffff { id & 0xffff } else { id };
    let mut name = Vec::new();
    for shift in (0..8).rev() {
        let digit = (id >> (shift * 4)) & 0xf;
        name.push(if digit < 10 { b'0' as u16 + digit as u16 } else { b'A' as u16 + (digit - 10) as u16 });
    }
    name
}

/// Why a layout activation was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    /// Relative activation, and changing the user locale, are not layouts this
    /// owner can select.
    NotImplemented,
}

/// Decide one activation. Answers the layout to install; a request naming a
/// locale other than the user's, or a relative step, is refused. # C: O(1)
pub fn activate_layout(layout: u64, locale: u32) -> Result<u64, LayoutError> {
    if layout == HKL_NEXT || layout == HKL_PREV { return Err(LayoutError::NotImplemented); }
    let low = layout as u32 & 0xffff;
    if low != INVARIANT_LANGID && low != locale { return Err(LayoutError::NotImplemented); }
    Ok(layout)
}

impl WindowManager {
    /// Active layout of one thread. # C: O(N_layouts)
    pub fn keyboard_layout(&self, tid: u64) -> u64 {
        self.layouts.iter().find(|(owner, _)| *owner == tid).map_or(locale_layout(DEFAULT_LOCALE), |(_, layout)| *layout)
    }

    /// Install one thread's layout and answer the previous one. A thread that
    /// had none reports the locale layout. The focused window of the calling
    /// thread is told with WM_INPUTLANGCHANGE when the layout actually changes.
    /// # C: O(N_layouts + N_windows)
    pub fn activate_keyboard_layout(&mut self, tid: u64, layout: u64) -> Result<u64, LayoutError> {
        let installed = activate_layout(layout, DEFAULT_LOCALE)?;
        let stored = self.layouts.iter().position(|(owner, _)| *owner == tid);
        let previous = stored.map(|index| self.layouts[index].1);
        if previous != Some(installed) {
            if let Some(index) = stored { self.layouts[index].1 = installed; }
            else {
                if self.layouts.try_reserve(1).is_err() { return Err(LayoutError::NotImplemented); }
                self.layouts.push((tid, installed));
            }
            self.notify_layout_change(tid, installed);
        }
        Ok(previous.unwrap_or_else(|| locale_layout(DEFAULT_LOCALE)))
    }

    /// # C: O(N_windows + N_queues)
    fn notify_layout_change(&mut self, tid: u64, layout: u64) {
        let Some(focus) = self.focus_window().filter(|id| self.get(*id).is_some_and(|record| record.owner_tid == tid)) else { return; };
        let message = super::WinMessage { hwnd: Some(focus), message: WM_INPUTLANGCHANGE, wparam: 0, lparam: layout as i64 };
        let _ = self.post_to_window(focus, message);
    }

    /// Layouts the desktop offers. The locale layout is always present.
    /// # C: O(N_layouts)
    pub fn keyboard_layout_list(&self) -> Vec<u64> {
        let mut list = alloc::vec![locale_layout(DEFAULT_LOCALE)];
        for (_, layout) in &self.layouts { if !list.contains(layout) { list.push(*layout); } }
        list
    }

    /// # C: O(N_windows)
    fn focus_window(&self) -> Option<WindowId> { self.focus }
}

#[cfg(test)]
#[path = "tests/kbd_state.rs"]
mod tests;
