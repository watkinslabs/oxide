//! How many paint traces one window is worth.
//!
//! A paint trace is bounded because every console line costs serial time
//! inside the message pump it is measuring. A bound spent by whichever
//! windows painted first is an instrument that goes silent exactly when
//! something new appears: a dialog opened a minute into a session traced
//! nothing at all, and its silence was read as a dialog that never painted.
//! The budget is per window, so a window that has just been created reports
//! its first paints whatever the windows before it spent.
use core::sync::atomic::{AtomicU64, Ordering};

/// Windows the table remembers at once. A window whose slot is taken by
/// another is traced again from the start rather than staying silent.
pub(crate) const SLOTS: usize = 64;
/// Traces one window is worth: enough to carry a create, a first paint and
/// the repaints around it.
pub(crate) const PER_WINDOW: u32 = 8;

/// The slot a window's budget is kept in. # C: O(1)
pub(crate) const fn slot_of(hwnd: u32) -> usize { hwnd as usize % SLOTS }

/// Whether one trace is emitted, and what the slot holds afterwards. A slot
/// holding another window is taken over: the window that owned it has had its
/// traces and the new one has had none. # C: O(1)
pub(crate) const fn admit(slot: (u32, u32), hwnd: u32, per_window: u32) -> (bool, (u32, u32)) {
    if slot.0 != hwnd { return (true, (hwnd, 1)); }
    if slot.1 >= per_window { return (false, slot); }
    (true, (hwnd, slot.1 + 1))
}

/// The per-window budgets, packed as the window in the high half and its
/// spend in the low half.
static SPENT: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];

/// Take one trace out of a window's budget. A racing pair of paints can spend
/// the same unit twice; a trace is not a counter. # C: O(1)
pub(crate) fn take(hwnd: u32) -> bool {
    let cell = &SPENT[slot_of(hwnd)];
    let held = cell.load(Ordering::Relaxed);
    let (emit, next) = admit(((held >> 32) as u32, held as u32), hwnd, PER_WINDOW);
    if emit { cell.store(u64::from(next.0) << 32 | u64::from(next.1), Ordering::Relaxed); }
    emit
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One window spends its own budget and nobody else's.
    #[test]
    fn a_window_spends_its_own_budget_and_goes_quiet_at_the_end_of_it() {
        let mut slot = (0, 0);
        for _ in 0..PER_WINDOW {
            let (emit, next) = admit(slot, 7, PER_WINDOW);
            assert!(emit); slot = next;
        }
        assert_eq!(admit(slot, 7, PER_WINDOW), (false, slot));
    }

    /// A window created after another has spent its budget is traced from the
    /// start: the silence of a spent budget is what read as a window that
    /// never painted.
    #[test]
    fn a_new_window_in_a_spent_slot_is_traced_from_the_start() {
        let spent = (7, PER_WINDOW);
        assert_eq!(admit(spent, 7, PER_WINDOW), (false, spent));
        let (emit, next) = admit(spent, 8, PER_WINDOW);
        assert!(emit, "a window that has spent nothing is never silent");
        assert_eq!(next, (8, 1));
    }

    /// Distinct windows keep distinct budgets until the table wraps.
    #[test]
    fn the_table_keeps_one_budget_for_each_window_it_holds() {
        assert_ne!(slot_of(1), slot_of(2));
        assert_eq!(slot_of(1), slot_of(1 + SLOTS as u32));
        assert!(take(0x1001));
        for _ in 1..PER_WINDOW { assert!(take(0x1001)); }
        assert!(!take(0x1001));
        assert!(take(0x1002), "another window's budget is its own");
        assert!(take(0x1001 + SLOTS as u32), "a window taking over a spent slot is traced");
    }
}
