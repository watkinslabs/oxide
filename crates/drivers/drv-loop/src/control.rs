//! `/dev/loop-control`: which loop numbers exist, and which may go away.
//!
//! The index decisions are pure over a set of (number, state) pairs, so the
//! whole `ADD` / `REMOVE` / `GET_FREE` contract is decided and tested without
//! a device, a file or a block registry.

use alloc::vec::Vec;
use syscall::errno::Errno;

/// Where a loop device is in its lifecycle. The reference distinguishes these
/// because they answer `REMOVE` differently: only an unbound device with no
/// openers may be taken away.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum State {
    /// Exists, no backing file.
    Unbound,
    /// Has a backing file.
    Bound,
    /// Being torn down; no longer a candidate for anything.
    Deleting,
}

/// One entry of the index `/dev/loop-control` acts on.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Entry {
    pub number: u32,
    pub state: State,
    /// Descriptions currently open on the device.
    pub openers: u32,
}

/// What an index request resolves to. Kept separate from performing it so the
/// decision is testable and the caller owns the mutation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Action {
    /// Create this number.
    Add(u32),
    /// Destroy this number.
    Remove(u32),
    /// Report this number without changing anything.
    Report(u32),
}

/// `LOOP_CTL_ADD`: create the named device.
///
/// A negative number is not a request the reference accepts here — unlike
/// `GET_FREE`, `ADD` names exactly one device — and a number that already
/// exists is `EEXIST` rather than a silent success, so a caller that races
/// another can tell which of them created it.
/// # C: O(N)
pub fn add(index: &[Entry], requested: i64) -> Result<Action, Errno> {
    if requested < 0 || requested > u32::MAX as i64 { return Err(Errno::Einval); }
    let number = requested as u32;
    if index.iter().any(|e| e.number == number) { return Err(Errno::Eexist); }
    Ok(Action::Add(number))
}

/// `LOOP_CTL_REMOVE`: destroy the named device.
///
/// Unspecified removal is refused: the reference will not pick a victim. A
/// device that does not exist is `ENODEV`; one that is bound or open is
/// `EBUSY`, and the busy check comes second so a caller asking about a
/// device that was never there is told that, not that it is busy.
/// # C: O(N)
pub fn remove(index: &[Entry], requested: i64) -> Result<Action, Errno> {
    if requested < 0 || requested > u32::MAX as i64 { return Err(Errno::Einval); }
    let number = requested as u32;
    let entry = index.iter().find(|e| e.number == number).ok_or(Errno::Enodev)?;
    if entry.state != State::Unbound || entry.openers > 0 { return Err(Errno::Ebusy); }
    Ok(Action::Remove(number))
}

/// `LOOP_CTL_GET_FREE`: report an unbound device, creating one if every
/// existing device is in use.
///
/// The lowest free number is reported so repeated calls are stable, and a
/// device being torn down is never offered. When none is free the new number
/// is the lowest unused one, which keeps `/dev` dense rather than climbing
/// forever.
/// # C: O(N log N)
pub fn get_free(index: &[Entry]) -> Result<Action, Errno> {
    let mut free: Vec<u32> = index.iter()
        .filter(|e| e.state == State::Unbound && e.openers == 0)
        .map(|e| e.number).collect();
    free.sort_unstable();
    if let Some(number) = free.first() { return Ok(Action::Report(*number)); }
    Ok(Action::Add(lowest_unused(index)))
}

/// Lowest number no entry holds. # C: O(N log N)
pub fn lowest_unused(index: &[Entry]) -> u32 {
    let mut taken: Vec<u32> = index.iter().map(|e| e.number).collect();
    taken.sort_unstable();
    let mut candidate = 0u32;
    for number in taken {
        if number > candidate { break; }
        if number == candidate { candidate = candidate.saturating_add(1); }
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(number: u32, state: State, openers: u32) -> Entry { Entry { number, state, openers } }

    #[test]
    fn add_creates_a_named_device_and_refuses_a_duplicate() {
        let index = [e(0, State::Unbound, 0)];
        assert_eq!(add(&index, 1), Ok(Action::Add(1)));
        assert_eq!(add(&index, 0), Err(Errno::Eexist));
        assert_eq!(add(&index, -1), Err(Errno::Einval), "ADD names exactly one device");
    }

    /// Removal refuses in a fixed order: a device that never existed reports
    /// that, even though it is also not removable.
    #[test]
    fn remove_reports_absent_before_busy() {
        let index = [e(0, State::Bound, 1), e(1, State::Unbound, 0)];
        assert_eq!(remove(&index, 7), Err(Errno::Enodev));
        assert_eq!(remove(&index, 0), Err(Errno::Ebusy), "bound");
        assert_eq!(remove(&index, 1), Ok(Action::Remove(1)));
        assert_eq!(remove(&index, -1), Err(Errno::Einval), "will not pick a victim");
    }

    /// An unbound device with an opener is still busy — a caller holding it
    /// open would otherwise lose the device underneath its descriptor.
    #[test]
    fn an_open_unbound_device_is_busy() {
        assert_eq!(remove(&[e(3, State::Unbound, 1)], 3), Err(Errno::Ebusy));
        assert_eq!(remove(&[e(3, State::Deleting, 0)], 3), Err(Errno::Ebusy));
    }

    /// `GET_FREE` reports the lowest free device, so repeated calls with no
    /// intervening bind are stable rather than wandering.
    #[test]
    fn get_free_reports_the_lowest_free_device() {
        let index = [e(0, State::Bound, 1), e(2, State::Unbound, 0), e(1, State::Unbound, 0)];
        assert_eq!(get_free(&index), Ok(Action::Report(1)));
        assert_eq!(get_free(&index), Ok(Action::Report(1)), "stable");
    }

    /// With every device in use it creates one, and the number it picks fills
    /// the lowest hole rather than climbing past the existing devices.
    #[test]
    fn get_free_creates_and_fills_the_lowest_hole() {
        let all_bound = [e(0, State::Bound, 1), e(1, State::Bound, 1)];
        assert_eq!(get_free(&all_bound), Ok(Action::Add(2)));
        let with_hole = [e(0, State::Bound, 1), e(2, State::Bound, 1), e(3, State::Bound, 0)];
        assert_eq!(get_free(&with_hole), Ok(Action::Add(1)));
        assert_eq!(get_free(&[]), Ok(Action::Add(0)));
    }

    /// A device being torn down is not offered as free, or two callers would
    /// be handed the device that is going away.
    #[test]
    fn a_deleting_device_is_never_offered() {
        assert_eq!(get_free(&[e(0, State::Deleting, 0)]), Ok(Action::Add(1)));
    }

    /// An unbound device someone holds open is not free either: binding it
    /// would change the backing store under that descriptor.
    #[test]
    fn an_open_unbound_device_is_not_free() {
        assert_eq!(get_free(&[e(0, State::Unbound, 2)]), Ok(Action::Add(1)));
    }

    #[test]
    fn the_lowest_unused_number_fills_holes_in_order() {
        assert_eq!(lowest_unused(&[]), 0);
        assert_eq!(lowest_unused(&[e(0, State::Unbound, 0)]), 1);
        assert_eq!(lowest_unused(&[e(1, State::Unbound, 0)]), 0);
        assert_eq!(lowest_unused(&[e(0, State::Unbound, 0), e(1, State::Unbound, 0), e(3, State::Unbound, 0)]), 2);
    }
}
