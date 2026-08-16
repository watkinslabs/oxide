// The station state ladder.
//
// A station climbs and descends one step at a time. The rule is not
// bookkeeping: each step is where a driver is told, where keys become usable,
// and where the controlled port opens, and a jump skips whichever of those
// sits on the step that was passed over. A station that went straight from
// "known" to "authorized" would have an open port and no key.

use crate::ops::StaState;

/// The step above this one, if there is one. # C: O(1)
pub fn up(state: StaState) -> Option<StaState> {
    Some(match state {
        StaState::NotExist => StaState::None,
        StaState::None => StaState::Auth,
        StaState::Auth => StaState::Assoc,
        StaState::Assoc => StaState::Authorized,
        StaState::Authorized => return None,
    })
}

/// The step below this one, if there is one. # C: O(1)
pub fn down(state: StaState) -> Option<StaState> {
    Some(match state {
        StaState::Authorized => StaState::Assoc,
        StaState::Assoc => StaState::Auth,
        StaState::Auth => StaState::None,
        StaState::None => StaState::NotExist,
        StaState::NotExist => return None,
    })
}

/// Whether one transition is a single step. # C: O(1)
pub fn is_single_step(old: StaState, new: StaState) -> bool {
    up(old) == Some(new) || down(old) == Some(new)
}

/// The sequence of single steps that takes a station from `old` to `new`.
/// A caller that wants to move a station several steps walks this rather than
/// assigning the end state, so every intermediate step's side effects happen.
/// # C: O(steps)
pub fn steps(old: StaState, new: StaState) -> impl Iterator<Item = (StaState, StaState)> {
    let mut cur = old;
    core::iter::from_fn(move || {
        if cur == new { return None; }
        let next = if cur < new { up(cur)? } else { down(cur)? };
        let step = (cur, next);
        cur = next;
        Some(step)
    })
}

/// Whether a station at this state may send or receive data frames. Only the
/// top step may: the association exchange completing is not the same event as
/// the controlled port opening, and on a protected network there is a whole
/// key exchange between them. # C: O(1)
pub fn data_allowed(state: StaState) -> bool { state == StaState::Authorized }

/// Whether a station at this state is associated, so it counts against the
/// interface's station limit and appears in a station dump. # C: O(1)
pub fn is_associated(state: StaState) -> bool { state >= StaState::Assoc }

/// Whether a station at this state may have keys installed against it.
/// # C: O(1)
pub fn keys_allowed(state: StaState) -> bool { state >= StaState::Auth }
