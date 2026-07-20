//! PageMeta reclaim-state decoding. Queue links remain an index in
//! `pmm::reclaim`; this is the only per-page membership truth.

use super::PageFlags;

/// Canonical reclaim state encoded in one `PageMeta.flags` word.
///
/// `OnLru` and `Isolated` are mutually exclusive. `Unevictable` is always an
/// LRU state and never active. The decoder deliberately represents invalid
/// flag combinations so callers can reject corruption rather than inventing
/// a recovery state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ReclaimPageState {
    NotOnLru,
    OnLru { active: bool, unevictable: bool },
    Isolated { active: bool },
    Invalid,
}

/// Decode the reclaim ownership bits without treating the queue as a second
/// source of truth. # C: O(1)
pub fn reclaim_state(flags: PageFlags) -> ReclaimPageState {
    let lru = flags.contains(PageFlags::LRU);
    let active = flags.contains(PageFlags::ACTIVE);
    let unevictable = flags.contains(PageFlags::UNEVICTABLE);
    let isolated = flags.contains(PageFlags::ISOLATED);
    match (lru, active, unevictable, isolated) {
        (false, false, false, false) => ReclaimPageState::NotOnLru,
        (true, active, false, false) => ReclaimPageState::OnLru { active, unevictable: false },
        (true, false, true, false) => ReclaimPageState::OnLru { active: false, unevictable: true },
        (false, active, false, true) => ReclaimPageState::Isolated { active },
        _ => ReclaimPageState::Invalid,
    }
}
