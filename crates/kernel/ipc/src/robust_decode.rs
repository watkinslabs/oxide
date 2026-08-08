// Robust-futex list decoding and the death-handler's branch ladder.
//
// Non-gated: `live::futex::robust` is kernel-only, and these rules decide
// whether a dying thread's peers are released or stranded forever.
//
// The bug this closes: the walk required every fetched `robust_list` pointer to
// be 8-aligned and aborted otherwise. Linux tags PI robust mutexes by setting
// BIT 0 of the list pointer (`FUTEX_ROBUST_MOD_PI`), so a single PI entry made
// the pointer odd and killed the whole walk — every robust mutex after it on
// the list stayed owned by a dead thread, silently, with its waiters blocked.

/// `sizeof(struct robust_list_head)` on a 64-bit ABI: `robust_list list` (8) +
/// `long futex_offset` (8) + `robust_list *list_op_pending` (8). ABI-fixed:
/// `set_robust_list(2)` accepts NO other length, and `get_robust_list(2)`
/// reports THIS constant — never the length the caller happened to register.
pub const ROBUST_LIST_HEAD_SIZE: u64 = 24;

/// Bit 0 of a `robust_list` pointer tags a PI futex.
pub const FUTEX_ROBUST_MOD_PI: u64 = 0x1;
/// Mask covering all tag bits packed into a `robust_list` pointer.
pub const FUTEX_ROBUST_MOD_MASK: u64 = FUTEX_ROBUST_MOD_PI;

/// A decoded `robust_list` pointer: the address with tag bits split out.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RobustPtr {
    /// The pointer with the mod bits cleared.
    pub addr: u64,
    /// `uentry & FUTEX_ROBUST_MOD_MASK`.
    pub mod_bits: u64,
}

impl RobustPtr {
    /// Split a raw fetched pointer word into its clean address and its tag
    /// bits. # C: O(1)
    pub const fn decode(uentry: u64) -> Self {
        Self { addr: uentry & !FUTEX_ROBUST_MOD_MASK, mod_bits: uentry & FUTEX_ROBUST_MOD_MASK }
    }

    /// True when the PI tag bit is set. # C: O(1)
    pub const fn pi(self) -> bool { self.mod_bits & FUTEX_ROBUST_MOD_PI != 0 }
}

/// Which list position an entry was reached from: the ordinary `list` chain,
/// or the single in-flight `list_op_pending` slot.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeathSite {
    /// Walked off `head->list`.
    List,
    /// Reached via `head->list_op_pending`.
    Pending,
}

/// What the death handler does with one robust word.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DeathAction {
    /// Wake a potential waiter WITHOUT touching the word.
    WakeOnly,
    /// cmpxchg OWNER_DIED in, then wake if non-PI.
    SetOwnerDied,
    /// `owner != task_pid_vnr(curr)` — not ours.
    Skip,
}

/// The robust-death branch ladder, evaluated in this exact order.
///
/// The `WakeOnly` case is subtle and is why `pending_op` and `pi` both have to
/// be threaded down here: a REGULAR futex reached through `list_op_pending`
/// whose owner field is already zero means userspace released the lock and was
/// killed before it could issue the waking `futex()` call. Waking without
/// setting OWNER_DIED is correct there — if the futex value is zero, the rest
/// of the user space mutex state is consistent, so a woken waiter will just
/// take over the uncontended futex; setting the OWNER_DIED bit would create
/// inconsistent state. A PI futex never takes this path.
/// # C: O(1)
pub const fn death_verdict(owner: u32, curr_tid: u32, pi: bool, site: DeathSite) -> DeathAction {
    if matches!(site, DeathSite::Pending) && !pi && owner == 0 { return DeathAction::WakeOnly; }
    if owner != curr_tid { return DeathAction::Skip; }
    DeathAction::SetOwnerDied
}

#[cfg(test)]
mod tests {
    use super::*;

    const TID: u32 = 0x1234;

    #[test]
    fn a_pi_tagged_entry_decodes_instead_of_aborting_the_walk() {
        // THE bug: glibc tags a PI robust mutex by setting bit 0 of the list
        // pointer, making it odd. The old walk demanded 8-alignment and bailed,
        // stranding every later entry.
        let p = RobustPtr::decode(0x7fff_dead_b000 | FUTEX_ROBUST_MOD_PI);
        assert_eq!(p.addr, 0x7fff_dead_b000);
        assert!(p.pi());
    }

    #[test]
    fn a_plain_entry_has_no_mod_bits() {
        let p = RobustPtr::decode(0x7fff_dead_b000);
        assert_eq!(p.addr, 0x7fff_dead_b000);
        assert!(!p.pi());
        assert_eq!(p.mod_bits, 0);
    }

    #[test]
    fn decoding_never_shifts_the_address() {
        // Only bit 0 is a tag; every other bit is address.
        for raw in [0u64, 1, 0x8, 0x9, 0xffff_ffff_ffff_fffe, 0xffff_ffff_ffff_ffff] {
            let p = RobustPtr::decode(raw);
            assert_eq!(p.addr, raw & !1);
            assert_eq!(p.pi(), raw & 1 != 0);
        }
    }

    #[test]
    fn a_word_owned_by_another_thread_is_skipped() {
        assert_eq!(death_verdict(TID + 1, TID, false, DeathSite::List), DeathAction::Skip);
        assert_eq!(death_verdict(TID + 1, TID, true, DeathSite::Pending), DeathAction::Skip);
    }

    #[test]
    fn a_word_we_own_gets_owner_died() {
        assert_eq!(death_verdict(TID, TID, false, DeathSite::List), DeathAction::SetOwnerDied);
        assert_eq!(death_verdict(TID, TID, true, DeathSite::List), DeathAction::SetOwnerDied);
        assert_eq!(death_verdict(TID, TID, false, DeathSite::Pending), DeathAction::SetOwnerDied);
    }

    #[test]
    fn a_released_pending_regular_futex_is_woken_without_setting_owner_died() {
        // WakeOnly requires all three: pending_op && !pi && owner == 0.
        assert_eq!(death_verdict(0, TID, false, DeathSite::Pending), DeathAction::WakeOnly);
    }

    #[test]
    fn the_wake_only_case_needs_all_three_conditions() {
        // A PI futex never takes it (condition 3: "Regular futex: @pi == false").
        assert_eq!(death_verdict(0, TID, true, DeathSite::Pending), DeathAction::Skip);
        // Nor does a plain list entry, however zero its owner field.
        assert_eq!(death_verdict(0, TID, false, DeathSite::List), DeathAction::Skip);
        // Nor one whose owner field is a real, different tid.
        assert_eq!(death_verdict(TID + 1, TID, false, DeathSite::Pending), DeathAction::Skip);
    }

    #[test]
    fn a_zero_owner_word_owned_by_tid_zero_is_still_skipped_off_the_list() {
        // Guards against a decode that lets curr_tid == 0 match an unowned word.
        assert_eq!(death_verdict(0, 0, false, DeathSite::List), DeathAction::SetOwnerDied);
        assert_eq!(death_verdict(0, 0, false, DeathSite::Pending), DeathAction::WakeOnly);
    }
}
