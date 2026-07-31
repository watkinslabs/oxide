// POSIX timer slot table policy: id allocation and lookup.
// Linux keeps one `k_itimer` per timer in a slab, addressed by an id from
// `posix_timer_add()`; a deleted timer frees its id for reuse. This module owns
// the equivalent decisions over the thread group's slot vector so they stay
// hosted-testable, away from the kernel-only syscall glue.

use crate::timer_model::PosixTimer;

/// Ceiling on live+free slots per process. Linux has no per-process cap — it
/// allocates from `posix_timers_cache` until the allocation fails, returning
/// EAGAIN — but every armed slot is walked by the timer IRQ, so an unbounded
/// table is an interrupt-latency hazard rather than a memory one. Beyond this,
/// `timer_create` reports Linux's own allocation-failure errno.
pub const MAX_SLOTS: usize = 1024;

/// Free slot for a new timer, growing the table when every slot is live.
/// `None` = EAGAIN.
/// # C: O(SLOTS)
pub fn allocate_id(slots: &mut alloc::vec::Vec<PosixTimer>) -> Option<usize> {
    if let Some(id) = slots.iter().position(|timer| !timer.allocated) { return Some(id); }
    if slots.len() >= MAX_SLOTS { return None; }
    slots.push(PosixTimer::default());
    Some(slots.len() - 1)
}

/// Outcome of a `PR_TIMER_CREATE_RESTORE_IDS` id reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reserve {
    /// The requested id was free and is now this timer's.
    Taken(usize),
    /// Linux `posix_timer_add_at()` failure: the id names a live timer.
    Busy,
    /// The id is outside the table this process can hold. Linux's answer when
    /// no timer id could be allocated is EAGAIN, and the same slot ceiling
    /// already produces it for ordinary `timer_create`.
    NoSpace,
}

/// Reserve one EXACT id for `timer_create` while
/// `PR_TIMER_CREATE_RESTORE_IDS` is armed. Grows the table so a restore can
/// land above the current working set, which is the whole point of the
/// option — a checkpoint's ids are not dense from zero.
/// # C: O(id - SLOTS) on growth, else O(1)
pub fn allocate_id_at(slots: &mut alloc::vec::Vec<PosixTimer>, id: u32) -> Reserve {
    let id = id as usize;
    if id >= MAX_SLOTS { return Reserve::NoSpace; }
    if let Some(timer) = slots.get(id) {
        if timer.allocated { return Reserve::Busy; }
        return Reserve::Taken(id);
    }
    slots.resize(id + 1, PosixTimer::default());
    Reserve::Taken(id)
}

/// Resolve a user `timer_t`. Linux `lock_timer()` rejects any id outside
/// `0..=INT_MAX` before the hash lookup, and an id that names no timer of the
/// caller's own process is EINVAL.
/// # C: O(1)
pub fn slot_index(slots: &[PosixTimer], id: i64) -> Option<usize> {
    if id < 0 || id > i32::MAX as i64 { return None; }
    let id = id as usize;
    slots.get(id).filter(|timer| timer.allocated).map(|_| id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timer_model::{ClockSpec, Notify};

    fn table(n: usize) -> alloc::vec::Vec<PosixTimer> {
        alloc::vec![PosixTimer::default(); n]
    }

    fn live() -> PosixTimer {
        PosixTimer::allocate(ClockSpec::Monotonic, Notify::None)
    }

    #[test]
    fn ids_are_reused_lowest_first_after_delete() {
        let mut slots = table(PosixTimer::SLOTS);
        for expect in 0..PosixTimer::SLOTS {
            let id = allocate_id(&mut slots).unwrap();
            assert_eq!(id, expect);
            slots[id] = live();
        }
        slots[3] = PosixTimer::default();
        assert_eq!(allocate_id(&mut slots), Some(3));
    }

    #[test]
    fn table_grows_past_the_initial_working_set_then_eagains_at_the_cap() {
        let mut slots = table(PosixTimer::SLOTS);
        for _ in 0..MAX_SLOTS {
            let id = allocate_id(&mut slots).expect("below the cap every create succeeds");
            slots[id] = live();
        }
        assert_eq!(slots.len(), MAX_SLOTS);
        assert_eq!(allocate_id(&mut slots), None, "cap reports Linux's EAGAIN");
    }

    #[test]
    fn restore_ids_reserve_an_exact_slot_and_grow_the_table_to_reach_it() {
        let mut slots = table(PosixTimer::SLOTS);
        // A sparse id above the working set is reachable — a checkpoint's
        // timer ids are not dense.
        let high = PosixTimer::SLOTS + 500;
        assert_eq!(allocate_id_at(&mut slots, high as u32), Reserve::Taken(high));
        assert_eq!(slots.len(), high + 1);
        slots[high] = live();
        assert_eq!(allocate_id_at(&mut slots, high as u32), Reserve::Busy,
                   "a live id is EBUSY, never silently re-used");
        // A free slot inside the grown table is still reservable.
        assert_eq!(allocate_id_at(&mut slots, 7), Reserve::Taken(7));
        // Past the per-process ceiling there is no id to hand out.
        assert_eq!(allocate_id_at(&mut slots, MAX_SLOTS as u32), Reserve::NoSpace);
        assert_eq!(allocate_id_at(&mut slots, u32::MAX), Reserve::NoSpace);
    }

    #[test]
    fn lookup_rejects_negative_out_of_range_and_free_ids() {
        let mut slots = table(PosixTimer::SLOTS);
        slots[2] = live();
        assert_eq!(slot_index(&slots, 2), Some(2));
        assert_eq!(slot_index(&slots, 0), None, "free slot is not a timer");
        assert_eq!(slot_index(&slots, -1), None);
        assert_eq!(slot_index(&slots, i32::MAX as i64 + 1), None);
        assert_eq!(slot_index(&slots, i64::MAX), None);
        assert_eq!(slot_index(&slots, PosixTimer::SLOTS as i64), None);
    }
}
