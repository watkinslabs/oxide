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
