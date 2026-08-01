// PI-futex user-word transition rules — the ladders `FUTEX_LOCK_PI`,
// `FUTEX_UNLOCK_PI` and the owner-death handoff apply to the 32-bit futex word.
//
// Non-gated so every transition and every errno is hosted-tested; the live
// module (`live::futex::pi`) owns the locking, parking and boosting and calls
// these for each word decision. Getting one of these wrong does not produce a
// visible error — it produces a `PTHREAD_PRIO_INHERIT` mutex whose owner field
// disagrees with the kernel's, which userspace then treats as corrupt state.

use syscall::errno::Errno;

/// Set while at least one task is blocked in the kernel on this futex. Once PI
/// state exists the bit stays set through every handoff, so a userspace fast
/// path can never take the lock behind the kernel's back.
pub const FUTEX_WAITERS: u32 = 0x8000_0000;
/// Set by the kernel when the owning thread died holding the mutex. Userspace
/// (glibc) turns this into `EOWNERDEAD` from `pthread_mutex_lock`.
pub const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
/// The owner's TID occupies the low 30 bits.
pub const FUTEX_TID_MASK: u32 = 0x3fff_ffff;

/// What the caller must do next to acquire a PI futex, per Linux
/// `futex_lock_pi_atomic`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PiLockStep {
    /// No kernel PI state and the word carries no owner: compare-exchange
    /// `uval -> newval`. On success the caller owns the mutex outright and
    /// returns to userspace without blocking.
    TakeUncontended { newval: u32 },
    /// The word names a live owner and there is no kernel PI state yet: publish
    /// `FUTEX_WAITERS` so the owner is forced into the kernel to unlock, then
    /// attach to `owner_tid` as the first waiter.
    PublishWaitersThenAttach { newval: u32, owner_tid: u32 },
    /// Kernel PI state already exists for this key; queue on it. No word write
    /// is needed — `FUTEX_WAITERS` is already set and stays set for as long as
    /// PI state lives.
    AttachExisting,
}

/// Whether the futex word's alleged owner could be found.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OwnerLookup {
    /// A live, non-kernel task with that TID exists.
    Alive,
    /// The TID names a kernel thread. A kernel thread never takes a userspace
    /// PI mutex, so the word is userspace-corrupted.
    KernelThread,
    /// The task is between "started exiting" and "finished its futex cleanup".
    /// The caller must let the exit complete and retry rather than declare the
    /// mutex unowned, or two tasks race to become owner.
    Exiting,
    /// No such task.
    Gone,
}

/// Linux `futex_lock_pi_atomic`, in its own order: deadlock check first (so a
/// self-relock is `EDEADLK` even when kernel state exists), then existing PI
/// state, then the unowned word, then the first-waiter path.
///
/// `set_waiters` is the requeue-PI caller's demand that the acquired word carry
/// `FUTEX_WAITERS` even when uncontended, because a waiter is about to be
/// requeued onto it.
/// # C: O(1)
pub fn lock_pi_step(uval: u32, vpid: u32, have_pi_state: bool, set_waiters: bool)
    -> Result<PiLockStep, Errno>
{
    if uval & FUTEX_TID_MASK == vpid { return Err(Errno::Edeadlk); }
    if have_pi_state { return Ok(PiLockStep::AttachExisting); }
    if uval & FUTEX_TID_MASK == 0 {
        // Take over the futex. The owner-died bit is PRESERVED: the next owner
        // must still learn the previous one died, which is what turns into
        // `EOWNERDEAD` and forces a consistency check in userspace.
        let mut newval = (uval & FUTEX_OWNER_DIED) | vpid;
        if set_waiters { newval |= FUTEX_WAITERS; }
        return Ok(PiLockStep::TakeUncontended { newval });
    }
    Ok(PiLockStep::PublishWaitersThenAttach {
        newval: uval | FUTEX_WAITERS,
        owner_tid: uval & FUTEX_TID_MASK,
    })
}

/// Classify an owner lookup for the `PublishWaitersThenAttach` step
/// (`attach_to_pi_owner` + `handle_exit_race`).
///
/// `word_changed` is whether a re-read of the futex word still equals the value
/// the decision was made on. An exiting owner that already ran its robust-list
/// cleanup rewrote the word, and reporting `ESRCH` on that is wrong — the state
/// is simply stale, so the caller retries.
/// # C: O(1)
pub fn attach_owner_result(lookup: OwnerLookup, word_changed: bool) -> Result<(), Errno> {
    match lookup {
        OwnerLookup::Alive => Ok(()),
        OwnerLookup::KernelThread => Err(Errno::Eperm),
        // The owner is mid-exit: it still owns the mutex and will hand it over
        // when its cleanup runs. Retry rather than steal it.
        OwnerLookup::Exiting => Err(Errno::Eagain),
        OwnerLookup::Gone if word_changed => Err(Errno::Eagain),
        // No such task and the word still names it: the owner died without a
        // robust list, or userspace wrote a bogus TID. Tell userspace.
        OwnerLookup::Gone => Err(Errno::Esrch),
    }
}

/// The word an unlocking owner writes when handing the mutex to `new_owner_tid`
/// — Linux `wake_futex_pi`.
///
/// `FUTEX_WAITERS` is unconditionally set: PI state still exists (the new owner
/// is in it), so userspace must keep coming through the kernel to unlock.
/// `FUTEX_OWNER_DIED` is cleared, because the task performing this handoff is
/// alive and owns the lock.
/// # C: O(1)
pub const fn handoff_word(new_owner_tid: u32) -> u32 { FUTEX_WAITERS | new_owner_tid }

/// The word written when the mutex is handed on because its owner DIED —
/// Linux `__fixup_pi_state_owner`'s `newtid` with `pi_state->owner == NULL`.
/// Same as [`handoff_word`] plus the sticky owner-died bit, and it preserves an
/// owner-died bit already present in `uval`.
/// # C: O(1)
pub const fn dead_owner_handoff_word(uval: u32, new_owner_tid: u32) -> u32 {
    (uval & FUTEX_OWNER_DIED) | FUTEX_WAITERS | FUTEX_OWNER_DIED | new_owner_tid
}

/// The word written when the owner dies and NO task is waiting — Linux
/// `handle_futex_death`'s `mval`. The TID is dropped (the mutex is now
/// ownerless) and `FUTEX_WAITERS` is preserved so a waiter that is mid-enqueue
/// still forces the next locker through the kernel.
/// # C: O(1)
pub const fn owner_died_word(uval: u32) -> u32 { (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED }

/// `wake_futex_pi`'s failure classification when the compare-exchange lost.
///
/// A userspace unlock fast path that raced a waiter setting `FUTEX_WAITERS`
/// leaves `curval == uval | FUTEX_WAITERS`, which is benign and retried
/// (`EAGAIN`). Anything else means userspace wrote the word behind the kernel's
/// back, which is unrecoverable state (`EINVAL`).
/// # C: O(1)
pub const fn handoff_race(uval: u32, curval: u32) -> Errno {
    if curval & FUTEX_TID_MASK == uval { Errno::Eagain } else { Errno::Einval }
}

/// `futex_unlock_pi`'s ownership gate: only the task whose TID is in the word
/// may unlock it.
/// # C: O(1)
pub const fn may_unlock(uval: u32, vpid: u32) -> Result<(), Errno> {
    if uval & FUTEX_TID_MASK == vpid { Ok(()) } else { Err(Errno::Eperm) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: u32 = 0x2a;
    const OTHER: u32 = 0x63;

    #[test]
    fn relocking_a_futex_this_task_already_owns_is_edeadlk() {
        assert_eq!(lock_pi_step(ME, ME, false, false), Err(Errno::Edeadlk));
        assert_eq!(lock_pi_step(FUTEX_WAITERS | ME, ME, true, false), Err(Errno::Edeadlk),
                   "the deadlock check runs before the kernel-state check");
    }

    #[test]
    fn an_unowned_word_is_taken_without_blocking() {
        assert_eq!(lock_pi_step(0, ME, false, false),
                   Ok(PiLockStep::TakeUncontended { newval: ME }));
    }

    #[test]
    fn taking_over_preserves_owner_died_so_userspace_still_sees_eownerdead() {
        assert_eq!(lock_pi_step(FUTEX_OWNER_DIED, ME, false, false),
                   Ok(PiLockStep::TakeUncontended { newval: FUTEX_OWNER_DIED | ME }));
    }

    #[test]
    fn requeue_pi_forces_the_waiters_bit_on_an_uncontended_take() {
        assert_eq!(lock_pi_step(0, ME, false, true),
                   Ok(PiLockStep::TakeUncontended { newval: FUTEX_WAITERS | ME }));
    }

    #[test]
    fn the_first_waiter_publishes_waiters_and_attaches_to_the_owner() {
        assert_eq!(lock_pi_step(OTHER, ME, false, false),
                   Ok(PiLockStep::PublishWaitersThenAttach {
                        newval: FUTEX_WAITERS | OTHER, owner_tid: OTHER }));
    }

    #[test]
    fn a_later_waiter_attaches_to_existing_state_without_touching_the_word() {
        assert_eq!(lock_pi_step(FUTEX_WAITERS | OTHER, ME, true, false),
                   Ok(PiLockStep::AttachExisting));
    }

    #[test]
    fn owner_lookup_errors_follow_the_exit_race_ladder() {
        assert_eq!(attach_owner_result(OwnerLookup::Alive, false), Ok(()));
        assert_eq!(attach_owner_result(OwnerLookup::KernelThread, false), Err(Errno::Eperm));
        assert_eq!(attach_owner_result(OwnerLookup::Exiting, false), Err(Errno::Eagain));
        assert_eq!(attach_owner_result(OwnerLookup::Gone, true), Err(Errno::Eagain),
                   "the exiting owner rewrote the word — stale state, retry, never ESRCH");
        assert_eq!(attach_owner_result(OwnerLookup::Gone, false), Err(Errno::Esrch));
    }

    #[test]
    fn a_handoff_keeps_the_waiters_bit_and_clears_owner_died() {
        assert_eq!(handoff_word(OTHER), FUTEX_WAITERS | OTHER);
        assert_eq!(handoff_word(OTHER) & FUTEX_OWNER_DIED, 0);
    }

    #[test]
    fn a_dead_owners_handoff_sets_owner_died_for_the_new_owner() {
        let w = dead_owner_handoff_word(FUTEX_WAITERS | ME, OTHER);
        assert_eq!(w & FUTEX_TID_MASK, OTHER);
        assert_ne!(w & FUTEX_OWNER_DIED, 0, "the new owner must see EOWNERDEAD");
        assert_ne!(w & FUTEX_WAITERS, 0);
    }

    #[test]
    fn an_uncontended_death_drops_the_tid_and_keeps_waiters() {
        assert_eq!(owner_died_word(ME), FUTEX_OWNER_DIED);
        assert_eq!(owner_died_word(FUTEX_WAITERS | ME), FUTEX_WAITERS | FUTEX_OWNER_DIED);
    }

    #[test]
    fn a_lost_handoff_cmpxchg_is_eagain_only_for_the_waiters_bit_race() {
        assert_eq!(handoff_race(ME, FUTEX_WAITERS | ME), Errno::Eagain);
        assert_eq!(handoff_race(ME, OTHER), Errno::Einval);
        assert_eq!(handoff_race(ME, 0), Errno::Einval);
    }

    #[test]
    fn only_the_recorded_owner_may_unlock() {
        assert_eq!(may_unlock(FUTEX_WAITERS | ME, ME), Ok(()));
        assert_eq!(may_unlock(FUTEX_WAITERS | OTHER, ME), Err(Errno::Eperm));
        assert_eq!(may_unlock(0, ME), Err(Errno::Eperm));
    }
}
