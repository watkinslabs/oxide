// Target-set resolution RULES shared by getpriority/setpriority (140/141)
// and ioprio_set/ioprio_get (251/252). Ungated on purpose: the decision
// logic must be hosted-testable, so the live registry walk stays in
// `priority_common` and every branch that can be wrong lives here.

/// `which` selector, in the getpriority(2) base (`PRIO_PROCESS` = 0).
/// ioprio_set(2)/ioprio_get(2) number the same three sets from 1, so they
/// map onto this enum by subtracting one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Which {
    /// One thread: `who` is a vpid, `who == 0` is the caller.
    Process,
    /// Every thread of every process in a process group.
    Pgrp,
    /// Every thread owned by one real uid.
    User,
}

/// PRIO_PROCESS. # C: O(1)
pub const PRIO_PROCESS: u64 = 0;
/// PRIO_PGRP. # C: O(1)
pub const PRIO_PGRP: u64 = 1;
/// PRIO_USER. # C: O(1)
pub const PRIO_USER: u64 = 2;

/// Decode a getpriority(2)-base `which`. A negative `int` arrives
/// sign-extended and fails the same upper bound Linux's `which < PRIO_PROCESS`
/// rejects. # C: O(1)
pub fn which_from_prio_base(which: u64) -> Option<Which> {
    match which {
        PRIO_PROCESS => Some(Which::Process),
        PRIO_PGRP => Some(Which::Pgrp),
        PRIO_USER => Some(Which::User),
        _ => None,
    }
}

/// IOPRIO_WHO_PROCESS. # C: O(1)
pub const IOPRIO_WHO_PROCESS: u64 = 1;
/// IOPRIO_WHO_PGRP. # C: O(1)
pub const IOPRIO_WHO_PGRP: u64 = 2;
/// IOPRIO_WHO_USER. # C: O(1)
pub const IOPRIO_WHO_USER: u64 = 3;

/// Decode an ioprio(2)-base `which`. The two families share one target
/// resolver, so the ioprio numbering is folded onto [`Which`] here rather
/// than by an open-coded `which - 1` at the call site. # C: O(1)
pub fn which_from_ioprio_base(which: u64) -> Option<Which> {
    match which {
        IOPRIO_WHO_PROCESS => Some(Which::Process),
        IOPRIO_WHO_PGRP => Some(Which::Pgrp),
        IOPRIO_WHO_USER => Some(Which::User),
        _ => None,
    }
}

/// The real uid a PRIO_USER / IOPRIO_WHO_USER walk matches on.
///
/// `who == 0` aliases to the CALLER's real uid and is never mapped — the
/// caller's own id is already an internal one. Any other `who` is a
/// namespace-relative id that must be translated through the caller's user
/// namespace first (`mapped`); an id the namespace does not map has no
/// possible owner, so the target set is empty and the syscall reports the
/// seed ESRCH.
/// # C: O(1)
pub fn user_target_uid(who: u32, caller_ruid: u32, mapped: Option<u32>) -> Option<u32> {
    if who == 0 { Some(caller_ruid) } else { mapped }
}

/// Membership test for a PRIO_USER / IOPRIO_WHO_USER walk.
///
/// Two conditions, both required: the task's REAL uid equals the target (the
/// effective uid is not consulted), and the task is numbered in the caller's
/// pid namespace. The second is what keeps a `setpriority(PRIO_USER, …)`
/// inside a pid namespace from reaching processes the caller cannot even
/// name, and it is the condition oxide was missing.
/// # C: O(1)
pub fn user_target_matches(target_uid: u32, task_ruid: u32, task_visible: bool) -> bool {
    task_ruid == target_uid && task_visible
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prio_base_accepts_exactly_the_three_sets() {
        assert_eq!(which_from_prio_base(0), Some(Which::Process));
        assert_eq!(which_from_prio_base(1), Some(Which::Pgrp));
        assert_eq!(which_from_prio_base(2), Some(Which::User));
        assert_eq!(which_from_prio_base(3), None);
    }

    #[test]
    fn a_negative_which_sign_extends_past_the_upper_bound() {
        // `int which = -1` reaches the slot as a sign-extended u64.
        assert_eq!(which_from_prio_base((-1i32) as u32 as u64), None);
        assert_eq!(which_from_prio_base((-1i64) as u64), None);
        assert_eq!(which_from_ioprio_base((-1i64) as u64), None);
    }

    #[test]
    fn ioprio_base_is_the_prio_base_shifted_by_one() {
        assert_eq!(which_from_ioprio_base(1), Some(Which::Process));
        assert_eq!(which_from_ioprio_base(2), Some(Which::Pgrp));
        assert_eq!(which_from_ioprio_base(3), Some(Which::User));
        assert_eq!(which_from_ioprio_base(0), None);
        assert_eq!(which_from_ioprio_base(4), None);
    }

    #[test]
    fn who_zero_means_the_callers_own_real_uid_unmapped() {
        // Mapping must not be consulted for `who == 0`, even when the caller's
        // namespace maps nothing.
        assert_eq!(user_target_uid(0, 1000, None), Some(1000));
    }

    #[test]
    fn an_unmapped_who_yields_no_target_set() {
        assert_eq!(user_target_uid(4242, 1000, None), None);
    }

    #[test]
    fn a_mapped_who_uses_the_internal_id_not_the_namespace_one() {
        assert_eq!(user_target_uid(0, 1000, Some(500_000)), Some(1000));
        assert_eq!(user_target_uid(7, 1000, Some(500_007)), Some(500_007));
    }

    #[test]
    fn user_membership_needs_both_the_real_uid_and_pid_ns_visibility() {
        assert!(user_target_matches(1000, 1000, true));
        // Right uid, invisible in the caller's pid namespace.
        assert!(!user_target_matches(1000, 1000, false));
        // Visible, wrong uid.
        assert!(!user_target_matches(1000, 1001, true));
        assert!(!user_target_matches(1000, 1001, false));
    }
}
