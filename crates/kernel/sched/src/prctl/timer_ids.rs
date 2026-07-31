// `prctl(PR_TIMER_CREATE_RESTORE_IDS, cmd)` — Linux `kernel/time/
// posix-timers.c posixtimer_create_prctl`.
//
// Process-wide (Linux keeps it on `signal_struct`, not `task_struct`), so any
// thread arms it for the whole process. While armed, `timer_create(2)` reads
// the caller's OUT parameter as an INPUT: the id the caller wants restored.
// Checkpoint/restore needs this to recreate a process's POSIX timers under
// their original ids.
//
// UNGATED: the sub-command ladder and the requested-id validity rule are
// hosted-testable, and the latter changes `timer_create`'s errno ordering.

use syscall::errno::Errno;

use super::uapi::*;

/// What `PR_TIMER_CREATE_RESTORE_IDS` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreIds { Off, On, Get }

/// The sub-command ladder. `arg3 || arg4 || arg5` is rejected by the prctl
/// switch before this runs.
/// # C: O(1)
pub fn classify(cmd: u64) -> Result<RestoreIds, Errno> {
    match cmd {
        PR_TIMER_CREATE_RESTORE_IDS_OFF => Ok(RestoreIds::Off),
        PR_TIMER_CREATE_RESTORE_IDS_ON  => Ok(RestoreIds::On),
        PR_TIMER_CREATE_RESTORE_IDS_GET => Ok(RestoreIds::Get),
        _ => Err(Errno::Einval),
    }
}

/// `timer_create`'s validity rule for a restored id: "Valid IDs are
/// 0..INT_MAX", tested on the value read back from the user `timer_t` as an
/// `unsigned int`. A negative `timer_t` therefore fails this test rather than
/// being sign-extended into a huge index.
/// # C: O(1)
pub fn valid_requested_id(raw: i32) -> Result<u32, Errno> {
    if raw < 0 { return Err(Errno::Einval); }
    Ok(raw as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_command_ladder() {
        assert_eq!(classify(PR_TIMER_CREATE_RESTORE_IDS_OFF), Ok(RestoreIds::Off));
        assert_eq!(classify(PR_TIMER_CREATE_RESTORE_IDS_ON), Ok(RestoreIds::On));
        assert_eq!(classify(PR_TIMER_CREATE_RESTORE_IDS_GET), Ok(RestoreIds::Get));
        for bad in [3, 4, u64::MAX] { assert_eq!(classify(bad), Err(Errno::Einval)); }
    }

    #[test]
    fn requested_ids_span_zero_to_int_max_and_reject_negatives() {
        assert_eq!(valid_requested_id(0), Ok(0));
        assert_eq!(valid_requested_id(1), Ok(1));
        assert_eq!(valid_requested_id(i32::MAX), Ok(i32::MAX as u32));
        assert_eq!(valid_requested_id(-1), Err(Errno::Einval));
        assert_eq!(valid_requested_id(i32::MIN), Err(Errno::Einval));
    }
}
