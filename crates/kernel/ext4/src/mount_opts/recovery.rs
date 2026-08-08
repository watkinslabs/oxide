// What `noload`/`norecovery` does to journal replay at mount time.
//
// UNGATED: the decision is the whole of the option's effect, so it is stated
// once, here, where `cargo test` can reach it — the open path that acts on it
// is a shim around this answer.

use vfs::{KResult, VfsError};

/// What the open path does with the on-disk journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalRecovery {
    /// Replay the log, then mark it clean.
    Replay,
    /// Leave the log exactly as it is.
    Skip,
}

/// Decide whether to replay.
///
/// `noload` means "do not touch the log". A filesystem whose log is DIRTY and
/// which is being mounted writable cannot honour that and still be correct:
/// writing into a filesystem whose committed-but-unreplayed metadata is still
/// only in the log corrupts it. That combination is refused, so the option
/// never silently turns into "mount it anyway and hope". Read-only is fine —
/// nothing will be written — and so is a clean log, which has nothing to
/// replay whether or not the option was given.
/// # C: O(1)
pub fn recovery_action(noload: bool, rdonly: bool, needs_recovery: bool) -> KResult<JournalRecovery> {
    if !noload { return Ok(JournalRecovery::Replay); }
    if needs_recovery && !rdonly { return Err(VfsError::Einval); }
    Ok(JournalRecovery::Skip)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The option's whole point: a mount naming it does not replay.
    #[test]
    fn noload_skips_replay_on_a_clean_log() {
        assert_eq!(recovery_action(true, false, false), Ok(JournalRecovery::Skip));
        assert_eq!(recovery_action(true, true, false), Ok(JournalRecovery::Skip));
    }

    /// A mount that did not name it replays, dirty log or not — the replay of a
    /// clean log is the no-op the log's own state decides.
    #[test]
    fn without_the_option_the_log_is_replayed() {
        assert_eq!(recovery_action(false, false, true), Ok(JournalRecovery::Replay));
        assert_eq!(recovery_action(false, true, true), Ok(JournalRecovery::Replay));
        assert_eq!(recovery_action(false, false, false), Ok(JournalRecovery::Replay));
    }

    /// Suppressing required recovery on a writable mount is refused, not
    /// obeyed: the alternative is writing into a filesystem whose newest
    /// metadata is still only in the log.
    #[test]
    fn suppressed_recovery_without_read_only_is_refused() {
        assert_eq!(recovery_action(true, false, true), Err(VfsError::Einval));
    }

    /// Read-only is the mount that may suppress it, because it writes nothing.
    #[test]
    fn a_read_only_mount_may_suppress_required_recovery() {
        assert_eq!(recovery_action(true, true, true), Ok(JournalRecovery::Skip));
    }
}
