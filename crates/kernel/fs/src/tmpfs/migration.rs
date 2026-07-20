//! Tmpfs-side wait/restart bridge for canonical shmem migration tokens.

/// Register the current task while the VMM token is pending, then sleep with
/// no inode/page-table lock held.  Callers always re-read the inode index on
/// return; completion may have committed swap or rolled resident state back.
pub(super) fn wait_and_restart(token: hal::pt_walker::MigrationEntry) {
    #[cfg(target_os = "oxide-kernel")]
    if vmm::migration_pending_then(token, || sched::live::migration_wait::park(token.token())) {
        sched::live::migration_wait::schedule_after_park();
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = token;
}
