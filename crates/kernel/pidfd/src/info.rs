use sched::pid::{PidIdentity, PidInfo};

/// Snapshot pidfd information from the retained canonical identity.
/// # C: O(N_tasks)
pub fn snapshot(identity: &PidIdentity) -> Option<PidInfo> {
    identity.info()
}
