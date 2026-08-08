// `sigio_perm` — whether an `O_ASYNC` / `F_SETOWN` owner may signal the task
// it named (Linux `fcntl` async-I/O ownership check).
//
// Ungated (CLAUDE.md "Phantom tests"): this is a pure credential ladder, so it
// is provable by `cargo test -p sched`. `live::sigpend::send_sigio` is the
// kernel-only caller that resolves the target and posts the signal.
//
// The gate exists because `F_SETOWN` lets one process name ANOTHER as the
// recipient of a file's async-I/O signal. Without it, any unprivileged process
// could point a pipe's `O_ASYNC` owner at a root daemon and drive SIGIO —
// `F_SETSIG` even choosing which signal — into it.

/// The owner credentials `F_SETOWN` snapshots (Linux `struct fown_struct`'s
/// `uid` / `euid`, filled by `f_modown` from `current_cred()`). Captured at
/// `F_SETOWN` time, NOT read at delivery time: the owner may have changed
/// credentials, or exited, since it claimed the file.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FileOwnerCreds {
    /// `fown->uid` — the setter's real uid.
    pub uid: u32,
    /// `fown->euid` — the setter's effective uid.
    pub euid: u32,
}

/// The recipient's live credentials (Linux `__task_cred(p)`).
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct TargetCreds {
    /// `cred->uid` — the target's real uid.
    pub uid: u32,
    /// `cred->suid` — the target's saved-set uid.
    pub suid: u32,
}

/// `GLOBAL_ROOT_UID` — uid 0 in the initial user namespace. Never inline as a
/// bare 0 in a credential comparison (`07§5`).
pub const ROOT_UID: u32 = 0;

/// Linux `sigio_perm(p, fown, sig)`: the owner may signal the target when its
/// effective uid is root, or when EITHER of the owner's snapshotted ids
/// matches EITHER of the target's real / saved-set ids.
///
/// Note the asymmetry Linux encodes deliberately: the owner's *real* uid is
/// compared, but its being root is judged by the *effective* uid only — a
/// setuid-root helper that dropped euid cannot signal an arbitrary target just
/// because its real uid is 0.
/// # C: O(1)
pub fn sigio_perm(owner: FileOwnerCreds, target: TargetCreds) -> bool {
    owner.euid == ROOT_UID
        || owner.euid == target.suid
        || owner.euid == target.uid
        || owner.uid == target.suid
        || owner.uid == target.uid
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: TargetCreds = TargetCreds { uid: 0, suid: 0 };
    /// An ordinary user process: real == saved.
    const ALICE: TargetCreds = TargetCreds { uid: 1000, suid: 1000 };
    /// A setuid-root binary run by alice: real 1000, saved 0.
    const ALICE_SETUID_ROOT: TargetCreds = TargetCreds { uid: 1000, suid: 0 };

    fn owner(uid: u32, euid: u32) -> FileOwnerCreds { FileOwnerCreds { uid, euid } }

    #[test]
    fn root_effective_uid_may_signal_anyone() {
        assert!(sigio_perm(owner(0, 0), ALICE));
        // A process that kept euid 0 after setting its real uid still passes.
        assert!(sigio_perm(owner(1000, 0), ALICE));
    }

    #[test]
    fn a_dropped_setuid_root_owner_is_not_treated_as_root() {
        // Real uid 0, effective uid 1000: the root arm tests euid ONLY, so this
        // owner is judged purely on the id matches below — and 0 matches
        // neither of a stranger's ids.
        assert!(!sigio_perm(owner(0, 1000), TargetCreds { uid: 500, suid: 500 }));
        // Against a root target the real-uid arm matches.
        assert!(sigio_perm(owner(0, 1000), ROOT));
    }

    #[test]
    fn an_unrelated_unprivileged_owner_is_refused() {
        assert!(!sigio_perm(owner(1000, 1000), TargetCreds { uid: 1001, suid: 1001 }));
        // The exact hole the gate closes: a user process must not be able to
        // drive an async-I/O signal into a root daemon.
        assert!(!sigio_perm(owner(1000, 1000), ROOT));
    }

    #[test]
    fn matching_either_owner_id_against_either_target_id_is_enough() {
        assert!(sigio_perm(owner(1000, 1000), ALICE), "same user signals itself");
        // Owner euid matches the target's SAVED uid: a setuid-root target that
        // dropped to alice is still signalable by alice.
        assert!(sigio_perm(owner(1000, 1000), ALICE_SETUID_ROOT));
        // Owner real uid matches the target's saved uid while its euid does not.
        assert!(sigio_perm(owner(0, 1000), ALICE_SETUID_ROOT));
        // Owner euid matches the target's real uid while its real uid does not.
        assert!(sigio_perm(owner(7, 1000), ALICE));
    }
}
