// The two capability facts the new mount API's flag words choose between,
// sampled once per call. `fsmount(2)` and `open_tree(2)` both pick one of them
// by flag, so both sample the same pair and hand it to the ungated policy that
// decides which applies — a syscall that sampled only "its" fact would have to
// know the answer before asking.

#![cfg(target_os = "oxide-kernel")]

use crate::fsmount_abi::FsmountCaps;

/// Sample both rungs before any lock is taken: the capability walk reads
/// scheduler state. # C: O(userns depth)
pub(crate) fn sample_caps() -> FsmountCaps {
    FsmountCaps {
        cap_sys_admin_current_user_ns: crate::mount_perm::cap_sys_admin_in_current_user_ns(),
        may_mount: crate::mount_perm::may_mount(),
    }
}
