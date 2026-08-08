// Ring-creation admission: who may call `io_uring_setup(2)` at all.
//
// The tunables are `kernel.io_uring_disabled` and `kernel.io_uring_group`
// (`syscall::io_uring_ctl`, the single owner both procfs and this check read):
//
//   disabled == 0   anyone
//   disabled == 1   CAP_SYS_ADMIN, or a member of `io_uring_group`
//   disabled == 2   nobody
//
// A negative `io_uring_group` is "unset", which makes level 1
// CAP_SYS_ADMIN-only. Every refusal is EPERM — the caller learns that ring
// creation is administratively closed, not that its arguments were wrong.

use syscall::errno::Errno;
use syscall::io_uring_ctl::{DISABLED_ALL, DISABLED_OFF};

/// Group-membership test: the effective gid counts, as does any
/// supplementary group. # C: O(N_groups)
pub fn in_group(gid: u32, egid: u32, groups: &[u32]) -> bool {
    egid == gid || groups.contains(&gid)
}

/// The whole admission ladder as a decision over already-read state.
/// # C: O(N_groups)
pub fn allowed(disabled: i32, group: i32, cap_sys_admin: bool, egid: u32, groups: &[u32])
    -> Result<(), Errno>
{
    if disabled == DISABLED_ALL { return Err(Errno::Eperm); }
    if disabled == DISABLED_OFF || cap_sys_admin { return Ok(()); }
    if group < 0 { return Err(Errno::Eperm); }
    if !in_group(group as u32, egid, groups) { return Err(Errno::Eperm); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use syscall::io_uring_ctl::{DISABLED_PRIV, GROUP_NONE};

    #[test]
    fn level_zero_admits_every_caller() {
        assert_eq!(allowed(DISABLED_OFF, GROUP_NONE, false, 1000, &[]), Ok(()));
        assert_eq!(allowed(DISABLED_OFF, 17, false, 1000, &[]), Ok(()));
    }

    #[test]
    fn level_two_refuses_even_cap_sys_admin() {
        // The strict level is not a privilege check: it closes ring creation
        // for the whole machine, root included.
        assert_eq!(allowed(DISABLED_ALL, 17, true, 0, &[17]), Err(Errno::Eperm));
    }

    #[test]
    fn level_one_admits_cap_sys_admin_and_group_members_only() {
        assert_eq!(allowed(DISABLED_PRIV, GROUP_NONE, true, 1000, &[]), Ok(()));
        // No group configured: privilege is the only way through.
        assert_eq!(allowed(DISABLED_PRIV, GROUP_NONE, false, 1000, &[]), Err(Errno::Eperm));
        // Effective gid is a match.
        assert_eq!(allowed(DISABLED_PRIV, 1000, false, 1000, &[]), Ok(()));
        // Supplementary group is a match.
        assert_eq!(allowed(DISABLED_PRIV, 17, false, 1000, &[4, 17, 99]), Ok(()));
        // Non-member.
        assert_eq!(allowed(DISABLED_PRIV, 17, false, 1000, &[4, 99]), Err(Errno::Eperm));
    }

    #[test]
    fn group_membership_counts_the_effective_gid_and_the_supplementary_list() {
        assert!(in_group(5, 5, &[]));
        assert!(in_group(5, 9, &[1, 5]));
        assert!(!in_group(5, 9, &[1, 6]));
    }
}
