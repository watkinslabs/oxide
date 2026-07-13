use vfs::{QuotaCtlCmd, QuotaCtlCred, QuotaType, VfsError, quota_check_quotactl_permission};

fn cred(euid: u32, egid: u32, cap_sys_admin: bool) -> QuotaCtlCred {
    QuotaCtlCred { euid, egid, cap_sys_admin, ngroups: 0, groups: [0u32; vfs::CRED_NGROUPS] }
}

#[test]
fn xfs_quotactl_permission_matches_linux_owner_and_admin_rules() {
    let mut c = cred(1000, 100, false);
    c.groups[0] = 200;
    c.ngroups = 1;

    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XGetQstat, QuotaType::Project, 99, &c), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XGetQstatv, QuotaType::Project, 99, &c), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XQuotaSync, QuotaType::Project, 99, &c), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XGetQuota, QuotaType::User, 1000, &c), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XGetQuota, QuotaType::User, 1001, &c), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XGetQuota, QuotaType::Group, 200, &c), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XGetQuota, QuotaType::Project, 7, &c), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XGetNextQuota, QuotaType::User, 1000, &c), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XSetQlim, QuotaType::User, 1000, &c), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XQuotaOn, QuotaType::User, 0, &c), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XQuotaOff, QuotaType::User, 0, &c), Err(VfsError::Eperm));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XQuotaRm, QuotaType::User, 0, &c), Err(VfsError::Eperm));

    let root = cred(1000, 100, true);
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XGetNextQuota, QuotaType::User, 1000, &root), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XSetQlim, QuotaType::User, 1000, &root), Ok(()));
    assert_eq!(quota_check_quotactl_permission(QuotaCtlCmd::XQuotaRm, QuotaType::User, 0, &root), Ok(()));
}
