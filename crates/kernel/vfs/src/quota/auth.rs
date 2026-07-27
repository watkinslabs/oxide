use crate::{VfsError, namei::GroupList};

use super::ids::QuotaType;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaCtlCmd {
    Sync,
    QuotaOn,
    QuotaOff,
    GetFmt,
    GetInfo,
    SetInfo,
    GetQuota,
    SetQuota,
    GetNextQuota,
    XGetQstat,
    XGetQstatv,
    XQuotaSync,
    XGetQuota,
    XSetQlim,
    XGetNextQuota,
    XQuotaOn,
    XQuotaOff,
    XQuotaRm,
}

#[derive(Clone)]
pub struct QuotaCtlCred {
    pub euid: u32,
    pub egid: u32,
    pub cap_sys_admin: bool,
    pub groups: GroupList,
}

impl QuotaCtlCred {
    /// Root quotactl caller. # C: O(1)
    pub const fn root() -> Self {
        Self { euid: 0, egid: 0, cap_sys_admin: true, groups: GroupList::empty() }
    }

    /// Linux `in_egroup_p`: effective gid or supplementary group. # C: O(ngroups)
    pub fn in_egroup(&self, gid: u32) -> bool {
        if self.egid == gid { return true; }
        self.groups.contains(gid)
    }
}

/// Linux `check_quotactl_permission` for classic quota commands. # C: O(ngroups)
pub fn quota_check_quotactl_permission(cmd: QuotaCtlCmd, kind: QuotaType, id: u32, cred: &QuotaCtlCred) -> crate::KResult<()> {
    match cmd {
        QuotaCtlCmd::GetFmt | QuotaCtlCmd::GetInfo | QuotaCtlCmd::Sync
        | QuotaCtlCmd::XGetQstat | QuotaCtlCmd::XGetQstatv | QuotaCtlCmd::XQuotaSync => Ok(()),
        QuotaCtlCmd::GetQuota if kind == QuotaType::User && cred.euid == id => Ok(()),
        QuotaCtlCmd::GetQuota if kind == QuotaType::Group && cred.in_egroup(id) => Ok(()),
        QuotaCtlCmd::XGetQuota if kind == QuotaType::User && cred.euid == id => Ok(()),
        QuotaCtlCmd::XGetQuota if kind == QuotaType::Group && cred.in_egroup(id) => Ok(()),
        _ if cred.cap_sys_admin => Ok(()),
        _ => Err(VfsError::Eperm),
    }
}
