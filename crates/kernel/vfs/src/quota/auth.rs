use sync::Spinlock;

use crate::{VfsError, namei::GroupList};

use super::control::QFMT_VFS_OLD;
use super::ids::QuotaType;
use super::limits::DQF_ROOT_SQUASH;

struct QuotaCapHookLock;
impl sync::LockClass for QuotaCapHookLock { fn rank() -> u16 { 30 } fn name() -> &'static str { "QuotaCapHookLock" } }

type SysResourceHook = fn() -> bool;

static SYS_RESOURCE_HOOK: Spinlock<Option<SysResourceHook>, QuotaCapHookLock> = Spinlock::new(None);

/// Install the CAP_SYS_RESOURCE probe. VFS owns the limit ladder; the task's
/// capability set lives in the layer that owns credentials. # C: O(1)
pub fn set_quota_sys_resource_hook(hook: SysResourceHook) { *SYS_RESOURCE_HOOK.lock() = Some(hook); }

/// Remove the CAP_SYS_RESOURCE probe. # C: O(1)
pub fn clear_quota_sys_resource_hook() { *SYS_RESOURCE_HOOK.lock() = None; }

/// True when the current task holds CAP_SYS_RESOURCE. Without an installed
/// probe no task is privileged, so limits apply to everyone. # C: O(1)
pub fn quota_has_sys_resource() -> bool {
    let hook = *SYS_RESOURCE_HOOK.lock();
    hook.is_some_and(|hook| hook())
}

/// `ignore_hardlimit`: a CAP_SYS_RESOURCE holder bypasses hard limits and
/// expired grace periods, except on the original on-disk format when that
/// class is configured to squash root. # C: O(1)
pub fn quota_ignore_hardlimit(fmt: u32, dqi_flags: u32) -> bool {
    quota_has_sys_resource() && (fmt != QFMT_VFS_OLD || dqi_flags & DQF_ROOT_SQUASH == 0)
}

/// Linux `INVALID_UID`/`INVALID_GID`/`INVALID_PROJID` — the identity a quota
/// argument resolves to when the caller's user namespace has no mapping for
/// it. Never equal to a real credential. # C: O(1)
pub const INVALID_QUOTA_ID: u32 = u32::MAX;

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

/// Linux `check_quotactl_permission` for classic quota commands.
///
/// `id` is the INTERNAL identity the caller's namespace resolved its `qid_t`
/// argument to — the same space `cred.euid`/`cred.egid` live in, so the
/// "query the dquot you own" exemption compares like with like. An argument
/// the caller's namespace cannot name arrives as [`INVALID_QUOTA_ID`], which
/// no real credential equals, so it falls through to the capability rung
/// exactly as Linux's `INVALID_UID` does. # C: O(ngroups)
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
