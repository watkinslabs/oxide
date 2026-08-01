// Module manifest: `ids` owns quota identity keys, `usage` owns charged inode
// usage deltas, `limits` owns Linux `mem_dqblk`/limit shape, `dquot` owns
// per-id accounting state and lookup tables, `info` owns superblock quota
// state, `inode` owns inode dquot attachment, `ops` owns filesystem hooks,
// `kqid` owns user-namespace translation of quota identities,
// `auth` owns quotactl admission, `control` owns quotactl work functions, and
// `charge` owns the Linux limit ladder (`dquot_add_space`/`dquot_add_inodes`),
// `warn` owns quota warning classes and delivery, and
// `transfer` owns Linux-shaped `__dquot_transfer` movement across dquot slots.

mod auth;
mod charge;
mod control;
mod dquot;
mod error;
mod ids;
mod info;
mod inode;
mod kqid;
mod limits;
mod ops;
mod transfer;
mod usage;
mod warn;

pub use charge::{ChargeCtx, ChargeOutcome, DQUOT_SPACE_NOFAIL, DQUOT_SPACE_RESERVE, DQUOT_SPACE_WARN};
pub use warn::{DquotWarn, DquotWarns, QuotaWarnType, QuotaWarning, clear_quota_warn_hook, deliver_warning, set_quota_warn_hook};
#[cfg(not(target_os = "oxide-kernel"))]
pub use warn::take_logged_warnings;
pub use auth::{INVALID_QUOTA_ID, QuotaCtlCmd, QuotaCtlCred, clear_quota_sys_resource_hook, quota_check_quotactl_permission, quota_has_sys_resource, quota_ignore_hardlimit, set_quota_sys_resource_hook};
pub use control::{QFMT_VFS_OLD, QFMT_VFS_V0, QFMT_VFS_V1, quota_disable_limits, quota_enable_limits, quota_getfmt, quota_getinfo, quota_getnextquota, quota_getquota, quota_off, quota_on, quota_setinfo, quota_setquota, quota_setquota_masked, quota_shutdown, quota_suspend_sysfiles, quota_sync, quota_sync_all, quota_sysfile_active};
pub use dquot::{ChargeResult, Dquot, DquotRef, DquotSet};
pub use error::{QuotaError, QuotaResult};
pub use ids::{Kqid, QuotaId, QuotaType, MAXQUOTAS};
pub use kqid::{from_kqid, from_kqid_munged, id_map_kind as quota_id_map_kind, make_kqid, qid_has_mapping};
pub use info::{QuotaInfo, clear_quota_wait_hooks, set_quota_wait_hooks};
pub use inode::{DquotTransferIds, InodeDquots, dquot_alloc_inode, dquot_charge_usage, dquot_drop, dquot_drop_type, dquot_free_inode, dquot_initialize, dquot_release_usage, dquot_transfer_inode, dquot_transfer_owner, dqget, dqput, inode_dquot};
pub use limits::{DQB_INO_COUNT, DQB_INO_HARD, DQB_INO_SOFT, DQB_INO_TIMER, DQB_RTB_COUNT, DQB_RTB_HARD, DQB_RTB_SOFT, DQB_RTB_TIMER, DQB_SPACE, DQB_SPC_HARD, DQB_SPC_SOFT, DQB_SPC_TIMER, DQB_VFS_MASK, DQF_GETINFO_MASK, DQF_ROOT_SQUASH, DQF_SETINFO_MASK, DQF_SYS_FILE, DquotLimits, IIF_ALL, IIF_BGRACE, IIF_BWARN, IIF_FLAGS, IIF_IGRACE, IIF_IWARN, IIF_RT_BGRACE, IIF_RTBWARN, MemDqblk, MemDqinfo, QuotaLimit};
pub use ops::{DquotOperations, QuotaFileStat, QuotaState, QuotaTypeState};
pub use transfer::{__dquot_transfer, DquotTransferSlot, dquot_transfer, dquot_transfer_with_grace};
pub use usage::DquotUsage;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod wake_gate_race;
