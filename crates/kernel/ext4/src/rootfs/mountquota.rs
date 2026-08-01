// Mount-time quota activation: turn the mount's quota OPTIONS
// (`crate::mount_opts`) plus its on-disk quota features into live
// `sb.s_dquot` state.
//
// Two quota-file sources, never both on one filesystem:
// - hidden: the QUOTA feature's kernel-owned quota inodes. A failure here
//   fails the mount, because the filesystem declares the accounting is live.
// - journalled: a visible quota file named by `usrjquota=`/`grpjquota=` and
//   read in the `jqfmt=` format. A failure here does NOT fail the mount; the
//   filesystem is otherwise usable and the quota file may simply be missing.
//
// Limit enforcement is separate from usage tracking: a hidden quota class
// loads usage-only unless its plain quota option (`usrquota`, `grpquota`,
// `prjquota`) asked for limits. A journalled quota file always brings both.

use alloc::sync::Arc;

use crate::mount_opts::SbQuotaOpts;
use crate::superblock::EXT4_ROOT_INO;
use super::RootfsState;

const QUOTA_KINDS: [vfs::QuotaType; vfs::MAXQUOTAS] =
    [vfs::QuotaType::User, vfs::QuotaType::Group, vfs::QuotaType::Project];

/// Enable every quota class this mount asks for.
/// `allow_readonly` marks the RO→RW remount window, where the superblock
/// still reads read-only while quota files are being loaded.
/// # C: O(quota files)
pub(super) fn enable_mount_quotas(
    st: &Arc<RootfsState>,
    sb: &Arc<vfs::SuperBlock>,
    allow_readonly: bool,
) -> vfs::KResult<()> {
    if sb.sb_rdonly() && !allow_readonly { return Ok(()); }
    let opts = st.quota_opts();
    if st.mount.sb.has_quota() { enable_hidden_quotas(st, sb, &opts, allow_readonly)?; }
    enable_journalled_quotas(st, sb, &opts, allow_readonly);
    Ok(())
}

/// Load the QUOTA feature's hidden quota inodes. Fatal on failure. # C: O(quota files)
fn enable_hidden_quotas(
    st: &Arc<RootfsState>,
    sb: &Arc<vfs::SuperBlock>,
    opts: &SbQuotaOpts,
    allow_readonly: bool,
) -> vfs::KResult<()> {
    let mut done = [false; vfs::MAXQUOTAS];
    for kind in QUOTA_KINDS {
        let ino = hidden_quota_inum(st, kind);
        if ino == 0 { continue; }
        if sb.s_dquot.is_enabled(kind) { continue; }
        let r = if allow_readonly {
            crate::quota::quota_on_hidden_remount(st, sb, kind, vfs::QFMT_VFS_V1)
        } else {
            crate::quota::quota_on_hidden(st, sb, kind, vfs::QFMT_VFS_V1)
        };
        // Usage tracking is unconditional; limits only where the mount options
        // asked for enforcement.
        let keep_limits = opts.limits_requested(kind)
            || (allow_readonly && sb.s_dquot.has_suspended_limits(kind));
        if let Err(e) = r.and_then(|_| {
            if keep_limits { Ok(()) } else { vfs::quota_disable_limits(sb, kind) }
        }) {
            let rb = if allow_readonly { rollback_remount_quotas(sb, done) } else { rollback_mount_quotas(sb, done) };
            if let Err(rb) = rb { return Err(rb); }
            return Err(e);
        }
        done[kind.slot()] = true;
    }
    if allow_readonly {
        for kind in QUOTA_KINDS {
            if done[kind.slot()] { let _ = sb.s_dquot.take_suspended_limits(kind); }
        }
    }
    Ok(())
}

/// Load each journalled quota file named in the mount options. A class whose
/// file is missing or unreadable is skipped, leaving the rest of the mount
/// intact. # C: O(quota files)
fn enable_journalled_quotas(
    st: &Arc<RootfsState>,
    sb: &Arc<vfs::SuperBlock>,
    opts: &SbQuotaOpts,
    allow_readonly: bool,
) {
    if !opts.has_journalled_files() { return; }
    for kind in QUOTA_KINDS {
        let Some(name) = opts.journalled_file(kind) else { continue; };
        if sb.s_dquot.is_enabled(kind) { continue; }
        let Ok(ino) = st.lookup_child_ino_result(EXT4_ROOT_INO, name) else { continue; };
        let _ = crate::quota::quota_on_journalled(st, sb, kind, opts.jquota_fmt, ino, allow_readonly);
    }
}

/// Hidden quota inode number for one class (0 = the class has none). # C: O(1)
fn hidden_quota_inum(st: &RootfsState, kind: vfs::QuotaType) -> u32 {
    match kind {
        vfs::QuotaType::User    => st.mount.sb.usr_quota_inum,
        vfs::QuotaType::Group   => st.mount.sb.grp_quota_inum,
        vfs::QuotaType::Project => st.mount.sb.prj_quota_inum,
    }
}

fn rollback_mount_quotas(sb: &vfs::SuperBlock, done: [bool; vfs::MAXQUOTAS]) -> vfs::KResult<()> {
    let mut first = Ok(());
    for old in QUOTA_KINDS {
        if !done[old.slot()] { continue; }
        if let Err(e) = vfs::quota_off(sb, old) {
            if first.is_ok() { first = Err(e); }
        }
    }
    first
}

fn rollback_remount_quotas(sb: &vfs::SuperBlock, done: [bool; vfs::MAXQUOTAS]) -> vfs::KResult<()> {
    if done.iter().any(|done| *done) { vfs::quota_suspend_sysfiles(sb) } else { Ok(()) }
}
