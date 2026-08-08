// Quota mount-option consistency: every combination ext4 refuses, in the
// order it refuses them. `quota_loaded` is "some quota class is already
// active on this superblock", i.e. the remount case.

use vfs::{KResult, MAXQUOTAS, VfsError};

use super::ctx::{Ext4MountOpts, FsQuotaFeatures, Ext4SbOpts};
use super::flags::{EXT4_MOUNT_GRPQUOTA, EXT4_MOUNT_PRJQUOTA, EXT4_MOUNT_QUOTA_MASK,
                   EXT4_MOUNT_USRQUOTA};

/// Validate `ctx` against the mounted filesystem's features and live quota
/// option state.
///
/// Rejected with `EINVAL`:
/// - `prjquota` on a filesystem without the project feature;
/// - turning quota options OFF while a quota class is loaded;
/// - adding or removing a journalled quota file while quota is loaded;
/// - naming a journalled quota file different from the one in force;
/// - changing `jqfmt` while quota is loaded;
/// - mixing plain `usrquota`/`grpquota` with a journalled quota file;
/// - a journalled quota file with no quota format selected.
///
/// With the on-disk QUOTA feature enabled the journalled options are inert
/// (the kernel owns the hidden quota inodes), so the checks that would only
/// constrain journalled files stop there rather than failing the mount.
///
/// Clears the plain-quota bit of any class that a journalled quota file
/// covers, so the applied superblock state never claims both forms.
/// # C: O(MAXQUOTAS)
pub fn check_quota_consistency(
    ctx: &mut Ext4MountOpts,
    feat: &FsQuotaFeatures,
    sb: &Ext4SbOpts,
    quota_loaded: bool,
) -> KResult<()> {
    // Only project quota is feature-gated: legacy user/group quotas in quota
    // files predate the feature bit and stay allowed without it.
    if ctx.test_opt(EXT4_MOUNT_PRJQUOTA) && !feat.project { return Err(VfsError::Einval); }

    if quota_loaded && ctx.touched_quota_opts() && !ctx.test_opt(EXT4_MOUNT_QUOTA_MASK) {
        return Err(VfsError::Einval);
    }

    if ctx.spec_jquota {
        for slot in 0..MAXQUOTAS {
            if !ctx.names_slot(slot) { continue; }
            if quota_loaded && sb.qf_name(slot).is_some() != ctx.qf_name(slot).is_some() {
                return Err(VfsError::Einval);
            }
            match (sb.qf_name(slot), ctx.qf_name(slot)) {
                (Some(live), Some(want)) if live != want => return Err(VfsError::Einval),
                _ => {}
            }
        }
        if feat.quota { return Ok(()); }
    }

    if ctx.spec_jqfmt {
        if sb.jquota_fmt != ctx.jquota_fmt && quota_loaded { return Err(VfsError::Einval); }
        if feat.quota { return Ok(()); }
    }

    let usr_slot = vfs::QuotaType::User.slot();
    let grp_slot = vfs::QuotaType::Group.slot();
    let usr_qf = sb.qf_name(usr_slot).is_some() || ctx.qf_name(usr_slot).is_some();
    let grp_qf = sb.qf_name(grp_slot).is_some() || ctx.qf_name(grp_slot).is_some();
    let mut usrquota = ctx.test_opt(EXT4_MOUNT_USRQUOTA) || sb.test_opt(EXT4_MOUNT_USRQUOTA);
    let mut grpquota = ctx.test_opt(EXT4_MOUNT_GRPQUOTA) || sb.test_opt(EXT4_MOUNT_GRPQUOTA);
    if usr_qf { ctx.clear_opt(EXT4_MOUNT_USRQUOTA); usrquota = false; }
    if grp_qf { ctx.clear_opt(EXT4_MOUNT_GRPQUOTA); grpquota = false; }

    if usr_qf || grp_qf {
        if usrquota || grpquota { return Err(VfsError::Einval); }
        if !ctx.spec_jqfmt && sb.jquota_fmt == 0 { return Err(VfsError::Einval); }
    }
    Ok(())
}
