// Fold a validated parse context into the live per-superblock quota option
// state. Runs only after `check_quota_consistency` has accepted the context.

use vfs::MAXQUOTAS;

use super::ctx::{Ext4MountOpts, FsQuotaFeatures, SbQuotaOpts};
use super::flags::EXT4_MOUNT_QUOTA;

/// Apply `ctx` to `sb`.
///
/// Mount-opt bits always apply. Journalled quota file names and `jqfmt` do
/// not when the on-disk QUOTA feature is enabled — the kernel-owned hidden
/// quota inodes are then the only quota files, and a named one would be a
/// second, disagreeing source of quota state.
/// # C: O(MAXQUOTAS)
pub fn apply_quota_options(ctx: &mut Ext4MountOpts, feat: &FsQuotaFeatures, sb: &mut SbQuotaOpts) {
    sb.mount_opt = (sb.mount_opt & !ctx.mask) | (ctx.vals & ctx.mask);
    if feat.quota { return; }
    if ctx.spec_jquota {
        for slot in 0..MAXQUOTAS {
            if !ctx.names_slot(slot) { continue; }
            let name = ctx.qf_names[slot].take();
            // A named journalled quota file implies quota accounting even
            // when no plain quota option asked for it.
            if name.is_some() { sb.mount_opt |= EXT4_MOUNT_QUOTA; }
            sb.qf_names[slot] = name;
        }
    }
    if ctx.spec_jqfmt { sb.jquota_fmt = ctx.jquota_fmt; }
}
