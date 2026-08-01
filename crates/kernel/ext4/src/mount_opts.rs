// ext4 mount-option parsing and the quota-family option contract.
//
// Module manifest:
// - flags: option token names, quota mount-opt bits, `jqfmt=` enum.
// - ctx: parse context, live per-superblock quota option state, feature bits.
// - parse: mount-data tokeniser, option table, quota-file name rules.
// - consistency: every rejected option combination, in rejection order.
// - apply: fold an accepted context into the superblock's option state.
//
// UNGATED on purpose: the whole decision surface must be reachable by
// `cargo test` on the host.

mod flags;
mod ctx;
mod parse;
mod consistency;
mod apply;

#[cfg(test)]
mod tests;

pub use flags::{EXT4_MOUNT_GRPQUOTA, EXT4_MOUNT_PRJQUOTA, EXT4_MOUNT_QUOTA,
                EXT4_MOUNT_QUOTA_MASK, EXT4_MOUNT_USRQUOTA, jqfmt_from_name, jqfmt_name,
                limit_bit};
pub use ctx::{Ext4MountOpts, FsQuotaFeatures, SbQuotaOpts};
pub use consistency::check_quota_consistency;
pub use apply::apply_quota_options;

/// Parse, validate, consistency-check and apply one mount-data string against
/// a filesystem's live quota option state. The single entry point for both
/// mount and remount; `quota_loaded` selects remount semantics.
///
/// The parse context is heap-allocated and this function is kept out of its
/// caller's frame: mounting the root filesystem sits on the deepest boot chain
/// the stack-depth gate measures, and carrying the context by value there costs
/// the chain a few hundred bytes for the life of every frame below it.
/// # C: O(len(data) + MAXQUOTAS)
#[inline(never)]
pub fn configure(
    data: &str,
    feat: &FsQuotaFeatures,
    sb: &mut SbQuotaOpts,
    quota_loaded: bool,
) -> vfs::KResult<()> {
    let mut ctx = alloc::boxed::Box::new(Ext4MountOpts::parse(data)?);
    ctx.validate()?;
    check_quota_consistency(&mut ctx, feat, sb, quota_loaded)?;
    apply_quota_options(&mut ctx, feat, sb);
    Ok(())
}
