// ext4 mount-option parsing and the quota-family option contract.
//
// Module manifest:
// - behaviour: the non-quota options and what each one changes.
// - flags: option token names, quota mount-opt bits, `jqfmt=` enum.
// - ctx: parse context, live per-superblock quota option state, feature bits.
// - parse: mount-data tokeniser, option table, quota-file name rules.
// - consistency: every rejected option combination, in rejection order.
// - apply: fold an accepted context into the superblock's option state.
// - recovery: what `noload`/`norecovery` does to journal replay at mount.
//
// UNGATED on purpose: the whole decision surface must be reachable by
// `cargo test` on the host.

pub mod behaviour;
mod flags;
mod ctx;
mod parse;
mod consistency;
mod apply;
mod recovery;

#[cfg(test)]
mod tests;

pub use flags::{EXT4_MOUNT_GRPQUOTA, EXT4_MOUNT_PRJQUOTA, EXT4_MOUNT_QUOTA,
                EXT4_MOUNT_QUOTA_MASK, EXT4_MOUNT_USRQUOTA, jqfmt_from_name, jqfmt_name,
                limit_bit};
pub use behaviour::{DataMode, ErrorsPolicy, Ext4Behaviour};
pub use ctx::{Ext4MountOpts, FsQuotaFeatures, Ext4SbOpts};
pub use consistency::check_quota_consistency;
pub use apply::apply_quota_options;
pub use recovery::{JournalRecovery, recovery_action};

/// Parse and intra-string-validate one mount-data string, on top of the
/// behaviour already in force.
///
/// This is the half that needs no mounted filesystem, and it is separated from
/// the half that does because `noload` has to be known BEFORE the filesystem is
/// opened — the open is what replays the journal. The context it returns is the
/// one the rest of the mount finishes; nothing re-parses the string.
/// # C: O(len(data))
pub fn parse_data(data: &str, behaviour: Ext4Behaviour)
    -> vfs::KResult<alloc::boxed::Box<Ext4MountOpts>>
{
    let mut ctx = alloc::boxed::Box::new(Ext4MountOpts::parse_from(data, behaviour)?);
    ctx.validate()?;
    Ok(ctx)
}

/// Consistency-check an already-parsed context against a filesystem's live
/// option state and apply it. The second half of [`parse_data`].
/// # C: O(MAXQUOTAS)
pub fn configure_parsed(
    ctx: &mut Ext4MountOpts,
    feat: &FsQuotaFeatures,
    sb: &mut Ext4SbOpts,
    quota_loaded: bool,
) -> vfs::KResult<()> {
    check_quota_consistency(ctx, feat, sb, quota_loaded)?;
    apply_quota_options(ctx, feat, sb);
    Ok(())
}

/// Parse, validate, consistency-check and apply one mount-data string against
/// a filesystem's live quota option state. The single entry point for a
/// remount, whose filesystem is already open; a first mount splits the two
/// halves so the open can see `noload`.
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
    sb: &mut Ext4SbOpts,
    quota_loaded: bool,
) -> vfs::KResult<()> {
    let mut ctx = parse_data(data, sb.behaviour)?;
    configure_parsed(&mut ctx, feat, sb, quota_loaded)
}
