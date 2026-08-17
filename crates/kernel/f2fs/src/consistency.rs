//! Whether what a mount line ASKED FOR can be true of THIS volume.
//!
//! Parsing answers a different question. It says the line is well formed and
//! its values are in range; it cannot say that `nodiscard` is impossible on a
//! zoned volume, that `atgc` and `mode=lfs` cannot both hold, or that a
//! remount may not switch the extent cache on. Every one of those is a
//! property of the pair — line and volume — and none of them is visible from
//! either side alone.
//!
//! Getting this wrong is silent in both directions. A refusal that should not
//! happen makes a working mount fail; a refusal that should happen and does
//! not leaves the mount running with an option the volume cannot honour, and
//! the caller believing it got what it asked for. The zoned pair is the plain
//! case: a zoned volume mounted `mode=adaptive` would overwrite blocks in
//! place on a medium whose zones make that impossible, and nothing reports it
//! until the write fails.
//!
//! Module manifest:
//! - `quota`: the two accounting arrangements, across a mount and a remount.
//! - `compress`: the compression group, against the volume that must record it.
//! - `apply`: parse, default and check in one call, at mount and at remount.

use syscall::errno::Errno;

use crate::opts::facts::Facts;
use crate::opts::{BackgroundGc, DiscardUnit, Mode, Options, Spec};

pub mod quota;
pub mod compress;
pub mod apply;

pub use apply::{resolve, resolve_remount};

/// Everything about the running mount and its volume that a check reads.
///
/// `cur` is the option set in force. At a fresh mount that is the
/// feature-derived default and every "already set" clause is vacuous; at a
/// remount it is what the mount is running with, and those clauses are the
/// whole point.
#[derive(Clone, Debug)]
pub struct Sbi<'a> {
    pub facts: Facts,
    /// Borrowed, never copied: the running option set is the mount's, and the
    /// reference reaches it through the superblock-info pointer for the same
    /// reason — a by-value field put it in every frame of the check.
    pub cur: &'a Options,
    /// Whether the mount is being reconfigured rather than opened.
    pub remount: bool,
    /// Whether accounting is switched on for any kind right now. Naming a
    /// different quota file under a live accounting run would leave the
    /// records that are open pointing at a file nothing writes.
    pub quota_on: bool,
    /// Whether this build could load the folding table the volume names.
    pub casefold_loadable: bool,
}

impl<'a> Sbi<'a> {
    /// The state a fresh mount checks against. # C: O(1)
    pub fn at_mount(facts: Facts, cur: &'a Options) -> Self {
        Self { facts, cur, remount: false, quota_on: false, casefold_loadable: true }
    }
}

/// Whether the line and the volume can both be true, adjusting the line where
/// the reference adjusts it rather than refusing.
///
/// Three clauses SILENTLY CORRECT instead of refusing, and each has a reason
/// the others do not: a discard the device cannot do is dropped because the
/// mount is still perfectly serviceable without it; a zoned volume's discard
/// unit is widened because a zone cannot be partly erased and the narrower
/// request has no meaning; a reserve that the mount already has is kept
/// because changing it under a running mount would strand the blocks already
/// held back. Everything else is a refusal, because honouring it would give
/// the caller something other than what it asked for.
///
/// Order is the contract. A line that trips several clauses reports the first,
/// so the answer does not move when an unrelated clause is added.
/// # C: O(1)
pub fn check_opt_consistency(sbi: &Sbi, o: &mut Options, spec: &mut Spec)
    -> Result<(), Errno> {
    let f = &sbi.facts;
    // The replay is what makes a crash's tail reachable. Skipping it on a
    // mount that then writes lets the allocator hand out the blocks the chain
    // still names, so a later mount replays a chain that has been overwritten.
    if o.norecovery && !f.mount_ro { return Err(Errno::Einval); }
    // A zone cannot be rewritten without being erased, so the device is not
    // being told as an optimisation — it is the only way space comes back.
    if f.hw_should_discard() && spec.discard && !o.discard { return Err(Errno::Einval); }
    if !f.hw_support_discard && spec.discard && o.discard {
        o.discard = false;
        spec.discard = false;
    }
    // An aliased device is described by an extent that the cache is what reads;
    // without it every block of the alias would be looked up one at a time
    // through a node tree that does not describe it.
    if f.device_alias() && spec.extent_cache && !o.extent_cache { return Err(Errno::Einval); }
    if sbi.cur.reserve_root != 0 && spec.reserve_root && o.reserve_root != 0 {
        o.reserve_root = sbi.cur.reserve_root;
        spec.reserve_root = false;
    }
    if sbi.cur.reserve_node != 0 && spec.reserve_node && o.reserve_node != 0 {
        o.reserve_node = sbi.cur.reserve_node;
        spec.reserve_node = false;
    }
    check_test_dummy_encryption(sbi, o)?;
    compress::check_compression(f.feature, o)?;
    quota::check_quota_consistency(sbi, o, spec)?;
    // Names on this volume resolve through a table; without it a lookup misses
    // names that exist, which reads as an empty directory rather than an error.
    if crate::features::has_casefold(f.feature) && !sbi.casefold_loadable {
        return Err(Errno::Einval);
    }
    if f.zoned() { check_zoned(o, spec)?; }
    if o.inline_xattr_size.is_some() {
        // The reservation is stated per inode, which only a volume carrying the
        // extra region and the flexible bit can do. Without them the number
        // would be accepted and every inode would still take the fixed one.
        if !f.extra_attr() || !f.flexible_inline_xattr() { return Err(Errno::Einval); }
        // Sizing a region that is not reserved reserves nothing.
        if !o.inline_xattr && !sbi.cur.inline_xattr { return Err(Errno::Einval); }
    }
    // The age-threshold cleaner picks victims by how old their blocks are and
    // rewrites them somewhere warmer; a volume that never overwrites in place
    // has no such choice to make.
    if o.atgc && o.mode == Mode::Lfs { return Err(Errno::Einval); }
    // There are no flushes to merge when nothing may be written.
    if f.readonly() && o.flush_merge { return Err(Errno::Einval); }
    // A volume marked read-only at format time was written by something that
    // recorded only what a read-only mount needs; opening it for writing would
    // append through logs whose current segments the checkpoint never named.
    if f.sb_readonly() && !f.mount_ro { return Err(Errno::Erofs); }
    Ok(())
}

/// The zoned clauses, which are three decisions rather than one.
/// # C: O(1)
fn check_zoned(o: &mut Options, spec: &mut Spec) -> Result<(), Errno> {
    // Space on a zoned volume comes back only when a zone is reset, and only
    // the cleaner resets one. Turning it off is a volume that fills and stays
    // full.
    if o.background_gc == BackgroundGc::Off { return Err(Errno::Einval); }
    if spec.discard_unit && o.discard_unit != DiscardUnit::Section {
        o.discard_unit = DiscardUnit::Section;
    }
    if spec.mode && o.mode != Mode::Lfs { return Err(Errno::Einval); }
    Ok(())
}

/// The well-known test key, which may be asked for and may not be changed.
///
/// It is not a policy a running mount can adopt: inodes created before it
/// would be unencrypted and inodes created after it would not be, with nothing
/// on the medium recording which is which. So it is settled once, at the
/// mount, and a remount may only restate what is already in force.
/// # C: O(1)
fn check_test_dummy_encryption(sbi: &Sbi, o: &Options) -> Result<(), Errno> {
    let Some(want) = o.dummy_policy else { return Ok(()) };
    if !crate::features::has_encrypt(sbi.facts.feature) { return Err(Errno::Einval); }
    if sbi.remount && sbi.cur.dummy_policy != Some(want) { return Err(Errno::Einval); }
    Ok(())
}

#[cfg(test)]
#[path = "tests/consistency/mod.rs"]
mod tests;
