//! Line, defaults and volume in one call.
//!
//! The order is the whole content of this file, and it is not interchangeable:
//! the volume's own defaults go down FIRST, the line is parsed on top of them,
//! and only then is the pair checked. Parsing first would compare the line
//! against a build-wide default rather than against this volume's, so a mount
//! that named nothing would be checked as though it had named everything.

use syscall::errno::Errno;

use crate::opts::facts::Facts;
use crate::opts::{parse_spec, Options, Spec};

use super::{check_opt_consistency, Sbi};

/// The options a fresh mount of a volume with these facts runs with.
/// # C: O(len(data))
#[inline(never)]
pub fn resolve(facts: &Facts, data: &str) -> Result<(Options, Spec), Errno> {
    let base = Options::defaults_for(facts);
    let (mut o, mut spec) = parse_spec(base, data)?;
    let sbi = Sbi::at_mount(*facts, base);
    check_opt_consistency(&sbi, &mut o, &mut spec)?;
    Ok((o, spec))
}

/// The options a remount leaves the mount running with.
///
/// The running set is the base, reset to the volume's defaults for everything
/// a remount may re-derive, so an option the new line stops naming goes back
/// to its default rather than persisting from the previous line.
/// # C: O(len(data))
pub fn resolve_remount(sbi: &Sbi, data: &str) -> Result<(Options, Spec), Errno> {
    let base = Options::redefault(sbi.cur, &sbi.facts, true);
    let (mut o, mut spec) = parse_spec(base, data)?;
    check_opt_consistency(sbi, &mut o, &mut spec)?;
    check_remount_switches(sbi, &o)?;
    Ok((o, spec))
}

/// The options a remount may not turn on or off while the mount is running.
///
/// Each of these is read once, when the mount is built, by machinery that has
/// no way to be told it changed: a cache whose entries would be stale, a
/// discard list whose runs are already the wrong width, a cleaner whose victim
/// policy chose the segments it is part way through. Refusing the change is
/// the honest answer — accepting it and ignoring it would leave the mount
/// reporting an option it is not honouring.
/// # C: O(1)
fn check_remount_switches(sbi: &Sbi, o: &Options) -> Result<(), Errno> {
    if o.atgc != sbi.cur.atgc { return Err(Errno::Einval); }
    if o.extent_cache != sbi.cur.extent_cache { return Err(Errno::Einval); }
    if o.age_extent_cache != sbi.cur.age_extent_cache { return Err(Errno::Einval); }
    if o.discard_unit != sbi.cur.discard_unit { return Err(Errno::Einval); }
    if o.nat_bits != sbi.cur.nat_bits { return Err(Errno::Einval); }
    // The compressed-block cache is built once, when the mount is made, and
    // the read path either consults it or does not. Turning it on afterwards
    // would leave a cache nothing had populated for the clusters already read;
    // turning it off would leave the entries it holds unreachable and never
    // invalidated, which is the same as keeping them and lying about it.
    if o.compress_cache != sbi.cur.compress_cache { return Err(Errno::Einval); }
    // A checkpoint is what makes the volume's state durable. A read-only mount
    // that also refuses to write one has no way to record the space it must
    // hold back, and no way to give it up again.
    if sbi.facts.mount_ro && o.checkpoint_disabled { return Err(Errno::Einval); }
    Ok(())
}
